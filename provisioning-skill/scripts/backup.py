"""Backup-root safety checks used before supervised native backup commands."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


class BackupError(ValueError):
    pass


def _lexically_contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_allowed_platform_root_alias(path: Path, mode: int) -> bool:
    """Allow only macOS's fixed /var -> private/var root alias."""
    if sys.platform != "darwin" or path != Path("/var") or not stat.S_ISLNK(mode):
        return False
    try:
        return os.readlink(path) == "private/var"
    except OSError as exc:
        raise BackupError("backup containment metadata could not be read") from exc


def _reject_symlink_components(path: Path, *, safe_root: Path = Path("/")) -> None:
    """Reject existing symlinks through an explicit lexical filesystem root."""
    if not safe_root.is_absolute() or path != safe_root and not _lexically_contains(safe_root, path):
        raise BackupError("backup containment path is outside the safe filesystem root")
    current = path
    while True:
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise BackupError("backup containment metadata could not be read") from exc
        else:
            if stat.S_ISLNK(mode) and not _is_allowed_platform_root_alias(current, mode):
                raise BackupError("backup containment path must not contain symlinks")
        if current == safe_root:
            return
        if current.parent == current:
            raise BackupError("backup containment path did not reach the safe filesystem root")
        current = current.parent


def assert_safe_backup_root(repository: Path, backup_root: Path) -> None:
    """Validate the exact lexical route before each G07 filesystem mutation."""
    if not repository.is_absolute() or not backup_root.is_absolute():
        raise BackupError("repository and backup root must be absolute paths")
    if repository != Path(os.path.normpath(repository)) or backup_root != Path(os.path.normpath(backup_root)):
        raise BackupError("repository and backup root must use canonical lexical spelling")

    beads = repository / ".beads"
    expected = beads / "backup"
    if backup_root != expected or not _lexically_contains(repository, backup_root):
        raise BackupError("backup root must be repository/.beads/backup")

    # Walk the complete lexical chain to the explicit filesystem root without
    # resolving attacker-controlled components. macOS's fixed /var platform
    # alias is the sole exception; any lower symlink remains forbidden.
    _reject_symlink_components(backup_root, safe_root=Path("/"))

    try:
        repository_result = repository.lstat()
        beads_result = beads.lstat()
    except FileNotFoundError as exc:
        raise BackupError("repository and .beads must already be directories") from exc
    except OSError as exc:
        raise BackupError("backup containment metadata could not be read") from exc
    if not stat.S_ISDIR(repository_result.st_mode) or not stat.S_ISDIR(beads_result.st_mode):
        raise BackupError("repository and .beads must be directories, not symlinks")
    try:
        repository_parent_device = repository.parent.lstat().st_dev
    except OSError as exc:
        raise BackupError("backup containment metadata could not be read") from exc
    filesystem_device = repository_result.st_dev
    if repository_parent_device != filesystem_device or beads_result.st_dev != filesystem_device:
        raise BackupError("repository, .beads, and backup root must not cross a filesystem boundary")

    try:
        root_result = backup_root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BackupError("backup root metadata could not be read") from exc
    if stat.S_ISLNK(root_result.st_mode):
        raise BackupError("backup root must not be a symlink")
    if not stat.S_ISDIR(root_result.st_mode):
        raise BackupError("backup root must be a directory when present")
    if root_result.st_dev != filesystem_device:
        raise BackupError("repository, .beads, and backup root must not cross a filesystem boundary")


def _validate_entry(path: Path, root_device: int, *, root: bool = False) -> None:
    try:
        result = path.lstat()
    except OSError as exc:
        raise BackupError("backup tree entry could not be read") from exc
    mode = result.st_mode
    if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise BackupError("backup tree contains unsafe entry")
    if result.st_dev != root_device:
        raise BackupError("backup tree crosses filesystem boundary")
    expected_mode = 0o700 if stat.S_ISDIR(mode) else 0o600
    if stat.S_IMODE(mode) != expected_mode:
        kind = "root" if root else ("directory" if stat.S_ISDIR(mode) else "file")
        raise BackupError(f"backup {kind} mode must be {expected_mode:04o}")


def validate_backup_tree(backup_root: Path) -> None:
    """Walk without following directory symlinks and fail closed on unsafe entries."""
    try:
        root_result = backup_root.lstat()
    except OSError as exc:
        raise BackupError("backup root missing or unreadable") from exc
    if stat.S_ISLNK(root_result.st_mode) or not stat.S_ISDIR(root_result.st_mode):
        raise BackupError("backup root must be a directory, not a symlink")
    root_device = root_result.st_dev
    _validate_entry(backup_root, root_device, root=True)

    try:
        for directory, names, files in os.walk(backup_root, topdown=True, followlinks=False):
            current = Path(directory)
            for name in [*names, *files]:
                _validate_entry(current / name, root_device)
    except BackupError:
        raise
    except OSError as exc:
        raise BackupError("backup tree could not be traversed safely") from exc
