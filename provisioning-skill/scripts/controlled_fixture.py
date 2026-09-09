"""Descriptor-pinned disposable-fixture support for controlled tests.

This is cooperative tempfile confinement, not a hostile same-process sandbox.
It has no production transport or public-CLI wiring.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ProvisioningEvidence

_MAX_READ = 65_536


class ControlledFixtureError(RuntimeError):
    """A controlled fixture changed or could not be safely addressed."""


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return (metadata.st_dev, metadata.st_ino)


def _stable(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    """All metadata fields used for one stable descriptor read/enumeration."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass(frozen=True, slots=True)
class ControlledMutationTarget:
    """Opaque one-shot descriptor-backed target with no destination path."""

    _session: "ControlledFixtureSession"
    _kind: str
    _pin: str
    _nonce: object

    def _claim(self, kind: str, pin: str) -> "ControlledFixtureSession":
        if self._kind != kind or self._pin != pin:
            raise ControlledFixtureError("controlled target was used for the wrong operation")
        self._session._consume_target(self, self._nonce, kind, pin)
        return self._session

    def initialize_beads(self, prefix: str) -> None:
        self._claim("beads-init", "destination").create_beads_metadata(prefix)

    def add_dolt_remote(self) -> None:
        self._claim("dolt-remote-add", "beads")

    def setup_agent(self, integration: str) -> None:
        self._claim(f"agent-setup:{integration}", "beads")

    def install_hooks(self, names: tuple[str, ...]) -> None:
        self._claim("hooks-install", "beads").create_managed_hooks(names)


class ControlledFixtureSession:
    """One run-scoped root/evidence descriptor session for cooperative fakes."""

    def __init__(self, root: Path, evidence_name: str = "evidence") -> None:
        if not isinstance(root, Path) or not root.is_absolute() or evidence_name != "evidence":
            raise ControlledFixtureError("controlled fixture session paths are invalid")
        try:
            metadata = root.lstat()
        except OSError as error:
            raise ControlledFixtureError("controlled fixture root was unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ControlledFixtureError("controlled fixture root must be an exact directory")
        self._root_path = root
        self._evidence_name = evidence_name
        self._root_identity = _identity(metadata)
        self._root_fd: int | None = None
        self._evidence_fd: int | None = None
        self._evidence_identity: tuple[int, int] | None = None
        self._pins: dict[str, tuple[tuple[str, ...], int, tuple[int, int]]] = {}
        self._file_pins: dict[str, tuple[str, str, int, tuple[int, int, int, int, int, int, int, int]]] = {}
        self._open_targets: dict[int, tuple[object, str, str]] = {}

    @staticmethod
    def _flags(*, directory: bool = False, write: bool = False) -> int:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if type(nofollow) is not int or (directory and type(directory_flag) is not int):
            raise ControlledFixtureError("controlled fixture requires no-follow descriptor support")
        flags = (os.O_WRONLY if write else os.O_RDONLY) | nofollow | cloexec
        if directory:
            flags |= directory_flag
        return flags

    def __enter__(self) -> "ControlledFixtureSession":
        self.open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def open(self) -> None:
        if self._root_fd is not None:
            raise ControlledFixtureError("controlled fixture session was already opened")
        try:
            root_fd = os.open(self._root_path, self._flags(directory=True))
        except OSError as error:
            raise ControlledFixtureError("controlled fixture root secure open failed") from error
        try:
            if _identity(os.fstat(root_fd)) != self._root_identity:
                raise ControlledFixtureError("controlled fixture root changed before the run")
            self._root_fd = root_fd
            try:
                evidence_fd = os.open(
                    self._evidence_name, self._flags(directory=True), dir_fd=root_fd
                )
            except FileNotFoundError:
                os.mkdir(self._evidence_name, 0o700, dir_fd=root_fd)
                # Durably link the evidence leaf before any evidence or mutation.
                os.fsync(root_fd)
                evidence_fd = os.open(
                    self._evidence_name, self._flags(directory=True), dir_fd=root_fd
                )
            self._evidence_fd = evidence_fd
            evidence_metadata = os.fstat(evidence_fd)
            if not stat.S_ISDIR(evidence_metadata.st_mode):
                raise ControlledFixtureError("controlled evidence leaf was not a directory")
            self._evidence_identity = _identity(evidence_metadata)
            self.assert_bindings()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        for _, _, fd, _ in tuple(self._file_pins.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        self._file_pins.clear()
        for _, fd, _ in tuple(self._pins.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        self._pins.clear()
        for fd in (self._evidence_fd, self._root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._evidence_fd = None
        self._root_fd = None
        self._evidence_identity = None
        self._open_targets.clear()

    @property
    def evidence_fd(self) -> int:
        if self._evidence_fd is None:
            raise ControlledFixtureError("controlled fixture evidence descriptor is unavailable")
        return self._evidence_fd

    @property
    def root_fd(self) -> int:
        if self._root_fd is None:
            raise ControlledFixtureError("controlled fixture root descriptor is unavailable")
        return self._root_fd

    @property
    def root_path(self) -> Path:
        """Controller-owned lexical anchor; identity is verified by this session."""
        return self._root_path

    def _canonical_root_identity(self) -> tuple[int, int]:
        try:
            metadata = self._root_path.lstat()
        except OSError as error:
            raise ControlledFixtureError("controlled fixture root canonical binding was unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ControlledFixtureError("controlled fixture root canonical binding changed")
        return _identity(metadata)

    def _open_directory(self, parts: tuple[str, ...]) -> int:
        parent = self.root_fd
        opened: list[int] = []
        try:
            for component in parts:
                if not component or component in {".", ".."} or "/" in component:
                    raise ControlledFixtureError("controlled fixture path component was invalid")
                next_fd = os.open(component, self._flags(directory=True), dir_fd=parent)
                opened.append(next_fd)
                parent = next_fd
            if not opened:
                return os.dup(self.root_fd)
            return opened.pop()
        except OSError as error:
            raise ControlledFixtureError("controlled fixture directory secure open failed") from error
        finally:
            for fd in opened:
                os.close(fd)

    def _entry_identity(self, parts: tuple[str, ...]) -> tuple[int, int]:
        if not parts:
            return _identity(os.fstat(self.root_fd))
        parent = self._open_directory(parts[:-1])
        try:
            metadata = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ControlledFixtureError("controlled fixture path contained a symlink")
            return _identity(metadata)
        except OSError as error:
            raise ControlledFixtureError("controlled fixture path binding was unavailable") from error
        finally:
            os.close(parent)

    def assert_ledger_binding(self) -> None:
        """Verify only the held root/evidence chain needed to preserve failure evidence."""
        if self._canonical_root_identity() != self._root_identity:
            raise ControlledFixtureError("controlled fixture root changed at its canonical location")
        if _identity(os.fstat(self.root_fd)) != self._root_identity:
            raise ControlledFixtureError("held controlled fixture root changed")
        if self._entry_identity((self._evidence_name,)) != self._evidence_identity:
            raise ControlledFixtureError("controlled evidence directory changed at its canonical location")
        if _identity(os.fstat(self.evidence_fd)) != self._evidence_identity:
            raise ControlledFixtureError("held controlled evidence directory changed")

    def assert_bindings(self) -> None:
        self.assert_ledger_binding()
        for _, (parts, fd, expected) in self._pins.items():
            if _identity(os.fstat(fd)) != expected or self._entry_identity(parts) != expected:
                raise ControlledFixtureError("controlled mutation target changed at its canonical location")
        for parent_pin, leaf, fd, expected in self._file_pins.values():
            _, parent_fd = self._pin(parent_pin)
            try:
                canonical = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error:
                raise ControlledFixtureError("controlled pinned file was unavailable canonically") from error
            if stat.S_ISLNK(canonical.st_mode) or _stable(canonical) != expected or _stable(os.fstat(fd)) != expected:
                raise ControlledFixtureError("controlled pinned file changed at its canonical location")

    def pin_directory(self, name: str, parts: tuple[str, ...]) -> None:
        self.assert_bindings()
        if name in self._pins:
            existing_parts, _, _ = self._pins[name]
            if existing_parts != parts:
                raise ControlledFixtureError("controlled target pin was rebound")
            self.assert_bindings()
            return
        fd = self._open_directory(parts)
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(fd)
            raise ControlledFixtureError("controlled target was not a directory")
        self._pins[name] = (parts, fd, _identity(metadata))
        try:
            self.assert_bindings()
        except Exception:
            _, failed_fd, _ = self._pins.pop(name)
            os.close(failed_fd)
            raise

    def target(self, kind: str, pin: str) -> ControlledMutationTarget:
        self.assert_bindings()
        if pin not in self._pins:
            raise ControlledFixtureError("controlled mutation target was not pinned")
        nonce = object()
        target = ControlledMutationTarget(self, kind, pin, nonce)
        self._open_targets[id(target)] = (nonce, kind, pin)
        return target

    def _consume_target(
        self,
        target: ControlledMutationTarget,
        nonce: object,
        kind: str,
        pin: str,
    ) -> None:
        if type(target) is not ControlledMutationTarget:
            raise ControlledFixtureError("controlled mutation target type was invalid")
        if self._open_targets.pop(id(target), None) != (nonce, kind, pin):
            raise ControlledFixtureError("controlled mutation target was replayed or forged")
        self.assert_bindings()

    def assert_target_consumed(self, target: ControlledMutationTarget) -> None:
        self.assert_bindings()
        if id(target) in self._open_targets:
            raise ControlledFixtureError("controlled mutation target was not cooperatively consumed")

    def _pin(self, name: str) -> tuple[tuple[str, ...], int]:
        try:
            parts, fd, _ = self._pins[name]
            return parts, fd
        except KeyError as error:
            raise ControlledFixtureError("controlled target descriptor was not pinned") from error

    def directory_fd(self, name: str) -> int:
        """Return a duplicate of a pinned directory descriptor to a controller.

        The duplicate keeps the pathless, descriptor-relative mutation boundary
        while preventing callers from closing or rebinding the session's pin.
        """
        self.assert_bindings()
        _, fd = self._pin(name)
        try:
            duplicate = os.dup(fd)
        except OSError as error:
            raise ControlledFixtureError(
                "controlled target descriptor could not be duplicated"
            ) from error
        try:
            self.assert_bindings()
            return duplicate
        except Exception:
            os.close(duplicate)
            raise

    def create_directory(self, parent_pin: str, leaf: str, *, mode: int) -> None:
        """Create one exact directory below a pinned parent descriptor."""
        if not leaf or leaf in {".", ".."} or "/" in leaf:
            raise ControlledFixtureError("controlled directory leaf was invalid")
        if mode != 0o700:
            raise ControlledFixtureError("controlled directory mode was not admitted")
        self.assert_bindings()
        _, parent_fd = self._pin(parent_pin)
        try:
            os.mkdir(leaf, mode, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as error:
            raise ControlledFixtureError(
                "controlled directory could not be created"
            ) from error
        self.assert_bindings()

    def create_regular(
        self,
        parent_pin: str,
        leaf: str,
        data: bytes,
        *,
        mode: int,
    ) -> None:
        """Atomically create one exact bounded regular fixture leaf."""
        if (
            not leaf
            or leaf in {".", ".."}
            or "/" in leaf
            or type(data) is not bytes
            or len(data) > _MAX_READ
        ):
            raise ControlledFixtureError("controlled regular fixture leaf was invalid")
        if mode not in {0o600, 0o700}:
            raise ControlledFixtureError("controlled regular fixture mode was not admitted")
        self.assert_bindings()
        _, parent_fd = self._pin(parent_pin)
        self._write_regular(parent_fd, leaf, data, mode)
        self.assert_bindings()

    def create_beads_metadata(self, prefix: str) -> None:
        destination_parts, destination_fd = self._pin("destination")
        self.assert_bindings()
        try:
            os.mkdir(".beads", 0o700, dir_fd=destination_fd)
            os.fsync(destination_fd)
        except OSError as error:
            raise ControlledFixtureError("controlled Beads directory could not be created") from error
        self.pin_directory("beads", destination_parts + (".beads",))
        _, beads_fd = self._pin("beads")
        payload = json.dumps(
            {
                "dolt_database": prefix,
                "dolt_mode": "server",
                "dolt_server_host": "127.0.0.1",
                "dolt_server_port": 3307,
            },
            sort_keys=True,
        ).encode("utf-8")
        self._write_regular(beads_fd, "metadata.json", payload, 0o600)
        self.pin_regular("beads:metadata.json", "beads", "metadata.json")
        self.assert_bindings()

    def create_managed_hooks(self, names: tuple[str, ...]) -> None:
        beads_parts, beads_fd = self._pin("beads")
        self.assert_bindings()
        try:
            os.mkdir("hooks", 0o700, dir_fd=beads_fd)
            os.fsync(beads_fd)
        except OSError as error:
            raise ControlledFixtureError("controlled hooks directory could not be created") from error
        self.pin_directory("hooks", beads_parts + ("hooks",))
        _, hooks_fd = self._pin("hooks")
        for name in names:
            if not name or "/" in name or name in {".", ".."}:
                raise ControlledFixtureError("controlled hook name was invalid")
            self._write_regular(
                hooks_fd,
                name,
                f"#!/bin/sh\n# controlled managed hook: {name}\nexit 0\n".encode(),
                0o700,
            )
            self.pin_regular(f"hooks:{name}", "hooks", name)
        self.assert_bindings()

    def _write_regular(self, directory_fd: int, name: str, data: bytes, mode: int) -> None:
        temporary = f".controlled-{secrets.token_hex(8)}"
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise ControlledFixtureError("controlled fixture write made no progress")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(temporary, mode, dir_fd=directory_fd, follow_symlinks=False)
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)

    def pin_regular(self, name: str, parent_pin: str, leaf: str) -> None:
        """Hold one exact named regular file and bind its canonical entry."""
        self.assert_bindings()
        if not name or not leaf or "/" in leaf or leaf in {".", ".."}:
            raise ControlledFixtureError("controlled pinned file name was invalid")
        existing = self._file_pins.get(name)
        if existing is not None:
            if existing[:2] != (parent_pin, leaf):
                raise ControlledFixtureError("controlled pinned file was rebound")
            self.assert_bindings()
            return
        _, parent_fd = self._pin(parent_pin)
        try:
            fd = os.open(leaf, self._flags(), dir_fd=parent_fd)
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 0 or metadata.st_size > _MAX_READ:
                os.close(fd)
                raise ControlledFixtureError("controlled pinned file was not a bounded regular file")
            self._file_pins[name] = (parent_pin, leaf, fd, _stable(metadata))
        except OSError as error:
            raise ControlledFixtureError("controlled pinned file secure open failed") from error
        try:
            self.assert_bindings()
        except Exception:
            _, _, failed_fd, _ = self._file_pins.pop(name)
            os.close(failed_fd)
            raise

    def read_pinned_regular(
        self, pin: str, name: str, *, label: str
    ) -> tuple[bytes, os.stat_result]:
        """Read one held named regular file after revalidating its canonical link."""
        self.assert_bindings()
        key = f"{pin}:{name}"
        try:
            parent_pin, leaf, fd, expected = self._file_pins[key]
        except KeyError as error:
            raise ControlledFixtureError(f"{label} was not pinned at its mutation boundary") from error
        if parent_pin != pin or leaf != name:
            raise ControlledFixtureError(f"{label} pinned file binding was invalid")
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or _stable(before) != expected:
                raise ControlledFixtureError(f"{label} changed before secure readback")
            chunks: list[bytes] = []
            remaining = _MAX_READ + 1
            while remaining:
                chunk = os.read(fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(fd)
            if len(data) > _MAX_READ or _stable(after) != expected:
                raise ControlledFixtureError(f"{label} changed during secure readback")
            self.assert_bindings()
            return data, before
        except OSError as error:
            raise ControlledFixtureError(f"{label} secure readback failed") from error

    def list_directory(self, name: str) -> tuple[str, ...]:
        self.assert_bindings()
        _, fd = self._pin(name)
        try:
            before = os.fstat(fd)
            entries = tuple(os.listdir(fd))
            after = os.fstat(fd)
        except OSError as error:
            raise ControlledFixtureError("controlled fixture directory enumeration failed") from error
        if _stable(before) != _stable(after):
            raise ControlledFixtureError("controlled fixture directory changed during enumeration")
        self.assert_bindings()
        return entries

    def persist(self, evidence: "ProvisioningEvidence", *, preserve_on_binding_failure: bool = False) -> Path:
        from .evidence import persist

        if preserve_on_binding_failure:
            self.assert_ledger_binding()
        else:
            self.assert_bindings()
        result = persist(
            evidence,
            self._root_path / self._evidence_name,
            directory_fd=self.evidence_fd,
        )
        if preserve_on_binding_failure:
            self.assert_ledger_binding()
        else:
            self.assert_bindings()
        return result
