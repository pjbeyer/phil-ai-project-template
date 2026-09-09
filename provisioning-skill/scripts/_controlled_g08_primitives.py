"""Closed descriptor-relative primitives for the controlled G08-C fixture."""
import os
import stat


class ControlledG08PrimitiveError(RuntimeError):
    """A controlled G08-C filesystem primitive did not complete."""


_CAPABILITY = object()
O_CLOEXEC = os.O_CLOEXEC
O_NOFOLLOW = os.O_NOFOLLOW
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC

# This registry is an admission guard, not a hostile-Python sandbox.  Only the
# private factory registers directory descriptors; every public-looking
# primitive rejects an arbitrary integer even if its caller obtained the
# module-private capability in the same process.
_CHILDREN = {
    "<root>": frozenset({"repository", "evidence", "fixture"}),
    "repository": frozenset({".beads"}),
    ".beads": frozenset({"backup", "metadata.json", "dolt-backup.json"}),
    "backup": frozenset({"snapshot.json"}),
    "evidence": None,  # sealed evidence names are registered by the factory
    "fixture": frozenset({".specify"}),
    ".specify": frozenset({"memory", "integration.json", "components.json"}),
    "memory": frozenset({"constitution.md"}),
}
_FACTORY_FDS = {}
_FILE_FDS = {}
_PENDING_DIRECTORY_FDS = set()
_PENDING_FILE_FDS = set()


class _DirectoryFD:
    """Opaque factory-issued directory handle; raw fd integers never leave primitives."""
    __slots__ = ("_fd",)

    def __init__(self, fd):
        object.__setattr__(self, "_fd", fd)

    def __setattr__(self, name, value):
        raise AttributeError("controlled G08-C directory capabilities are immutable")


class _FileFD:
    """Opaque factory-issued regular-file handle; raw fd integers never leave primitives."""
    __slots__ = ("_fd",)

    def __init__(self, fd):
        object.__setattr__(self, "_fd", fd)

    def __setattr__(self, name, value):
        raise AttributeError("controlled G08-C file capabilities are immutable")


def _fd_identity(fd):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_mode)


def _require(capability):
    if capability is not _CAPABILITY:
        raise ControlledG08PrimitiveError("controlled G08-C primitive capability was invalid")


def _raw_directory(fd):
    if type(fd) is not _DirectoryFD or fd not in _FACTORY_FDS:
        raise ControlledG08PrimitiveError("controlled G08-C directory descriptor was not factory-issued")
    raw, identity, _allowed = _FACTORY_FDS[fd]
    if _fd_identity(raw) != identity:
        raise ControlledG08PrimitiveError("controlled G08-C directory descriptor changed")
    return raw


def _raw_file(fd):
    if type(fd) is not _FileFD or fd not in _FILE_FDS:
        raise ControlledG08PrimitiveError("controlled G08-C file descriptor was not factory-issued")
    raw, identity = _FILE_FDS[fd]
    if _fd_identity(raw) != identity:
        raise ControlledG08PrimitiveError("controlled G08-C file descriptor changed")
    return raw


def _mark_pending_directory(capability, fd):
    _require(capability)
    if type(fd) is not int:
        raise ControlledG08PrimitiveError("controlled G08-C pending directory was invalid")
    _PENDING_DIRECTORY_FDS.add(fd)


def _close_unadmitted_directory(capability, fd):
    _require(capability)
    if type(fd) is not int or fd in _PENDING_DIRECTORY_FDS:
        raise ControlledG08PrimitiveError("controlled G08-C unadmitted directory was invalid")
    os.close(fd)


def _close_pending_directory(capability, fd):
    _require(capability)
    if type(fd) is not int or fd not in _PENDING_DIRECTORY_FDS:
        raise ControlledG08PrimitiveError("controlled G08-C pending directory was invalid")
    try:
        os.close(fd)
    except Exception:
        # Preserve raw-FD ownership so a caller can make one explicit
        # fail-closed cleanup attempt rather than losing an open descriptor.
        raise
    _PENDING_DIRECTORY_FDS.remove(fd)


def _register_directory(capability, fd, label, names=None):
    _require(capability)
    if label not in _CHILDREN:
        raise ControlledG08PrimitiveError("controlled G08-C directory admission was invalid")
    if type(fd) is int:
        raw = fd
        existing = None
        if raw not in _PENDING_DIRECTORY_FDS:
            raise ControlledG08PrimitiveError("controlled G08-C directory admission was invalid")
    elif type(fd) is _DirectoryFD and fd in _FACTORY_FDS:
        raw = _raw_directory(fd)
        existing = fd
    else:
        raise ControlledG08PrimitiveError("controlled G08-C directory admission was invalid")
    allowed = _CHILDREN[label] if names is None else frozenset(names)
    if allowed is None or any(type(name) is not str or not name or "/" in name or "\x00" in name or name in {".", ".."} for name in allowed):
        raise ControlledG08PrimitiveError("controlled G08-C directory admission was invalid")
    handle = _DirectoryFD(raw) if existing is None else existing
    try:
        identity = _fd_identity(raw)
        _FACTORY_FDS[handle] = (raw, identity, allowed)
    except Exception:
        # A registry insertion seam may raise after writing.  Remove a possible
        # partial handle before releasing the only raw-FD owner, but never let
        # registry cleanup prevent the pending descriptor from being closed.
        if existing is None:
            try:
                del _FACTORY_FDS[handle]
            except KeyError:
                pass
            if existing is None and raw in _PENDING_DIRECTORY_FDS:
                _close_pending_directory(capability, raw)
        raise
    if existing is None:
        _PENDING_DIRECTORY_FDS.discard(raw)
    return handle


def _require_entry(capability, parent_fd, name):
    _require(capability)
    raw = _raw_directory(parent_fd)
    if type(name) is not str or name not in _FACTORY_FDS[parent_fd][2]:
        raise ControlledG08PrimitiveError("controlled G08-C descriptor or name was not factory-issued")
    return raw


def _register_child(capability, fd, label, names=None):
    try:
        return _register_directory(capability, fd, label, names)
    except Exception:
        if type(fd) is int and fd in _PENDING_DIRECTORY_FDS:
            _close_pending_directory(capability, fd)
        raise


def _close_pending_file(capability, fd):
    _require(capability)
    if type(fd) is not int or fd not in _PENDING_FILE_FDS:
        raise ControlledG08PrimitiveError("controlled G08-C pending file was invalid")
    try:
        os.close(fd)
    except Exception:
        # Preserve raw-FD ownership so a caller can make one explicit
        # fail-closed cleanup attempt rather than losing an open descriptor.
        raise
    _PENDING_FILE_FDS.remove(fd)


def _register_file(capability, fd):
    _require(capability)
    if type(fd) is not int or fd not in _PENDING_FILE_FDS:
        raise ControlledG08PrimitiveError("controlled G08-C file admission was invalid")
    handle = _FileFD(fd)
    try:
        _FILE_FDS[handle] = (fd, _fd_identity(fd))
    except Exception as error:
        # File admission owns this raw descriptor until registry commit. A
        # failed identity or mapping write must not leak its unregistered FD.
        try:
            del _FILE_FDS[handle]
        except KeyError:
            pass
        try:
            _close_pending_file(capability, fd)
        except Exception as cleanup_error:
            raise ControlledG08PrimitiveError("controlled G08-C pending file cleanup failed") from cleanup_error
        raise error
    _PENDING_FILE_FDS.remove(fd)
    return handle


def _register_opened_file(capability, fd):
    try:
        return _register_file(capability, fd)
    except Exception:
        if fd in _PENDING_FILE_FDS:
            _close_pending_file(capability, fd)
        raise


def _require_file(capability, fd):
    _require(capability)
    return _raw_file(fd)


def fstat(capability, fd):
    _require(capability)
    raw = _raw_directory(fd) if type(fd) is _DirectoryFD else _raw_file(fd)
    return os.fstat(raw)


def fsync(capability, fd):
    _require(capability)
    raw = _raw_directory(fd) if type(fd) is _DirectoryFD else _raw_file(fd)
    os.fsync(raw)


def close(capability, fd):
    _require(capability)
    if type(fd) is _DirectoryFD:
        raw = _raw_directory(fd)
        registry = _FACTORY_FDS
    elif type(fd) is _FileFD:
        raw = _raw_file(fd)
        registry = _FILE_FDS
    else:
        raise ControlledG08PrimitiveError("controlled G08-C descriptor was not factory-issued")
    # Do not discard the only factory handle before close succeeds. A failed
    # close remains tracked so cleanup can fail closed instead of leaking an
    # unauthenticated raw descriptor.
    os.close(raw)
    del registry[fd]


def listdir(capability, fd):
    _require(capability)
    return os.listdir(_raw_directory(fd))


def open_directory(capability, parent_fd, name):
    return os.open(name, _DIR_FLAGS, dir_fd=_require_entry(capability, parent_fd, name))


def create_directory(capability, parent_fd, name):
    """Create and retain the validated child descriptor; never reopen by path."""
    parent_raw = _require_entry(capability, parent_fd, name)
    os.mkdir(name, 0o700, dir_fd=parent_raw)
    created_entry = stat_entry(capability, parent_fd, name)
    os.fsync(parent_raw)
    fd = open_directory(capability, parent_fd, name)
    try:
        parent = os.fstat(parent_raw)
        info = os.fstat(fd)
        entry = stat_entry(capability, parent_fd, name)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_dev != parent.st_dev
            or (info.st_dev, info.st_ino) != (created_entry.st_dev, created_entry.st_ino)
            or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)
        ):
            raise ControlledG08PrimitiveError("unsafe controlled G08-C directory")
        os.fsync(parent_raw)
        _PENDING_DIRECTORY_FDS.add(fd)
        return fd
    except Exception:
        os.close(fd)
        raise


def open_readonly(capability, parent_fd, name):
    raw = os.open(name, _READ_FLAGS, dir_fd=_require_entry(capability, parent_fd, name))
    _PENDING_FILE_FDS.add(raw)
    return _register_opened_file(capability, raw)


def create_writeonly(capability, parent_fd, name):
    raw = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=_require_entry(capability, parent_fd, name))
    _PENDING_FILE_FDS.add(raw)
    return _register_opened_file(capability, raw)


def set_mode(capability, parent_fd, name, mode):
    parent_raw = _require_entry(capability, parent_fd, name)
    if mode != 0o600:
        raise ControlledG08PrimitiveError("controlled G08-C leaf mode was invalid")
    os.chmod(name, mode, dir_fd=parent_raw, follow_symlinks=False)


def write_all(capability, fd, raw):
    raw_fd = _require_file(capability, fd)
    if type(raw) is not bytes:
        raise ControlledG08PrimitiveError("controlled G08-C write was invalid")
    written = 0
    while written < len(raw):
        count = os.write(raw_fd, raw[written:])
        if count <= 0:
            raise ControlledG08PrimitiveError("incomplete controlled G08-C write")
        written += count


def read_bounded(capability, fd, maximum):
    raw_fd = _require_file(capability, fd)
    if type(maximum) is not int or maximum <= 0:
        raise ControlledG08PrimitiveError("controlled G08-C read bound was invalid")
    parts = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(raw_fd, min(remaining, 4096))
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(parts)
    if len(raw) > maximum:
        raise ControlledG08PrimitiveError("controlled G08-C bound exceeded")
    return raw


def stat_entry(capability, parent_fd, name):
    return os.stat(name, dir_fd=_require_entry(capability, parent_fd, name), follow_symlinks=False)


def replace_ledger(capability, evidence_fd, held):
    evidence_raw = _raw_directory(evidence_fd)
    _require(capability)
    entry = stat_entry(capability, evidence_fd, "g08-c-ledger.next")
    if (
        not stat.S_ISREG(held.st_mode)
        or stat.S_IMODE(held.st_mode) != 0o600
        or not stat.S_ISREG(entry.st_mode)
        or stat.S_IMODE(entry.st_mode) != 0o600
        or (held.st_dev, held.st_ino) != (entry.st_dev, entry.st_ino)
    ):
        raise ControlledG08PrimitiveError("controlled G08-C transient ledger changed")
    os.replace("g08-c-ledger.next", "g08-c-ledger.json", src_dir_fd=evidence_raw, dst_dir_fd=evidence_raw)


def cleanup_next(capability, evidence_fd, held):
    evidence_raw = _raw_directory(evidence_fd)
    _require(capability)
    entry = stat_entry(capability, evidence_fd, "g08-c-ledger.next")
    if (
        not stat.S_ISREG(held.st_mode)
        or stat.S_IMODE(held.st_mode) != 0o600
        or not stat.S_ISREG(entry.st_mode)
        or stat.S_IMODE(entry.st_mode) != 0o600
        or (held.st_dev, held.st_ino) != (entry.st_dev, entry.st_ino)
    ):
        raise ControlledG08PrimitiveError("controlled G08-C transient ledger changed")
    os.unlink("g08-c-ledger.next", dir_fd=evidence_raw)
    os.fsync(evidence_raw)


def mode(info):
    return stat.S_IMODE(info.st_mode)


def is_directory(info):
    return stat.S_ISDIR(info.st_mode)


def is_regular(info):
    return stat.S_ISREG(info.st_mode)
