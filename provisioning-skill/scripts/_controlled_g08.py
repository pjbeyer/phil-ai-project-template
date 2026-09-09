"""Private, factory-gated controlled G08-C fixture controller.

It initializes only a disposable descriptor-pinned synthetic fixture. There is
no public CLI, production adapter, subprocess, network, credential, or live
provisioning path in this module.
"""

import hashlib
import json
import os
import tempfile

from . import _controlled_g08_primitives as primitive


class ControlledG08Error(RuntimeError):
    """Controlled G08-C rejected input or stopped fail-closed."""


_MAX_TREE = 4096
_MAX_LEDGER = 16384
_CAPABILITY = object()
_COMPONENTS = {
    "extensions": ["agent-context", "verify-tasks", "spec-validate", "red-team", "cleanup", "reconcile", "checkpoint", "security-review"],
    "presets": ["command-density", "explicit-task-dependencies", "security-governance"],
    "state": "simulation",
}
_INTEGRATION = {"default_integration": "hermes", "integrations": ["hermes"], "state": "simulation"}
_CONSTITUTION = b"# Controlled SpecKit Constitution\n\n- Integration: hermes\n- State: simulation only\n- External operations: forbidden\n- Credentials: [REDACTED]\n"


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def _indented(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2).encode("ascii") + b"\n"


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _same_identity(left, right):
    return _identity(left) == _identity(right)


def _same_inode(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _ordinary_json(value):
    if type(value) in (str, int, float, bool) or value is None:
        return True
    if type(value) is list:
        return all(_ordinary_json(item) for item in value)
    if type(value) is dict:
        return all(type(key) is str and _ordinary_json(item) for key, item in value.items())
    return False


def _g06_evidence(destination, prefix, database, f06, run_id):
    return _indented({"actual_database": database, "destination": "[REDACTED]", "dolt_sync": "not-attempted", "failed_gate": None, "gates": [{"detail": "one exact controlled path/prefix/metadata-database record was appended, strictly reparsed, and descriptor-bound; coverage remains deferred", "gate": "G06", "status": "passed"}], "git_sync": "not-attempted", "mutation_attempts": ["G06:controlled-manifest-append"], "mutations_completed": ["G06:controlled-manifest-append"], "next_action": "Controlled G06 partial state; controlled G07 inspection is required before every later controlled operation.", "repository_identity": "controlled-fixture/g06", "request_fingerprint": f06, "resume_requirement": "controlled-inspection-required", "run_id": run_id, "simulation": True, "state": "partial", "template_revision": "not-reached"})


def _g07_evidence(destination, prefix, database, f07, run_id):
    return _indented({"actual_database": database, "destination": "[REDACTED]", "dolt_sync": "not-attempted", "failed_gate": None, "gates": [{"detail": "one exact controlled path/prefix/metadata-database record was appended, strictly reparsed, and descriptor-bound; coverage remains deferred", "gate": "G06", "status": "passed"}, {"detail": "synthetic backup root, sidecar, synchronization, freshness, modes, filesystem device, and exact descriptor-bound bytes were confirmed", "gate": "G07", "status": "passed"}], "git_sync": "not-attempted", "mutation_attempts": ["G06:controlled-manifest-append", "G07:controlled-backup-init", "G07:controlled-backup-sync"], "mutations_completed": ["G06:controlled-manifest-append", "G07:controlled-backup-init", "G07:controlled-backup-sync"], "next_action": "Controlled G07 passed; G08 and every live/public operation remain blocked and require a separate controlled design and approval.", "repository_identity": "controlled-fixture/g07", "request_fingerprint": f07, "resume_requirement": "controlled-inspection-required", "run_id": run_id, "simulation": True, "state": "partial", "template_revision": "not-reached"})


def _factory_leaf(parent_fd, name, raw, maximum):
    """Create, durably read back, and retain a read-only predecessor pin."""
    writer = primitive.create_writeonly(primitive._CAPABILITY, parent_fd, name)
    reader = None
    try:
        primitive.write_all(primitive._CAPABILITY, writer, raw)
        primitive.fsync(primitive._CAPABILITY, writer)
        primitive.set_mode(primitive._CAPABILITY, parent_fd, name, 0o600)
        primitive.fsync(primitive._CAPABILITY, writer)
        written = primitive.fstat(primitive._CAPABILITY, writer)
        primitive.fsync(primitive._CAPABILITY, parent_fd)
        entry_before = primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)
        reader = primitive.open_readonly(primitive._CAPABILITY, parent_fd, name)
        opened = primitive.fstat(primitive._CAPABILITY, reader)
        observed = primitive.read_bounded(primitive._CAPABILITY, reader, maximum)
        after = primitive.fstat(primitive._CAPABILITY, reader)
        entry_after = primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)
        parent = primitive.fstat(primitive._CAPABILITY, parent_fd)
        if (
            observed != raw
            or not primitive.is_regular(written)
            or primitive.mode(written) != 0o600
            or written.st_dev != parent.st_dev
            or not _same_identity(written, entry_before)
            or not _same_identity(written, opened)
            or not _same_identity(written, after)
            or not _same_identity(written, entry_after)
        ):
            raise ControlledG08Error("controlled G08-C factory leaf readback failed")
        result = reader, _identity(written)
        reader = None
        return result
    finally:
        primitive.close(primitive._CAPABILITY, writer)
        if reader is not None:
            primitive.close(primitive._CAPABILITY, reader)


class ControlledG08Request:
    __slots__ = ("_destination", "_prefix", "_database")

    def __init__(self, destination, prefix, database):
        if type(destination) is not str or not destination or "\x00" in destination:
            raise ControlledG08Error("controlled G08-C destination was invalid")
        for value in (prefix, database):
            if type(value) is not str or not value or "\x00" in value or "\n" in value or "\r" in value:
                raise ControlledG08Error("controlled G08-C authority was invalid")
        object.__setattr__(self, "_destination", destination)
        object.__setattr__(self, "_prefix", prefix)
        object.__setattr__(self, "_database", database)

    def __setattr__(self, name, value):
        raise AttributeError("controlled G08-C requests are immutable")

    @property
    def destination(self):
        return self._destination

    @property
    def prefix(self):
        return self._prefix

    @property
    def database(self):
        return self._database


class _FrozenEvent:
    """Immutable, contract-flat mapping for a returned ledger event."""
    __slots__ = ("_items",)

    def __init__(self, event):
        if type(event) is not dict or any(type(key) is not str or type(value) not in (str, int) for key, value in event.items()):
            raise ControlledG08Error("controlled G08-C event was invalid")
        object.__setattr__(self, "_items", tuple(sorted(event.items())))

    def __setattr__(self, name, value):
        raise AttributeError("controlled G08-C events are immutable")

    def __getitem__(self, key):
        for candidate, value in self._items:
            if key == candidate:
                return value
        raise KeyError(key)

    def items(self):
        return self._items


class ControlledG08Result:
    __slots__ = ("gate", "state", "g07", "g08_c", "events", "recorded")

    def __init__(self, g07, g08_c, events, recorded):
        if g07 not in ("passed", "unproven") or g08_c not in ("partial", "passed") or type(events) not in (list, tuple) or type(recorded) is not bool:
            raise ControlledG08Error("controlled G08-C result was invalid")
        object.__setattr__(self, "gate", "G08-C")
        object.__setattr__(self, "state", "simulation")
        object.__setattr__(self, "g07", g07)
        object.__setattr__(self, "g08_c", g08_c)
        object.__setattr__(self, "events", tuple(_FrozenEvent(event) for event in events))
        object.__setattr__(self, "recorded", recorded)

    def __setattr__(self, name, value):
        raise AttributeError("controlled G08-C results are immutable")


class _ControlledG08Controller:
    __slots__ = (
        "_request", "_root_fd", "_repository_fd", "_beads_fd", "_backup_fd", "_evidence_fd", "_destination_fd",
        "_predecessor_pins", "_tree_pins", "_ledger_fd", "_expected", "_state", "_last_transition_indeterminate", "_cleanup_succeeded",
    )

    def __init__(self, request, root_fd, repository_fd, beads_fd, backup_fd, evidence_fd, destination_fd, predecessor_pins, expected, capability=None):
        if capability is not _CAPABILITY or type(self) is not _ControlledG08Controller or type(request) is not ControlledG08Request:
            raise ControlledG08Error("controlled G08-C requires the private factory")
        self._request = request
        self._root_fd = root_fd
        self._repository_fd = repository_fd
        self._beads_fd = beads_fd
        self._backup_fd = backup_fd
        self._evidence_fd = evidence_fd
        self._destination_fd = destination_fd
        self._predecessor_pins = tuple(predecessor_pins)
        self._tree_pins = {}
        self._ledger_fd = None
        self._expected = expected
        self._state = "new"
        self._last_transition_indeterminate = False
        self._cleanup_succeeded = False

    def _close(self):
        for fd in (self._ledger_fd,) + tuple(pin[3] for pin in self._predecessor_pins) + tuple(pin[0] for pin in self._tree_pins.values()) + (
            self._destination_fd, self._evidence_fd, self._backup_fd, self._beads_fd, self._repository_fd, self._root_fd,
        ):
            if fd is not None:
                try:
                    primitive.close(primitive._CAPABILITY, fd)
                except (OSError, primitive.ControlledG08PrimitiveError):
                    pass
        self._ledger_fd = None
        self._predecessor_pins = ()
        self._tree_pins = {}
        self._destination_fd = self._evidence_fd = self._backup_fd = None
        self._beads_fd = self._repository_fd = self._root_fd = None

    def _directory(self, fd):
        info = primitive.fstat(primitive._CAPABILITY, fd)
        if not primitive.is_directory(info) or primitive.mode(info) != 0o700:
            raise ControlledG08Error("controlled G08-C directory was unsafe")
        return info

    def _read_exact(self, parent_fd, name, expected, maximum):
        before = primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)
        parent = primitive.fstat(primitive._CAPABILITY, parent_fd)
        if not primitive.is_regular(before) or primitive.mode(before) != 0o600 or before.st_dev != parent.st_dev or before.st_size > maximum:
            raise ControlledG08Error("controlled G08-C leaf was unsafe")
        fd = primitive.open_readonly(primitive._CAPABILITY, parent_fd, name)
        try:
            opened = primitive.fstat(primitive._CAPABILITY, fd)
            raw = primitive.read_bounded(primitive._CAPABILITY, fd, maximum)
            after = primitive.fstat(primitive._CAPABILITY, fd)
        finally:
            primitive.close(primitive._CAPABILITY, fd)
        entry_after = primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)
        if raw != expected or not _same_identity(before, opened) or not _same_identity(after, opened) or not _same_identity(entry_after, opened):
            raise ControlledG08Error("controlled G08-C leaf changed")
        return raw

    def _read_pinned(self, parent_fd, name, expected, maximum, pin_fd, factory_identity):
        pinned = primitive.fstat(primitive._CAPABILITY, pin_fd)
        entry = primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)
        if _identity(pinned) != factory_identity or _identity(entry) != factory_identity:
            raise ControlledG08Error("controlled G08-C factory leaf binding changed")
        raw = self._read_exact(parent_fd, name, expected, maximum)
        if _identity(primitive.fstat(primitive._CAPABILITY, pin_fd)) != factory_identity or _identity(primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)) != factory_identity:
            raise ControlledG08Error("controlled G08-C factory leaf binding changed")
        return raw

    def _entries(self, fd, expected):
        if set(primitive.listdir(primitive._CAPABILITY, fd)) != expected:
            raise ControlledG08Error("controlled G08-C entries were unsafe")

    def _assert_child_binding(self, parent_fd, name, child_fd):
        parent = self._directory(parent_fd)
        entry = primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)
        opened = self._directory(child_fd)
        if (
            not primitive.is_directory(entry)
            or primitive.mode(entry) != 0o700
            or entry.st_dev != parent.st_dev
            or opened.st_dev != parent.st_dev
            or (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ControlledG08Error("controlled G08-C directory binding changed")

    def _predecessor(self, allow_specify=False):
        roots = (
            (self._root_fd, "repository", self._repository_fd),
            (self._root_fd, "evidence", self._evidence_fd),
            (self._root_fd, "fixture", self._destination_fd),
            (self._repository_fd, ".beads", self._beads_fd),
            (self._beads_fd, "backup", self._backup_fd),
        )
        for parent_fd, name, expected_fd in roots:
            self._assert_child_binding(parent_fd, name, expected_fd)
        for fd in (self._root_fd, self._repository_fd, self._beads_fd, self._backup_fd, self._evidence_fd, self._destination_fd):
            self._directory(fd)
        self._entries(self._root_fd, {"repository", "evidence", "fixture"})
        self._entries(self._repository_fd, {".beads"})
        self._entries(self._beads_fd, {"metadata.json", "dolt-backup.json", "backup"})
        self._entries(self._backup_fd, {"snapshot.json"})
        self._entries(self._evidence_fd, {self._expected["g06_name"], self._expected["g07_name"], "g08-c-ledger.json"})
        if not allow_specify:
            self._entries(self._destination_fd, set())
        observed = {}
        for parent_fd, name, raw, pin_fd, pin_identity, maximum in self._predecessor_pins:
            observed[name] = self._read_pinned(parent_fd, name, raw, maximum, pin_fd, pin_identity)
        destination, prefix, database = self._request.destination, self._request.prefix, self._request.database
        f06 = hashlib.sha256(_canonical({"database": database, "destination": destination, "prefix": prefix})).hexdigest()
        f07 = hashlib.sha256(_canonical({"g06": f06, "tuple": [destination, prefix, database]})).hexdigest()
        if f07 != self._expected["f07"] or self._expected["g06_name"] != f06 + "-" + "0" * 32 + ".json" or self._expected["g07_name"] != f07 + "-" + "1" * 32 + ".json":
            raise ControlledG08Error("controlled G08-C predecessor fingerprint changed")
        for name, raw, expected in ((self._expected["g06_name"], observed[self._expected["g06_name"]], _g06_evidence(destination, prefix, database, f06, "0" * 32)), (self._expected["g07_name"], observed[self._expected["g07_name"]], _g07_evidence(destination, prefix, database, f07, "1" * 32))):
            try:
                parsed = json.loads(raw.decode("ascii"))
            except (UnicodeError, json.JSONDecodeError) as error:
                raise ControlledG08Error("controlled G08-C predecessor evidence was malformed") from error
            if not _ordinary_json(parsed) or raw != expected or _indented(parsed) != raw:
                raise ControlledG08Error("controlled G08-C predecessor evidence was unsafe")
        expected_ledger = {
            "authority": {
                "database": self._request.database,
                "destination": self._request.destination,
                "g07_fingerprint": self._expected["f07"],
                "prefix": self._request.prefix,
            },
            "gate": "G08-C",
            "state": "simulation",
        }
        ledger = self._ledger()
        if (
            type(ledger.get("events")) is not list
            or ledger.get("authority") != expected_ledger["authority"]
            or ledger.get("gate") != expected_ledger["gate"]
            or ledger.get("state") != expected_ledger["state"]
            or ledger.get("g07") not in ("unproven", "passed")
            or ledger.get("g08_c") not in ("new", "partial", "passed")
        ):
            raise ControlledG08Error("controlled G08-C ledger authority was unsafe")

    def _bind_ledger(self, expected_identity=None):
        candidate = primitive.open_readonly(primitive._CAPABILITY, self._evidence_fd, "g08-c-ledger.json")
        try:
            info = primitive.fstat(primitive._CAPABILITY, candidate)
            entry = primitive.stat_entry(primitive._CAPABILITY, self._evidence_fd, "g08-c-ledger.json")
            if (
                not primitive.is_regular(info)
                or primitive.mode(info) != 0o600
                or not _same_identity(info, entry)
                or (expected_identity is not None and _identity(info) != expected_identity)
            ):
                raise ControlledG08Error("controlled G08-C ledger binding was unsafe")
            old = self._ledger_fd
            self._ledger_fd = candidate
            candidate = None
            if old is not None:
                primitive.close(primitive._CAPABILITY, old)
        finally:
            if candidate is not None:
                primitive.close(primitive._CAPABILITY, candidate)

    def _ledger(self):
        if self._ledger_fd is None:
            raise ControlledG08Error("controlled G08-C ledger was not pinned")
        info = primitive.fstat(primitive._CAPABILITY, self._ledger_fd)
        entry = primitive.stat_entry(primitive._CAPABILITY, self._evidence_fd, "g08-c-ledger.json")
        if not _same_identity(info, entry):
            raise ControlledG08Error("controlled G08-C ledger binding changed")
        raw = self._read_exact(self._evidence_fd, "g08-c-ledger.json", self._expected["ledger"], _MAX_LEDGER)
        if not _same_identity(primitive.fstat(primitive._CAPABILITY, self._ledger_fd), info) or not _same_identity(primitive.stat_entry(primitive._CAPABILITY, self._evidence_fd, "g08-c-ledger.json"), info):
            raise ControlledG08Error("controlled G08-C ledger binding changed")
        try:
            value = json.loads(raw.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ControlledG08Error("controlled G08-C ledger was malformed") from error
        if type(value) is not dict or _canonical(value) != raw:
            raise ControlledG08Error("controlled G08-C ledger was noncanonical")
        return value

    def _transition(self, ledger):
        self._last_transition_indeterminate = False
        self._cleanup_succeeded = False
        raw = _canonical(ledger)
        transient = None
        held = None
        prepared = False
        replaced = False
        try:
            transient = primitive.create_writeonly(primitive._CAPABILITY, self._evidence_fd, "g08-c-ledger.next")
            prepared = True
            primitive.write_all(primitive._CAPABILITY, transient, raw)
            primitive.fsync(primitive._CAPABILITY, transient)
            primitive.set_mode(primitive._CAPABILITY, self._evidence_fd, "g08-c-ledger.next", 0o600)
            primitive.fsync(primitive._CAPABILITY, transient)
            info = primitive.fstat(primitive._CAPABILITY, transient)
            if not primitive.is_regular(info) or primitive.mode(info) != 0o600 or info.st_size != len(raw):
                raise ControlledG08Error("controlled G08-C transient ledger was unsafe")
            held = primitive.fstat(primitive._CAPABILITY, transient)
            primitive.replace_ledger(primitive._CAPABILITY, self._evidence_fd, held)
            replaced = True
            primitive.fsync(primitive._CAPABILITY, self._evidence_fd)
            stable = primitive.stat_entry(primitive._CAPABILITY, self._evidence_fd, "g08-c-ledger.json")
            if not _same_inode(held, stable):
                raise ControlledG08Error("controlled G08-C stable ledger binding changed")
            self._read_exact(self._evidence_fd, "g08-c-ledger.json", raw, _MAX_LEDGER)
            if not primitive.is_regular(stable) or primitive.mode(stable) != 0o600:
                raise ControlledG08Error("controlled G08-C stable ledger was unsafe")
            self._expected["ledger"] = raw
            self._bind_ledger(_identity(stable))
            self._ledger()
            primitive.close(primitive._CAPABILITY, transient)
            transient = None
            return True
        except Exception:
            if transient is not None and not replaced:
                try:
                    if prepared:
                        held = primitive.fstat(primitive._CAPABILITY, transient)
                        primitive.close(primitive._CAPABILITY, transient)
                        transient = None
                        primitive.cleanup_next(primitive._CAPABILITY, self._evidence_fd, held)
                        self._cleanup_succeeded = True
                except Exception:
                    pass
            if transient is not None:
                try:
                    primitive.close(primitive._CAPABILITY, transient)
                except (OSError, primitive.ControlledG08PrimitiveError):
                    pass
            if replaced:
                self._last_transition_indeterminate = True
            return False

    def _result_partial(self, g07, events, predecessor):
        try:
            ledger = self._ledger()
        except Exception:
            return ControlledG08Result(g07, "partial", events, False)
        final_events = list(events)
        if predecessor and final_events:
            final_events.append({"kind": "predecessor-rejected", "mutation": "predecessor:G07", "sequence": len(final_events) + 1})
        ledger["g07"] = g07
        ledger["g08_c"] = "partial"
        ledger["events"] = final_events
        transitioned = self._transition(ledger)
        if self._last_transition_indeterminate:
            return ControlledG08Result(g07, "partial", final_events, False)
        return ControlledG08Result(g07, "partial", final_events, transitioned)

    def _after_transition_failure(self, g07, events, predecessor=False):
        if self._last_transition_indeterminate or not self._cleanup_succeeded:
            return ControlledG08Result(g07, "partial", events, False)
        # Cleanup proves the failed pre-replace transition did not publish a
        # ledger. The contract permits precisely one fresh terminal attempt.
        self._cleanup_succeeded = False
        return self._result_partial(g07, events, predecessor)

    def _pin_tree_leaf(self, parent_fd, name, raw, reader, identity):
        try:
            info = primitive.fstat(primitive._CAPABILITY, reader)
            if _identity(info) != identity or not primitive.is_regular(info) or primitive.mode(info) != 0o600:
                raise ControlledG08Error("controlled G08-C tree leaf was unsafe")
            self._read_exact(parent_fd, name, raw, _MAX_TREE)
            if not _same_identity(primitive.fstat(primitive._CAPABILITY, reader), info) or not _same_identity(primitive.stat_entry(primitive._CAPABILITY, parent_fd, name), info):
                raise ControlledG08Error("controlled G08-C tree leaf binding changed")
            previous = self._tree_pins.pop(name, None)
            self._tree_pins[name] = (reader, identity)
            reader = None
            if previous is not None:
                primitive.close(primitive._CAPABILITY, previous[0])
        finally:
            if reader is not None:
                primitive.close(primitive._CAPABILITY, reader)

    def _verify_tree_leaf(self, parent_fd, name, raw):
        pinned = self._tree_pins.get(name)
        if pinned is None:
            raise ControlledG08Error("controlled G08-C tree leaf was not pinned")
        pin_fd, pinned_identity = pinned
        if _identity(primitive.fstat(primitive._CAPABILITY, pin_fd)) != pinned_identity or _identity(primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)) != pinned_identity:
            raise ControlledG08Error("controlled G08-C tree leaf binding changed")
        self._read_exact(parent_fd, name, raw, _MAX_TREE)
        if _identity(primitive.fstat(primitive._CAPABILITY, pin_fd)) != pinned_identity or _identity(primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)) != pinned_identity:
            raise ControlledG08Error("controlled G08-C tree leaf binding changed")

    def _write_leaf(self, parent_fd, name, raw):
        fd = primitive.create_writeonly(primitive._CAPABILITY, parent_fd, name)
        reader = None
        written = None
        try:
            primitive.write_all(primitive._CAPABILITY, fd, raw)
            primitive.fsync(primitive._CAPABILITY, fd)
            primitive.set_mode(primitive._CAPABILITY, parent_fd, name, 0o600)
            primitive.fsync(primitive._CAPABILITY, fd)
            primitive.fsync(primitive._CAPABILITY, parent_fd)
            written = primitive.fstat(primitive._CAPABILITY, fd)
            if not primitive.is_regular(written) or primitive.mode(written) != 0o600 or written.st_size != len(raw):
                raise ControlledG08Error("controlled G08-C tree leaf was unsafe")
            reader = primitive.open_readonly(primitive._CAPABILITY, parent_fd, name)
            opened = primitive.fstat(primitive._CAPABILITY, reader)
            entry = primitive.stat_entry(primitive._CAPABILITY, parent_fd, name)
            if not _same_identity(written, opened) or not _same_identity(entry, written):
                raise ControlledG08Error("controlled G08-C tree leaf binding changed")
        except Exception:
            if reader is not None:
                primitive.close(primitive._CAPABILITY, reader)
            raise
        finally:
            primitive.close(primitive._CAPABILITY, fd)
        self._pin_tree_leaf(parent_fd, name, raw, reader, _identity(written))

    def _tree_before_mutation(self, index, specify_fd, memory_fd):
        if index == 0:
            self._entries(self._destination_fd, set())
            return
        self._entries(self._destination_fd, {".specify"})
        self._assert_child_binding(self._destination_fd, ".specify", specify_fd)
        expected_specify = (set(), {"memory"}, {"memory", "integration.json"}, {"memory", "integration.json", "components.json"})[index - 1]
        self._entries(specify_fd, expected_specify)
        if index >= 2:
            self._assert_child_binding(specify_fd, "memory", memory_fd)
            self._entries(memory_fd, set())
        if index >= 3:
            self._verify_tree_leaf(specify_fd, "integration.json", _canonical(_INTEGRATION))
        if index >= 4:
            self._verify_tree_leaf(specify_fd, "components.json", _canonical(_COMPONENTS))

    def _tree_complete(self, specify_fd, memory_fd):
        self._entries(self._destination_fd, {".specify"})
        self._assert_child_binding(self._destination_fd, ".specify", specify_fd)
        self._entries(specify_fd, {"memory", "integration.json", "components.json"})
        self._assert_child_binding(specify_fd, "memory", memory_fd)
        self._entries(memory_fd, {"constitution.md"})
        self._verify_tree_leaf(specify_fd, "integration.json", _canonical(_INTEGRATION))
        self._verify_tree_leaf(specify_fd, "components.json", _canonical(_COMPONENTS))
        self._verify_tree_leaf(memory_fd, "constitution.md", _CONSTITUTION)

    def _prove_predecessor_or_partial(self, events, allow_specify=False):
        try:
            self._predecessor(allow_specify)
        except Exception:
            return self._result_partial("unproven", events, True)
        return None

    def run(self):
        if self._state != "new":
            raise ControlledG08Error("controlled G08-C controller is single-use")
        self._state = "finished"
        events = []
        specify_fd = memory_fd = None
        try:
            failed = self._prove_predecessor_or_partial(events)
            if failed is not None:
                return failed
            ledger = self._ledger()
            ledger["g07"] = "passed"
            if not self._transition(ledger):
                return self._after_transition_failure("passed", events)
            actions = [
                ("mkdir:.specify", "mkdir", ".specify", None),
                ("mkdir:.specify/memory", "mkdir", "memory", None),
                ("write:.specify/integration.json", "write", "integration.json", _canonical(_INTEGRATION)),
                ("write:.specify/components.json", "write", "components.json", _canonical(_COMPONENTS)),
                ("write:.specify/memory/constitution.md", "write", "constitution.md", _CONSTITUTION),
            ]
            for index, (mutation, kind, name, raw) in enumerate(actions):
                failed = self._prove_predecessor_or_partial(events, allow_specify=True)
                if failed is not None:
                    return failed
                self._tree_before_mutation(index, specify_fd, memory_fd)
                ledger = self._ledger()
                attempt = events + [{"kind": "attempt", "mutation": mutation, "sequence": len(events) + 1}]
                ledger["events"] = attempt
                if not self._transition(ledger):
                    return self._after_transition_failure("passed", events)
                events = attempt
                if kind == "mkdir":
                    parent_fd = self._destination_fd if name == ".specify" else specify_fd
                    created_fd = primitive.create_directory(primitive._CAPABILITY, parent_fd, name)
                    if name == ".specify":
                        specify_fd = primitive._register_child(primitive._CAPABILITY, created_fd, ".specify")
                        self._assert_child_binding(self._destination_fd, name, specify_fd)
                    else:
                        memory_fd = primitive._register_child(primitive._CAPABILITY, created_fd, "memory")
                        self._assert_child_binding(specify_fd, name, memory_fd)
                else:
                    self._write_leaf(memory_fd if name == "constitution.md" else specify_fd, name, raw)
                failed = self._prove_predecessor_or_partial(events, allow_specify=True)
                if failed is not None:
                    return failed
                completion = events + [{"kind": "completion", "mutation": mutation, "sequence": len(events) + 1}]
                ledger = self._ledger()
                ledger["events"] = completion
                if not self._transition(ledger):
                    return self._after_transition_failure("passed", events)
                events = completion
            self._tree_complete(specify_fd, memory_fd)
            failed = self._prove_predecessor_or_partial(events, allow_specify=True)
            if failed is not None:
                return failed
            ledger = self._ledger()
            ledger["g08_c"] = "passed"
            ledger["events"] = list(events)
            if not self._transition(ledger):
                return self._after_transition_failure("passed", events)
            return ControlledG08Result("passed", "passed", events, True)
        except Exception:
            return self._result_partial("passed", events, False)
        finally:
            for fd in (memory_fd, specify_fd):
                if fd is not None:
                    try:
                        primitive.close(primitive._CAPABILITY, fd)
                    except (OSError, primitive.ControlledG08PrimitiveError):
                        pass
            self._close()


def _controlled_g08_for_test(prefix="demo", database="demo_database"):
    """Create the sole disposable private G08-C fixture/controller pair."""
    root_path = tempfile.mkdtemp(prefix="controlled-g08-c-", suffix="", dir=None)
    destination = root_path + "/fixture"
    root_fd = os.open(root_path, primitive._DIR_FLAGS)
    del root_path
    root_pending = False
    root_admitted = False
    repository_fd = beads_fd = backup_fd = evidence_fd = destination_fd = None
    predecessor_pins = []
    controller = None
    try:
        primitive._mark_pending_directory(primitive._CAPABILITY, root_fd)
        root_pending = True
        root_fd = primitive._register_directory(primitive._CAPABILITY, root_fd, "<root>")
        root_admitted = True
        root_pending = False
        root_info = primitive.fstat(primitive._CAPABILITY, root_fd)
        if not primitive.is_directory(root_info) or primitive.mode(root_info) != 0o700:
            raise ControlledG08Error("controlled G08-C root was unsafe")
        repository_fd = primitive._register_child(primitive._CAPABILITY, primitive.create_directory(primitive._CAPABILITY, root_fd, "repository"), "repository")
        evidence_fd = primitive._register_child(primitive._CAPABILITY, primitive.create_directory(primitive._CAPABILITY, root_fd, "evidence"), "evidence", ())
        destination_fd = primitive._register_child(primitive._CAPABILITY, primitive.create_directory(primitive._CAPABILITY, root_fd, "fixture"), "fixture")
        beads_fd = primitive._register_child(primitive._CAPABILITY, primitive.create_directory(primitive._CAPABILITY, repository_fd, ".beads"), ".beads")
        backup_fd = primitive._register_child(primitive._CAPABILITY, primitive.create_directory(primitive._CAPABILITY, beads_fd, "backup"), "backup")
        request = ControlledG08Request(destination, prefix, database)
        f06 = hashlib.sha256(_canonical({"database": database, "destination": destination, "prefix": prefix})).hexdigest()
        f07 = hashlib.sha256(_canonical({"g06": f06, "tuple": [destination, prefix, database]})).hexdigest()
        r06, r07 = "0" * 32, "1" * 32
        g06_name, g07_name = f06 + "-" + r06 + ".json", f07 + "-" + r07 + ".json"
        primitive._register_directory(primitive._CAPABILITY, evidence_fd, "evidence", {g06_name, g07_name, "g08-c-ledger.json", "g08-c-ledger.next"})
        metadata = _canonical({"dolt_database": database, "dolt_mode": "server", "dolt_server_port": 3307})
        sidecar = _canonical({"database": database, "identity": "controlled-g07-sidecar/v1", "root": ".beads/backup"})
        snapshot = _canonical({"database": database, "fresh": True, "identity": "controlled-g07-snapshot/v1", "synchronized": True})
        g06 = _indented({"actual_database": database, "destination": "[REDACTED]", "dolt_sync": "not-attempted", "failed_gate": None, "gates": [{"detail": "one exact controlled path/prefix/metadata-database record was appended, strictly reparsed, and descriptor-bound; coverage remains deferred", "gate": "G06", "status": "passed"}], "git_sync": "not-attempted", "mutation_attempts": ["G06:controlled-manifest-append"], "mutations_completed": ["G06:controlled-manifest-append"], "next_action": "Controlled G06 partial state; controlled G07 inspection is required before every later controlled operation.", "repository_identity": "controlled-fixture/g06", "request_fingerprint": f06, "resume_requirement": "controlled-inspection-required", "run_id": r06, "simulation": True, "state": "partial", "template_revision": "not-reached"})
        g07 = _indented({"actual_database": database, "destination": "[REDACTED]", "dolt_sync": "not-attempted", "failed_gate": None, "gates": [{"detail": "one exact controlled path/prefix/metadata-database record was appended, strictly reparsed, and descriptor-bound; coverage remains deferred", "gate": "G06", "status": "passed"}, {"detail": "synthetic backup root, sidecar, synchronization, freshness, modes, filesystem device, and exact descriptor-bound bytes were confirmed", "gate": "G07", "status": "passed"}], "git_sync": "not-attempted", "mutation_attempts": ["G06:controlled-manifest-append", "G07:controlled-backup-init", "G07:controlled-backup-sync"], "mutations_completed": ["G06:controlled-manifest-append", "G07:controlled-backup-init", "G07:controlled-backup-sync"], "next_action": "Controlled G07 passed; G08 and every live/public operation remain blocked and require a separate controlled design and approval.", "repository_identity": "controlled-fixture/g07", "request_fingerprint": f07, "resume_requirement": "controlled-inspection-required", "run_id": r07, "simulation": True, "state": "partial", "template_revision": "not-reached"})
        for parent_fd, name, raw, maximum in ((beads_fd, "metadata.json", metadata, _MAX_TREE), (beads_fd, "dolt-backup.json", sidecar, _MAX_TREE), (backup_fd, "snapshot.json", snapshot, _MAX_TREE), (evidence_fd, g06_name, g06, _MAX_LEDGER), (evidence_fd, g07_name, g07, _MAX_LEDGER)):
            pin, pin_identity = _factory_leaf(parent_fd, name, raw, maximum)
            predecessor_pins.append((parent_fd, name, raw, pin, pin_identity, maximum))
        ledger = {"authority": {"database": database, "destination": destination, "g07_fingerprint": f07, "prefix": prefix}, "events": [], "gate": "G08-C", "g07": "unproven", "g08_c": "new", "state": "simulation"}
        expected = {"g06_name": g06_name, "g07_name": g07_name, "f07": f07, "ledger": b""}
        controller = _ControlledG08Controller(request, root_fd, repository_fd, beads_fd, backup_fd, evidence_fd, destination_fd, predecessor_pins, expected, _CAPABILITY)
        if not controller._transition(ledger):
            raise ControlledG08Error("controlled G08-C initial ledger was not durable")
        return controller
    except Exception:
        if controller is not None:
            controller._close()
        else:
            for fd in tuple(pin[3] for pin in predecessor_pins) + (destination_fd, evidence_fd, backup_fd, beads_fd, repository_fd):
                if fd is not None:
                    try:
                        primitive.close(primitive._CAPABILITY, fd)
                    except (OSError, primitive.ControlledG08PrimitiveError):
                        pass
            if root_admitted:
                try:
                    primitive.close(primitive._CAPABILITY, root_fd)
                except (OSError, primitive.ControlledG08PrimitiveError):
                    pass
            elif root_pending:
                try:
                    primitive._close_pending_directory(primitive._CAPABILITY, root_fd)
                except (OSError, primitive.ControlledG08PrimitiveError):
                    pass
            else:
                try:
                    primitive._close_unadmitted_directory(primitive._CAPABILITY, root_fd)
                except (OSError, primitive.ControlledG08PrimitiveError):
                    pass
        raise
