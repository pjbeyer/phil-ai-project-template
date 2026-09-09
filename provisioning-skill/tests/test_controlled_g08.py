"""Failure-first V&V for the private controlled G08-C fixture.

Every case uses a disposable factory root. No test invokes a live adapter,
public CLI, command runner, credential provider, network client, Git, Beads,
Dolt, Copier, manifest, backup, or real SpecKit command.
"""

import ast
import builtins
import hashlib
import json
import os
import shutil
import stat
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from scripts import _controlled_g08 as controlled
from scripts import _controlled_g08_primitives as primitive


class ControlledG08Tests(unittest.TestCase):
    def make_controller(self):
        captured = []
        original = controlled.tempfile.mkdtemp

        def capture_root(*args, **kwargs):
            root = original(*args, **kwargs)
            captured.append(root)
            return root

        with patch.object(controlled.tempfile, "mkdtemp", side_effect=capture_root):
            controller = controlled._controlled_g08_for_test()
        self.assertEqual(len(captured), 1)
        root = Path(captured[0])
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return controller, root

    def read_ledger(self, root):
        return json.loads((root / "evidence" / "g08-c-ledger.json").read_text(encoding="ascii"))

    def test_success_is_private_exact_and_simulation_only(self):
        controller, root = self.make_controller()
        result = controller.run()
        self.assertEqual((result.gate, result.state, result.g07, result.g08_c, result.recorded), ("G08-C", "simulation", "passed", "passed", True))
        self.assertEqual(len(result.events), 10)
        self.assertEqual([event["kind"] for event in result.events], ["attempt", "completion"] * 5)
        fixture = root / "fixture" / ".specify"
        self.assertEqual(set(path.name for path in fixture.iterdir()), {"memory", "integration.json", "components.json"})
        self.assertEqual(json.loads((fixture / "integration.json").read_text(encoding="ascii")), controlled._INTEGRATION)
        components = json.loads((fixture / "components.json").read_text(encoding="ascii"))
        self.assertEqual(components, controlled._COMPONENTS)
        self.assertNotIn("verify", components["extensions"])
        self.assertNotIn("review", components["extensions"])
        self.assertNotIn("jira", components["extensions"])
        self.assertEqual((fixture / "memory" / "constitution.md").read_bytes(), controlled._CONSTITUTION)
        self.assertEqual((self.read_ledger(root)["g07"], self.read_ledger(root)["g08_c"]), ("passed", "passed"))
        self.assertEqual(stat.S_IMODE(fixture.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((fixture / "integration.json").stat().st_mode), 0o600)

    def test_root_admission_failure_closes_pending_descriptor(self):
        observed = []
        original_open = controlled.os.open
        original_close = controlled.os.close

        def capture_close(fd):
            observed.append(fd)
            return original_close(fd)

        with patch.object(primitive, "_register_directory", side_effect=primitive.ControlledG08PrimitiveError("injected root admission")), \
             patch.object(controlled.os, "close", side_effect=capture_close):
            with self.assertRaises(primitive.ControlledG08PrimitiveError):
                controlled._controlled_g08_for_test()
        self.assertEqual(len(observed), 1)
        with self.assertRaises(OSError):
            original_open("/dev/fd/" + str(observed[0]), primitive._DIR_FLAGS)

    def test_root_pending_mark_failure_closes_unadmitted_descriptor(self):
        observed = []
        original_open = controlled.os.open
        original_close = primitive.os.close

        def capture_close(fd):
            observed.append(fd)
            return original_close(fd)

        with patch.object(primitive, "_mark_pending_directory", side_effect=primitive.ControlledG08PrimitiveError("injected root pending")), \
             patch.object(primitive.os, "close", side_effect=capture_close):
            with self.assertRaises(primitive.ControlledG08PrimitiveError):
                controlled._controlled_g08_for_test()
        self.assertEqual(len(observed), 1)
        with self.assertRaises(OSError):
            original_open("/dev/fd/" + str(observed[0]), primitive._DIR_FLAGS)

    def test_controller_is_single_use(self):
        controller, root = self.make_controller()
        controller.run()
        before = self.read_ledger(root)
        with self.assertRaises(controlled.ControlledG08Error):
            controller.run()
        self.assertEqual(self.read_ledger(root), before)

    def test_factory_leaf_replacement_with_identical_bytes_is_predecessor_rejection(self):
        controller, root = self.make_controller()
        leaf = root / "repository" / ".beads" / "metadata.json"
        raw = leaf.read_bytes()
        leaf.unlink()
        leaf.write_bytes(raw)
        os.chmod(leaf, 0o600)
        result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("unproven", "partial", True))
        self.assertFalse((root / "fixture" / ".specify").exists())
        self.assertEqual((self.read_ledger(root)["g07"], self.read_ledger(root)["g08_c"]), ("unproven", "partial"))

    def test_tree_leaf_replacement_with_identical_bytes_is_partial(self):
        controller, root = self.make_controller()
        original = controlled._ControlledG08Controller._write_leaf
        swapped = False

        def write_then_swap(instance, parent_fd, name, raw):
            nonlocal swapped
            original(instance, parent_fd, name, raw)
            if name == "integration.json" and not swapped:
                swapped = True
                leaf = root / "fixture" / ".specify" / name
                saved = leaf.read_bytes()
                leaf.unlink()
                leaf.write_bytes(saved)
                os.chmod(leaf, 0o600)

        with patch.object(controlled._ControlledG08Controller, "_write_leaf", new=write_then_swap):
            result = controller.run()
        self.assertTrue(swapped)
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", True))

    def test_cross_device_child_binding_is_rejected(self):
        controller, _ = self.make_controller()
        original = controlled.os.fstat
        calls = 0

        class Info:
            pass

        def cross_device(fd):
            nonlocal calls
            info = original(fd)
            calls += 1
            if calls == 2:
                copy = Info()
                for field in ("st_mode", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
                    setattr(copy, field, getattr(info, field))
                copy.st_dev = info.st_dev + 1
                return copy
            return info

        with patch.object(controlled.os, "fstat", side_effect=cross_device):
            result = controller.run()
        self.assertEqual((result.g07, result.g08_c), ("unproven", "partial"))

    def test_predecessor_fingerprints_are_recomputed_for_each_proof(self):
        controller, _ = self.make_controller()
        original = controlled.hashlib.sha256
        calls = 0

        def count_hash(raw):
            nonlocal calls
            calls += 1
            return original(raw)

        with patch.object(controlled.hashlib, "sha256", side_effect=count_hash):
            result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "passed", True))
        self.assertGreaterEqual(calls, 12)

    def test_predecessor_path_removal_is_not_an_independent_failure(self):
        controller, root = self.make_controller()
        shutil.rmtree(root / "repository")
        result = controller.run()
        self.assertEqual((result.g07, result.g08_c), ("unproven", "partial"))
        self.assertFalse((root / "fixture" / ".specify").exists())

    def test_post_start_predecessor_tampering_preserves_history(self):
        controller, root = self.make_controller()
        original = controlled._ControlledG08Controller._predecessor
        calls = 0

        def tamper_after_first_mutation(instance, allow_specify=False):
            nonlocal calls
            calls += 1
            original(instance, allow_specify)
            if calls == 3:
                leaf = root / "repository" / ".beads" / "metadata.json"
                leaf.write_bytes(b"{}\n")

        with patch.object(controlled._ControlledG08Controller, "_predecessor", new=tamper_after_first_mutation):
            result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("unproven", "partial", True))
        ledger = self.read_ledger(root)
        self.assertEqual(ledger["events"][-1]["kind"], "predecessor-rejected")
        self.assertEqual([item["sequence"] for item in ledger["events"]], list(range(1, len(ledger["events"]) + 1)))

    def test_independent_write_failure_records_partial_after_durability(self):
        controller, root = self.make_controller()
        with patch.object(primitive, "create_directory", side_effect=OSError("injected")):
            result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", True))
        self.assertEqual((self.read_ledger(root)["g07"], self.read_ledger(root)["g08_c"]), ("passed", "partial"))

    def test_specify_replacement_after_open_is_independent_partial(self):
        controller, root = self.make_controller()
        original_create_directory = primitive.create_directory
        swapped = False

        def create_then_swap(capability, parent_fd, name):
            nonlocal swapped
            fd = original_create_directory(capability, parent_fd, name)
            if name == ".specify" and not swapped:
                swapped = True
                detached = root / "fixture" / ".specify-detached"
                os.rename(root / "fixture" / ".specify", detached)
                os.mkdir(root / "fixture" / ".specify", 0o700)
            return fd

        with patch.object(primitive, "create_directory", side_effect=create_then_swap):
            result = controller.run()
        self.assertTrue(swapped)
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", True))
        self.assertEqual(set(path.name for path in (root / "fixture").iterdir()), {".specify", ".specify-detached"})

    def test_directory_replacement_before_open_is_partial(self):
        controller, root = self.make_controller()
        original = primitive.open_directory
        replaced = False

        def replace_before_open(capability, parent_fd, name):
            nonlocal replaced
            if name == ".specify" and not replaced:
                replaced = True
                target = root / "fixture" / name
                detached = root / "fixture" / ".specify-detached"
                os.rename(target, detached)
                os.mkdir(target, 0o700)
            return original(capability, parent_fd, name)

        with patch.object(primitive, "open_directory", side_effect=replace_before_open):
            result = controller.run()
        self.assertTrue(replaced)
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", True))

    def test_final_transition_failure_cannot_report_passed(self):
        controller, root = self.make_controller()
        original = controlled._ControlledG08Controller._transition

        def fail_only_final(instance, ledger):
            if ledger.get("g08_c") == "passed":
                instance._last_transition_indeterminate = True
                return False
            return original(instance, ledger)

        with patch.object(controlled._ControlledG08Controller, "_transition", new=fail_only_final):
            result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", False))

    def test_post_replace_fsync_failure_is_indeterminate(self):
        controller, _ = self.make_controller()
        original = primitive.fsync
        seen = 0

        def fail_evidence_once(capability, fd):
            nonlocal seen
            if fd == controller._evidence_fd:
                seen += 1
                if seen == 2:
                    raise OSError("injected post-replace fsync")
            return original(capability, fd)

        with patch.object(primitive, "fsync", side_effect=fail_evidence_once):
            result = controller.run()
        self.assertEqual((result.g08_c, result.recorded), ("partial", False))

    def test_terminal_ledger_readback_failure_is_indeterminate(self):
        controller, _ = self.make_controller()
        original = controlled._ControlledG08Controller._ledger
        calls = 0

        def fail_after_transition(instance):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise controlled.ControlledG08Error("injected post-replace readback")
            return original(instance)

        with patch.object(controlled._ControlledG08Controller, "_ledger", new=fail_after_transition):
            result = controller.run()
        self.assertEqual((result.g08_c, result.recorded), ("partial", False))

    def test_fixed_cleanup_makes_fresh_terminal_partial_transition(self):
        controller, root = self.make_controller()
        original = primitive.write_all
        calls = 0

        def fail_first_transition_write(capability, fd, raw):
            nonlocal calls
            self.assertIs(capability, primitive._CAPABILITY)
            calls += 1
            if calls == 1:
                raise OSError("injected preparation failure")
            return original(capability, fd, raw)

        with patch.object(primitive, "write_all", side_effect=fail_first_transition_write):
            result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", True))
        self.assertFalse((root / "evidence" / "g08-c-ledger.next").exists())
        self.assertEqual((self.read_ledger(root)["g07"], self.read_ledger(root)["g08_c"]), ("passed", "partial"))

    def test_two_pre_replace_failures_do_not_retry_terminal_partial(self):
        """One failed partial transition is never retried as a second terminal write."""
        controller, root = self.make_controller()
        original = primitive.write_all
        calls = 0

        def fail_first_two_transition_writes(capability, fd, raw):
            nonlocal calls
            calls += 1
            if calls <= 2:
                raise OSError("injected preparation failure")
            return original(capability, fd, raw)

        with patch.object(primitive, "write_all", side_effect=fail_first_two_transition_writes):
            result = controller.run()
        self.assertEqual(calls, 2)
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", False))
        self.assertFalse((root / "evidence" / "g08-c-ledger.next").exists())
        self.assertEqual((self.read_ledger(root)["g07"], self.read_ledger(root)["g08_c"]), ("unproven", "new"))

    def test_stale_next_is_rejected_without_cleanup(self):
        controller, root = self.make_controller()
        stale = root / "evidence" / "g08-c-ledger.next"
        stale.write_text("{}\n", encoding="ascii")
        with patch.object(primitive, "cleanup_next", side_effect=AssertionError("cleanup forbidden")):
            result = controller.run()
        self.assertEqual((result.g08_c, result.recorded), ("partial", False))
        self.assertTrue(stale.exists())

    def test_constructor_and_request_forgery_are_rejected(self):
        with self.assertRaises((controlled.ControlledG08Error, TypeError)):
            controlled._ControlledG08Controller(None, None, None, None, None, None, None, (), {}, None)
        with self.assertRaises(controlled.ControlledG08Error):
            controlled.ControlledG08Request("fixture\x00", "demo", "database")

    def test_primitive_rejects_nonfactory_descriptors_before_syscall(self):
        """T066 admission: a capability is insufficient without a factory token."""
        controller, root = self.make_controller()
        external = os.open(root, primitive._DIR_FLAGS)
        self.addCleanup(os.close, external)
        original_open, original_mkdir, original_stat = primitive.os.open, primitive.os.mkdir, primitive.os.stat
        with patch.object(primitive.os, "open", side_effect=AssertionError("external open reached")), \
             patch.object(primitive.os, "mkdir", side_effect=AssertionError("external mkdir reached")), \
             patch.object(primitive.os, "stat", side_effect=AssertionError("external stat reached")):
            for method, args in (
                (primitive.open_directory, (primitive._CAPABILITY, external, "fixture")),
                (primitive.create_directory, (primitive._CAPABILITY, external, "fixture")),
                (primitive.open_readonly, (primitive._CAPABILITY, external, "fixture")),
                (primitive.create_writeonly, (primitive._CAPABILITY, external, "fixture")),
                (primitive.set_mode, (primitive._CAPABILITY, external, "fixture", 0o600)),
                (primitive.stat_entry, (primitive._CAPABILITY, external, "fixture")),
            ):
                with self.subTest(method=method.__name__):
                    with self.assertRaises(primitive.ControlledG08PrimitiveError):
                        method(*args)
    def test_recycled_raw_descriptor_is_not_admitted(self):
        """A raw descriptor cannot replace the opaque factory capability."""
        controller, root = self.make_controller()
        original = controller._destination_fd
        raw = primitive._raw_directory(original)
        primitive.close(primitive._CAPABILITY, original)
        replacement = os.open(root / "fixture", primitive._DIR_FLAGS)
        try:
            os.dup2(replacement, raw)
        finally:
            if replacement != raw:
                os.close(replacement)
        controller._destination_fd = raw
        result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("unproven", "partial", True))

    def test_register_file_identity_failure_closes_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._PENDING_FILE_FDS.add(raw)
        try:
            with patch.object(primitive, "_fd_identity", side_effect=OSError("injected identity")):
                with self.assertRaises(OSError):
                    primitive._register_file(primitive._CAPABILITY, raw)
            self.assertNotIn(raw, [entry[0] for entry in primitive._FILE_FDS.values()])
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                os.close(raw)
            except OSError:
                pass

    def test_register_file_registry_commit_failure_closes_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._PENDING_FILE_FDS.add(raw)
        original = primitive._FILE_FDS

        class FailingRegistry(dict):
            def __setitem__(self, key, value):
                dict.__setitem__(self, key, value)
                raise OSError("injected registry commit")

        failing = FailingRegistry(original)
        try:
            with patch.object(primitive, "_FILE_FDS", failing):
                with self.assertRaises(OSError):
                    primitive._register_file(primitive._CAPABILITY, raw)
            self.assertEqual(failing, original)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                os.close(raw)
            except OSError:
                pass

    def test_register_file_close_failure_preserves_pending_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._PENDING_FILE_FDS.add(raw)
        original_close = primitive.os.close
        try:
            with patch.object(primitive, "_fd_identity", side_effect=OSError("injected identity")), \
                 patch.object(primitive.os, "close", side_effect=OSError("injected close")):
                with self.assertRaises(primitive.ControlledG08PrimitiveError):
                    primitive._register_file(primitive._CAPABILITY, raw)
            self.assertIn(raw, primitive._PENDING_FILE_FDS)
            os.fstat(raw)
            primitive._close_pending_file(primitive._CAPABILITY, raw)
            self.assertNotIn(raw, primitive._PENDING_FILE_FDS)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                original_close(raw)
            except OSError:
                pass

    def test_close_failure_retains_factory_handle_for_retry(self):
        controller, _ = self.make_controller()
        directory = controller._destination_fd
        reader = primitive.open_readonly(primitive._CAPABILITY, controller._beads_fd, "metadata.json")
        original_close = primitive.os.close
        for handle, registry in ((directory, primitive._FACTORY_FDS), (reader, primitive._FILE_FDS)):
            with self.subTest(handle=type(handle).__name__):
                with patch.object(primitive.os, "close", side_effect=OSError("injected close")):
                    with self.assertRaises(OSError):
                        primitive.close(primitive._CAPABILITY, handle)
                self.assertIn(handle, registry)
                primitive.close(primitive._CAPABILITY, handle)
                self.assertNotIn(handle, registry)

    def test_open_readonly_admission_failure_closes_factory_opened_descriptor(self):
        controller, _ = self.make_controller()
        before = set(primitive._PENDING_FILE_FDS)
        closed = []
        original_close = primitive.os.close

        def capture_close(fd):
            closed.append(fd)
            return original_close(fd)

        with patch.object(primitive, "_register_file", side_effect=OSError("injected admission")), \
             patch.object(primitive.os, "close", side_effect=capture_close):
            with self.assertRaises(OSError):
                primitive.open_readonly(primitive._CAPABILITY, controller._beads_fd, "metadata.json")
        self.assertEqual(primitive._PENDING_FILE_FDS, before)
        self.assertEqual(len(closed), 1)
        with self.assertRaises(OSError):
            os.fstat(closed[0])

    def test_register_opened_file_close_failure_is_reported_without_untracked_fd(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._PENDING_FILE_FDS.add(raw)
        original_close = primitive.os.close
        try:
            with patch.object(primitive, "_register_file", side_effect=OSError("injected admission")), \
                 patch.object(primitive.os, "close", side_effect=OSError("injected close")):
                with self.assertRaises(OSError):
                    primitive._register_opened_file(primitive._CAPABILITY, raw)
            self.assertIn(raw, primitive._PENDING_FILE_FDS)
            os.fstat(raw)
            primitive._close_pending_file(primitive._CAPABILITY, raw)
            self.assertNotIn(raw, primitive._PENDING_FILE_FDS)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                original_close(raw)
            except OSError:
                pass

    def test_register_directory_identity_failure_closes_pending_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._mark_pending_directory(primitive._CAPABILITY, raw)
        try:
            with patch.object(primitive, "_fd_identity", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    primitive._register_directory(primitive._CAPABILITY, raw, "fixture")
            self.assertNotIn(raw, primitive._PENDING_DIRECTORY_FDS)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                os.close(raw)
            except OSError:
                pass

    def test_register_directory_close_failure_preserves_pending_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._mark_pending_directory(primitive._CAPABILITY, raw)
        original_close = primitive.os.close
        try:
            with patch.object(primitive, "_fd_identity", side_effect=OSError("injected identity")), \
                 patch.object(primitive.os, "close", side_effect=OSError("injected close")):
                with self.assertRaises(OSError):
                    primitive._register_directory(primitive._CAPABILITY, raw, "fixture")
            self.assertIn(raw, primitive._PENDING_DIRECTORY_FDS)
            os.fstat(raw)
            primitive._close_pending_directory(primitive._CAPABILITY, raw)
            self.assertNotIn(raw, primitive._PENDING_DIRECTORY_FDS)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                original_close(raw)
            except OSError:
                pass

    def test_register_directory_registry_commit_failure_closes_pending_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._mark_pending_directory(primitive._CAPABILITY, raw)
        original = primitive._FACTORY_FDS

        class FailingRegistry(dict):
            def __setitem__(self, key, value):
                dict.__setitem__(self, key, value)
                raise OSError("injected registry commit")

        failing = FailingRegistry(original)
        try:
            with patch.object(primitive, "_FACTORY_FDS", failing):
                with self.assertRaises(OSError):
                    primitive._register_directory(primitive._CAPABILITY, raw, "fixture")
            self.assertNotIn(raw, primitive._PENDING_DIRECTORY_FDS)
            self.assertEqual(failing, original)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                os.close(raw)
            except OSError:
                pass

    def test_register_child_failure_closes_pending_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._mark_pending_directory(primitive._CAPABILITY, raw)
        try:
            with patch.object(primitive, "_register_directory", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    primitive._register_child(primitive._CAPABILITY, raw, "fixture")
            self.assertNotIn(raw, primitive._PENDING_DIRECTORY_FDS)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                os.close(raw)
            except OSError:
                pass

    def test_register_child_identity_failure_closes_pending_descriptor(self):
        controller, root = self.make_controller()
        raw = os.open(root / "fixture", primitive._DIR_FLAGS)
        primitive._mark_pending_directory(primitive._CAPABILITY, raw)
        try:
            with patch.object(primitive, "_fd_identity", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    primitive._register_child(primitive._CAPABILITY, raw, "fixture")
            self.assertNotIn(raw, primitive._PENDING_DIRECTORY_FDS)
            with self.assertRaises(OSError):
                os.fstat(raw)
        finally:
            try:
                os.close(raw)
            except OSError:
                pass

    def test_result_cannot_be_forged_as_live_g08_complete(self):
        result = controlled.ControlledG08Result("passed", "passed", [{"kind": "attempt", "mutation": "mkdir:.specify", "sequence": 1}], True)
        self.assertEqual((result.gate, result.state), ("G08-C", "simulation"))
        for name, value in (("gate", "G08"), ("state", "complete"), ("g08_c", "complete")):
            with self.subTest(attribute=name):
                with self.assertRaises(AttributeError):
                    setattr(result, name, value)
        with self.assertRaises((AttributeError, TypeError)):
            result.events[0]["kind"] = "forged"
        with self.assertRaises(controlled.ControlledG08Error):
            controlled.ControlledG08Result("passed", "passed", [{"kind": ["mutable"]}], True)
        for args in (("passed", "complete", [], True), ("new", "passed", [], True), ("passed", "passed", [], 1)):
            with self.subTest(args=args):
                with self.assertRaises(controlled.ControlledG08Error):
                    controlled.ControlledG08Result(*args)
        self.assertEqual(result.events[0]["kind"], "attempt")

    def test_quarantine_rejects_indirect_and_dormant_os_operations(self):
        method = self.test_quarantine_has_exact_operation_matrix_closure
        original_read_text = Path.read_text
        original_sources = {
            name: (SKILL_ROOT / "scripts" / name).read_text(encoding="utf-8")
            for name in ("_controlled_g08.py", "_controlled_g08_primitives.py")
        }
        for filename, injected in (
            ("_controlled_g08.py", "\nos_alias, = (os,)\nos_alias.system('x')\n"),
            ("_controlled_g08.py", "\nos.fsync(0)\n"),
            ("_controlled_g08.py", "\ngetattr(os, 'system')('x')\n"),
            ("_controlled_g08.py", "\n__builtins__['__import__']('subprocess')\n"),
            ("_controlled_g08.py", "\n__loader__.get_data('/etc/passwd')\n"),
            ("_controlled_g08.py", "\n__spec__.loader.get_data('/etc/passwd')\n"),
            ("_controlled_g08.py", "\nbreakpoint()\n"),
            ("_controlled_g08.py", "\nprint.__self__.__import__('subprocess').run([])\n"),
            ("_controlled_g08.py", "\nlen.__self__.__import__('subprocess').run([])\n"),
            ("_controlled_g08.py", "\nhelp.__call__('modules')\n"),
            ("_controlled_g08.py", "\n(lambda: help.__call__)()('modules')\n"),
            ("_controlled_g08.py", "\n(lambda: help)()('modules')\n"),
            ("_controlled_g08.py", "\n(lambda: input)()()\n"),
            ("_controlled_g08.py", "\nmatch (lambda: None):\n    case object(__globals__=scope):\n        scope['__builtins__']['input']()\n"),
            ("_controlled_g08.py", "\n(lambda: None).__globals__['os'].system('x')\n"),
            ("_controlled_g08.py", "\ntry:\n    1 / 0\nexcept Exception as error:\n    error.__traceback__.tb_frame.f_globals['os'].system('x')\n"),
            ("_controlled_g08.py", "\ntry:\n    1 / 0\nexcept Exception as error:\n    error.__traceback__.tb_frame.f_builtins['__import__']('subprocess').run([])\n"),
            ("_controlled_g08_primitives.py", "\ndef bad(fd):\n    return os.read(fd, 1)\n"),
            ("_controlled_g08_primitives.py", "\ndef create_directory(capability, parent_fd, name):\n    if False:\n        os.fsync(parent_raw)\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    while False:\n        os.fsync(raw)\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    if True:\n        pass\n    else:\n        os.fsync(raw)\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    return None if True else os.fsync(raw)\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    return os.fsync(raw) if not True else None\n"),
            ("_controlled_g08_primitives.py", "\ndef _require(capability):\n    return None\n"),
            ("_controlled_g08_primitives.py", "\n_require = lambda capability: None\n"),
            ("_controlled_g08_primitives.py", "\n_require, = (lambda capability: None,)\n"),
            ("_controlled_g08_primitives.py", "\ndef _require_entry(capability, parent_fd, name):\n    return parent_fd\n"),
            ("_controlled_g08_primitives.py", "\n_require_entry = lambda capability, parent_fd, name: parent_fd\n"),
            ("_controlled_g08_primitives.py", "\n_require_entry, = (lambda capability, parent_fd, name: 0,)\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    for _require in (lambda capability: None,):\n        pass\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    for _require_entry, in ((lambda capability, parent_fd, name: 0,),):\n        pass\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    if (_require_entry := (lambda capability, parent_fd, name: 0)):\n        pass\n"),
            ("_controlled_g08_primitives.py", "\nclass RebindGuard:\n    global _require\n    for _require in (lambda capability: None,):\n        pass\n"),
            ("_controlled_g08_primitives.py", "\ndef locally_rebind_guard():\n    global _require\n    _require = lambda capability: None\n"),
            ("_controlled_g08_primitives.py", "\nclass _require_entry:\n    pass\n"),
            ("_controlled_g08_primitives.py", "\ntry:\n    raise RuntimeError()\nexcept RuntimeError as _require:\n    pass\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(_require, fd):\n    return None\n"),
            ("_controlled_g08_primitives.py", "\nimport os as _require_entry\n"),
            ("_controlled_g08_primitives.py", "\n_require_file = lambda capability, fd: fd\n"),
            ("_controlled_g08_primitives.py", "\n_raw_file = lambda fd: fd\n"),
            ("_controlled_g08.py", "\ndef dormant_keyword_wrapper(capability, parent_fd, name):\n    if False:\n        return primitive.open_directory(primitive._CAPABILITY, parent_fd, name, names=None)\n"),
            ("_controlled_g08.py", "\ndef dormant_wrapper(capability, parent_fd, name):\n    if False:\n        return primitive.open_directory(capability, parent_fd, name)\n"),
            ("_controlled_g08.py", "\ndef _factory_leaf(parent_fd, name, payload):\n    if False:\n        primitive.fsync(primitive._CAPABILITY, parent_fd)\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    while not True:\n        os.fsync(raw)\n"),
            ("_controlled_g08_primitives.py", "\ndef fsync(capability, fd):\n    for _ in ():\n        os.fsync(raw)\n"),
        ):
            with self.subTest(filename=filename, injected=injected):
                original = original_sources[filename]
                digest = hashlib.sha256((original + injected).encode("utf-8")).hexdigest()
                self.assertNotEqual(digest, hashlib.sha256(original.encode("utf-8")).hexdigest())
                with patch.object(Path, "read_text", autospec=True, side_effect=lambda path, *a, **k: original_sources[path.name] + injected if path.name == filename else original_sources.get(path.name, original_read_text(path, *a, **k))):
                    with self.assertRaises(AssertionError):
                        method()

    def test_leaf_replacement_before_pin_is_partial(self):
        controller, root = self.make_controller()
        original = controlled._ControlledG08Controller._pin_tree_leaf
        replaced = False

        def replace_before_pin(instance, parent_fd, name, raw, reader, identity):
            nonlocal replaced
            if name == "integration.json" and not replaced:
                replaced = True
                target = root / "fixture" / ".specify" / name
                detached = target.with_name(name + ".detached")
                os.rename(target, detached)
                target.write_bytes(raw)
                os.chmod(target, 0o600)
            return original(instance, parent_fd, name, raw, reader, identity)

        with patch.object(controlled._ControlledG08Controller, "_pin_tree_leaf", new=replace_before_pin):
            result = controller.run()
        self.assertEqual((result.g08_c, result.recorded), ("partial", True))

    def test_ledger_replacement_before_bind_is_indeterminate(self):
        controller, root = self.make_controller()
        original = controlled._ControlledG08Controller._bind_ledger
        replaced = False

        def replace_before_bind(instance, identity=None):
            nonlocal replaced
            if not replaced:
                replaced = True
                target = root / "evidence" / "g08-c-ledger.json"
                raw = target.read_bytes()
                detached = target.with_name("ledger-detached.json")
                os.rename(target, detached)
                target.write_bytes(raw)
                os.chmod(target, 0o600)
            return original(instance, identity)

        with patch.object(controlled._ControlledG08Controller, "_bind_ledger", new=replace_before_bind):
            result = controller.run()
        self.assertEqual((result.g08_c, result.recorded), ("partial", False))

    def test_factory_runtime_matrix_admission(self):
        """T066 runtime proof covers every factory writer/admission primitive."""
        observed = []
        originals = {name: getattr(primitive, name) for name in ("create_directory", "open_directory", "create_writeonly", "replace_ledger", "_register_directory", "_register_child")}

        def directory(capability, parent_fd, name):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(name, {"repository", "evidence", "fixture", ".beads", "backup"})
            observed.append(("create-directory", name))
            return originals["create_directory"](capability, parent_fd, name)

        def opened(capability, parent_fd, name):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(name, {"repository", "evidence", "fixture", ".beads", "backup"})
            observed.append(("open-directory", name))
            return originals["open_directory"](capability, parent_fd, name)

        def created(capability, parent_fd, name):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertTrue(name in {"metadata.json", "dolt-backup.json", "snapshot.json", "g08-c-ledger.next"} or name.endswith(".json"))
            observed.append(("create-write", name))
            return originals["create_writeonly"](capability, parent_fd, name)

        def registered_directory(capability, fd, label, names=None):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(label, {"<root>", "repository", "evidence", "fixture", ".beads", "backup"})
            observed.append(("register-directory", label))
            return originals["_register_directory"](capability, fd, label, names)

        def registered_child(capability, fd, label, names=None):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(label, {"repository", "evidence", "fixture", ".beads", "backup"})
            self.assertTrue(names is None or (label == "evidence" and names == ()))
            observed.append(("register-child", label))
            return originals["_register_child"](capability, fd, label, names)

        def replaced(capability, evidence_fd, held):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertTrue(stat.S_ISREG(held.st_mode))
            observed.append(("replace", "g08-c-ledger.next:g08-c-ledger.json"))
            return originals["replace_ledger"](capability, evidence_fd, held)

        forbidden = {"system": "system", "popen": "popen", "execv": "execv", "execve": "execve", "spawnv": "spawnv", "spawnve": "spawnve"}
        with patch.object(primitive, "create_directory", side_effect=directory), \
             patch.object(primitive, "open_directory", side_effect=opened), \
             patch.object(primitive, "create_writeonly", side_effect=created), \
             patch.object(primitive, "_register_directory", side_effect=registered_directory), \
             patch.object(primitive, "_register_child", side_effect=registered_child), \
             patch.object(primitive, "replace_ledger", side_effect=replaced), \
             patch.object(builtins, "open", side_effect=AssertionError("ambient builtin open")), \
             patch.multiple(controlled.os, **{name: (lambda *args, _name=value, **kwargs: (_ for _ in ()).throw(AssertionError(_name))) for name, value in forbidden.items()}):
            controller = controlled._controlled_g08_for_test()
        controller.run()
        self.assertEqual([entry for entry in observed if entry[0] == "create-directory"], [("create-directory", name) for name in ("repository", "evidence", "fixture", ".beads", "backup")])
        self.assertEqual(observed.count(("replace", "g08-c-ledger.next:g08-c-ledger.json")), 1)
        self.assertEqual([entry for entry in observed if entry[0] == "register-child"], [("register-child", name) for name in ("repository", "evidence", "fixture", ".beads", "backup")])
        self.assertEqual([entry for entry in observed if entry[0] == "register-directory"], [("register-directory", name) for name in ("<root>", "repository", "evidence", "fixture", ".beads", "backup", "evidence")])

    def test_runtime_tripwires_and_success_matrix_names(self):
        controller, _ = self.make_controller()
        observed = []
        original_create_directory = primitive.create_directory
        original_create_writeonly = primitive.create_writeonly
        original_open_directory = primitive.open_directory
        original_replace = primitive.replace_ledger
        original_register_child = primitive._register_child
        original_register_directory = primitive._register_directory

        def record_directory(capability, parent_fd, name):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(name, {".specify", "memory"})
            observed.append(("mkdir", name))
            return original_create_directory(capability, parent_fd, name)

        def record_write(capability, parent_fd, name):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(name, {"g08-c-ledger.next", "integration.json", "components.json", "constitution.md"})
            observed.append(("write", name))
            return original_create_writeonly(capability, parent_fd, name)

        def record_open(capability, parent_fd, name):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(name, {".specify", "memory"})
            observed.append(("open-directory", name))
            return original_open_directory(capability, parent_fd, name)

        def record_replace(capability, evidence_fd, held):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertEqual(evidence_fd, controller._evidence_fd)
            self.assertTrue(stat.S_ISREG(held.st_mode))
            observed.append(("replace", "g08-c-ledger.next:g08-c-ledger.json"))
            return original_replace(capability, evidence_fd, held)

        def record_register_directory(capability, fd, label, names=None):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(label, {"<root>", "repository", "evidence", "fixture", ".beads", "backup", ".specify", "memory"})
            if label == "evidence":
                self.assertEqual(names, {controller._g06_name, controller._g07_name, "g08-c-ledger.json", "g08-c-ledger.next"})
            observed.append(("register-directory", label))
            return original_register_directory(capability, fd, label, names)

        def record_register_child(capability, fd, label, names=None):
            self.assertIs(capability, primitive._CAPABILITY)
            self.assertIn(label, {"repository", "evidence", "fixture", ".beads", "backup", ".specify", "memory"})
            self.assertTrue(names is None or (label == "evidence" and names == ()))
            observed.append(("register-child", label))
            return original_register_child(capability, fd, label, names)

        forbidden = {"system": "system", "popen": "popen", "execv": "execv", "execve": "execve", "spawnv": "spawnv", "spawnve": "spawnve"}
        with patch.object(primitive, "create_directory", side_effect=record_directory), \
             patch.object(primitive, "create_writeonly", side_effect=record_write), \
             patch.object(primitive, "open_directory", side_effect=record_open), \
             patch.object(primitive, "_register_directory", side_effect=record_register_directory), \
             patch.object(primitive, "_register_child", side_effect=record_register_child), \
             patch.object(primitive, "replace_ledger", side_effect=record_replace), \
             patch.object(builtins, "open", side_effect=AssertionError("ambient builtin open")), \
             patch.object(controlled.tempfile, "NamedTemporaryFile", side_effect=AssertionError("unexpected tempfile")), \
             patch.multiple(controlled.os, **{name: (lambda *args, _name=value, **kwargs: (_ for _ in ()).throw(AssertionError(_name))) for name, value in forbidden.items()}):
            result = controller.run()
        self.assertEqual((result.g08_c, result.recorded), ("passed", True))
        self.assertIn(("mkdir", ".specify"), observed)
        self.assertIn(("mkdir", "memory"), observed)
        self.assertIn(("write", "integration.json"), observed)
        self.assertIn(("write", "components.json"), observed)
        self.assertIn(("write", "constitution.md"), observed)
        self.assertIn(("replace", "g08-c-ledger.next:g08-c-ledger.json"), observed)
        self.assertEqual(observed.count(("mkdir", ".specify")), 1)
        self.assertEqual(observed.count(("mkdir", "memory")), 1)
        self.assertEqual(observed.count(("write", "integration.json")), 1)
        self.assertEqual(observed.count(("write", "components.json")), 1)
        self.assertEqual(observed.count(("write", "constitution.md")), 1)
        self.assertEqual(observed.count(("replace", "g08-c-ledger.next:g08-c-ledger.json")), 12)
        self.assertEqual(observed.count(("register-directory", "<root>")), 0)
        self.assertEqual(observed.count(("register-directory", "evidence")), 0)
        self.assertEqual([item for item in observed if item[0] == "register-child"], [("register-child", name) for name in (".specify", "memory")])
        self.assertEqual([item["kind"] for item in result.events], ["attempt", "completion"] * 5)

    def test_factory_allowed_primitives_fail_closed_before_issuance(self):
        """Every factory-only writer/admission primitive refuses issuance on failure."""
        names = ("create_directory", "open_directory", "create_writeonly", "replace_ledger", "_register_directory", "_register_child")
        for name in names:
            with self.subTest(primitive=name):
                with patch.object(primitive, name, side_effect=OSError("injected factory " + name)):
                    with self.assertRaises((OSError, controlled.ControlledG08Error)):
                        controlled._controlled_g08_for_test()

    def test_cleanup_failure_is_unrecorded_indeterminate(self):
        """A failed post-create cleanup may not claim the old ledger is terminal."""
        controller, root = self.make_controller()
        original_write = primitive.write_all
        calls = 0

        def fail_first_transition_write(capability, fd, raw):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected preparation failure")
            return original_write(capability, fd, raw)

        with patch.object(primitive, "write_all", side_effect=fail_first_transition_write), \
             patch.object(primitive, "cleanup_next", side_effect=OSError("injected cleanup failure")):
            result = controller.run()
        self.assertEqual((result.g07, result.g08_c, result.recorded), ("passed", "partial", False))
        self.assertTrue((root / "evidence" / "g08-c-ledger.next").exists())

    def test_each_allowed_controller_primitive_fails_closed(self):
        names = ("create_directory", "create_writeonly", "write_all", "set_mode", "replace_ledger", "open_directory", "open_readonly", "read_bounded", "stat_entry")
        for name in names:
            with self.subTest(primitive=name):
                controller, _ = self.make_controller()
                with patch.object(primitive, name, side_effect=OSError("injected " + name)):
                    result = controller.run()
                self.assertEqual(result.g08_c, "partial")
                self.assertFalse(result.g08_c == "passed")

    def test_quarantine_has_exact_operation_matrix_closure(self):
        """T066: static closed-world proof of imports, calls, and operation shapes."""
        forbidden_names = {"eval", "exec", "compile", "__import__", "__builtins__", "__loader__", "__spec__", "__self__", "open", "system", "popen", "getattr", "setattr", "delattr", "globals", "locals", "vars", "breakpoint", "print", "help", "LiveAdapter", "subprocess", "socket", "urllib", "http", "requests", "importlib", "runpy", "ctypes", "pathlib"}
        allowed_bare_calls = {
            "AttributeError", "ControlledG08Error", "ControlledG08Request", "ControlledG08Result", "ControlledG08PrimitiveError", "KeyError", "_ControlledG08Controller", "_DirectoryFD", "_FileFD", "_FrozenEvent", "_canonical", "_close_pending_directory", "_close_pending_file", "_close_unadmitted_directory", "_factory_leaf", "_fd_identity", "_g06_evidence", "_g07_evidence", "_identity", "_indented", "_ordinary_json", "_raw_directory", "_raw_file", "_register_directory", "_register_file", "_register_opened_file", "_require", "_require_entry", "_require_file", "_same_identity", "_same_inode", "all", "any", "enumerate", "frozenset", "len", "list", "min", "object", "open_directory", "set", "sorted", "stat_entry", "tuple", "type",
        }
        # Builtins are ambient authority too: a bare name can be captured and
        # invoked later through a lambda or other wrapper.  Permit only the
        # exact builtin names used by the two controlled modules.
        allowed_builtin_loads = {
            "AttributeError", "Exception", "KeyError", "OSError", "RuntimeError", "UnicodeError",
            "all", "any", "bool", "bytes", "dict", "enumerate", "float", "frozenset", "int",
            "len", "list", "min", "object", "property", "set", "sorted", "str", "tuple", "type",
        }
        allowed_named_attribute_calls = {
            "_controlled_g08.py": {
                "value": {"items"}, "event": {"items"}, "object": {"__setattr__"}, "raw": {"decode"},
                "ledger": {"get"}, "final_events": {"append"}, "predecessor_pins": {"append"},
                "controller": {"_transition", "_close"},
                "self": {"_read_exact", "_directory", "_assert_child_binding", "_entries", "_predecessor", "_read_pinned", "_ledger", "_bind_ledger", "_transition", "_after_transition_failure", "_result_partial", "_pin_tree_leaf", "_verify_tree_leaf", "_prove_predecessor_or_partial", "_tree_before_mutation", "_write_leaf", "_tree_complete", "_close"},
            },
            "_controlled_g08_primitives.py": {
                "object": {"__setattr__"}, "_PENDING_DIRECTORY_FDS": {"add", "discard", "remove"}, "_PENDING_FILE_FDS": {"add", "remove"}, "parts": {"append"},
            },
        }
        allowed_chained_attribute_calls = {
            "_controlled_g08.py": {
                "json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')",
                "json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2).encode('ascii')",
                "hashlib.sha256(_canonical({'database': database, 'destination': destination, 'prefix': prefix})).hexdigest()",
                "hashlib.sha256(_canonical({'g06': f06, 'tuple': [destination, prefix, database]})).hexdigest()",
                "self._tree_pins.get(name)", "self._tree_pins.pop(name, None)", "self._tree_pins.values()",
            },
            "_controlled_g08_primitives.py": {"b''.join(parts)"},
        }
        allowed_attribute_accesses = {
            "_controlled_g08.py": {
                "before.st_dev", "before.st_size", "controller._close", "controller._transition", "entry.st_dev", "entry.st_ino", "event.items", "final_events.append", "ledger.get", "object.__setattr__", "predecessor_pins.append", "raw.decode", "hashlib.sha256(_canonical({'database': database, 'destination': destination, 'prefix': prefix})).hexdigest", "hashlib.sha256(_canonical({'g06': f06, 'tuple': [destination, prefix, database]})).hexdigest", "info.st_ctime_ns", "info.st_dev", "info.st_ino", "info.st_mode", "info.st_mtime_ns", "info.st_size", "json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2).encode", "json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode", "left.st_dev", "left.st_ino", "opened.st_dev", "opened.st_ino", "parent.st_dev", "right.st_dev", "right.st_ino", "self._after_transition_failure", "self._assert_child_binding", "self._backup_fd", "self._beads_fd", "self._bind_ledger", "self._cleanup_succeeded", "self._close", "self._database", "self._destination", "self._destination_fd", "self._directory", "self._entries", "self._evidence_fd", "self._expected", "self._items", "self._last_transition_indeterminate", "self._ledger", "self._ledger_fd", "self._pin_tree_leaf", "self._predecessor", "self._predecessor_pins", "self._prefix", "self._prove_predecessor_or_partial", "self._read_exact", "self._read_pinned", "self._repository_fd", "self._request", "self._request.database", "self._request.destination", "self._request.prefix", "self._result_partial", "self._root_fd", "self._state", "self._transition", "self._tree_before_mutation", "self._tree_complete", "self._tree_pins", "self._tree_pins.get", "self._tree_pins.pop", "self._tree_pins.values", "self._verify_tree_leaf", "self._write_leaf", "value.items", "written.st_dev", "written.st_size",
            },
            "_controlled_g08_primitives.py": {
                "_PENDING_DIRECTORY_FDS.add", "_PENDING_DIRECTORY_FDS.discard", "_PENDING_DIRECTORY_FDS.remove", "_PENDING_FILE_FDS.add", "_PENDING_FILE_FDS.remove", "b''.join", "created_entry.st_dev", "created_entry.st_ino", "entry.st_dev", "entry.st_ino", "entry.st_mode", "held.st_dev", "held.st_ino", "held.st_mode", "info.st_dev", "info.st_ino", "info.st_mode", "object.__setattr__", "parent.st_dev", "parts.append",
            },
        }
        sources = {
            "_controlled_g08.py": {
                "imports": {"hashlib", "json", "os", "tempfile"},
                "attrs": {
                    "hashlib": {"sha256"}, "json": {"JSONDecodeError", "dumps", "loads"},
                    "os": {"open"},
                    "tempfile": {"mkdtemp"},
                    "primitive": {"ControlledG08PrimitiveError", "_CAPABILITY", "_DIR_FLAGS", "_register_child", "_register_directory", "_close_pending_directory", "_close_unadmitted_directory", "_mark_pending_directory", "cleanup_next", "close", "create_directory", "create_writeonly", "fsync", "fstat", "is_directory", "is_regular", "listdir", "mode", "open_directory", "open_readonly", "read_bounded", "replace_ledger", "set_mode", "stat_entry", "write_all"},
                },
            },
            "_controlled_g08_primitives.py": {
                "imports": {"os", "stat"},
                "attrs": {
                    "os": {"O_CLOEXEC", "O_CREAT", "O_DIRECTORY", "O_EXCL", "O_NOFOLLOW", "O_RDONLY", "O_WRONLY", "chmod", "close", "fsync", "fstat", "listdir", "mkdir", "open", "read", "replace", "stat", "unlink", "write"},
                    "stat": {"S_IMODE", "S_ISDIR", "S_ISREG"},
                },
            },
        }
        trees = {}
        parents = {}
        for filename, policy in sources.items():
            tree = ast.parse((SKILL_ROOT / "scripts" / filename).read_text(encoding="utf-8"))
            protected = {"_require", "_require_entry", "_require_file", "_raw_file"}
            guard_bindings = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in protected:
                    guard_bindings.append(("definition", node.name, node))
                elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in protected:
                    guard_bindings.append(("name", node.id, node))
                elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name) and node.target.id in protected:
                    guard_bindings.append(("named-expression", node.target.id, node))
                elif isinstance(node, ast.ExceptHandler) and node.name in protected:
                    guard_bindings.append(("exception", node.name, node))
                elif isinstance(node, ast.arg) and node.arg in protected:
                    guard_bindings.append(("parameter", node.arg, node))
                elif isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) in protected:
                    guard_bindings.append(("import", node.asname or node.name.split(".")[0], node))
            expected_guards = {"_require", "_require_entry", "_require_file", "_raw_file"} if filename == "_controlled_g08_primitives.py" else set()
            self.assertEqual(
                sorted((kind, name) for kind, name, _ in guard_bindings),
                sorted(("definition", name) for name in expected_guards),
                "capability guard bindings are closed-world: " + filename,
            )
            self.assertTrue(
                all(node in tree.body for _, _, node in guard_bindings),
                "capability guards must be module-level only: " + filename,
            )
            for scope in [tree] + [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]:
                definitions = [node.name for node in scope.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
                self.assertEqual(len(definitions), len(set(definitions)), "duplicate callable definition is forbidden: " + filename)
                protected = {"_require", "_require_entry", "_require_file", "_raw_file"}
                rebindings = [
                    node.id
                    for node in ast.walk(scope)
                    if isinstance(node, ast.Name)
                    and isinstance(node.ctx, ast.Store)
                    and node.id in protected
                ]
                self.assertEqual(rebindings, [], "capability guard rebinding is forbidden: " + filename)
            trees[filename] = tree
            parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            parents[filename] = parent
            module_names = set(policy["attrs"])
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id in module_names and isinstance(node.ctx, ast.Load):
                    # Modules may appear only as the direct base of a permitted
                    # attribute; tuple/default/annotation alias construction is forbidden.
                    self.assertIsInstance(parent.get(node), ast.Attribute, "module aliases are forbidden: " + ast.dump(node))
                if isinstance(node, ast.Import):
                    self.assertTrue(all(alias.name in policy["imports"] and alias.asname is None for alias in node.names), ast.dump(node))
                elif isinstance(node, ast.ImportFrom):
                    self.assertEqual(filename, "_controlled_g08.py")
                    self.assertIn(node.module, (None, ""))
                    self.assertEqual([(alias.name, alias.asname) for alias in node.names], [("_controlled_g08_primitives", "primitive")])
                elif isinstance(node, ast.Match):
                    self.fail("structural pattern matching is forbidden: " + ast.dump(node))
                elif isinstance(node, ast.Name):
                    self.assertNotIn(node.id, forbidden_names, ast.dump(node))
                    if isinstance(node.ctx, ast.Load) and hasattr(builtins, node.id):
                        self.assertIn(node.id, allowed_builtin_loads, "ambient builtin load is forbidden: " + ast.dump(node))
                    if isinstance(node.ctx, ast.Load) and isinstance(parent.get(node), ast.Call) and parent[node].func is node:
                        self.assertIn(node.id, allowed_bare_calls, "bare calls are closed-world: " + ast.dump(node))
                elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in policy["attrs"]:
                    self.assertIn(node.attr, policy["attrs"][node.value.id], ast.dump(node))
                    attribute_parent = parent[node]
                    direct_call = isinstance(attribute_parent, ast.Call) and attribute_parent.func is node
                    constant_reference = (
                        (filename == "_controlled_g08.py" and node.value.id == "primitive" and node.attr in {"_CAPABILITY", "_DIR_FLAGS", "ControlledG08PrimitiveError"})
                        or (filename == "_controlled_g08.py" and node.value.id == "json" and node.attr == "JSONDecodeError")
                        or (filename == "_controlled_g08_primitives.py" and node.value.id == "os" and node.attr.startswith("O_"))
                    )
                    self.assertTrue(direct_call or constant_reference, "module attributes may not be captured or called through aliases: " + ast.dump(node))
                elif isinstance(node, ast.Attribute):
                    # Attribute loads are closed-world.  This rejects captured
                    # ambient callables even if a wrapper invokes them later.
                    self.assertIn(
                        ast.unparse(node),
                        allowed_attribute_accesses[filename],
                        "attribute access is not allowed: " + ast.dump(node),
                    )
                    self.assertNotIn(
                        node.attr,
                        {
                            "__globals__", "__builtins__", "__dict__", "__getattribute__", "__subclasses__", "__self__", "__import__",
                            "__traceback__", "tb_frame", "f_globals", "f_builtins", "f_locals", "gi_frame", "cr_frame",
                        },
                        "dynamic namespace escape is forbidden: " + ast.dump(node),
                    )
                elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                    self.assertNotIn(node.value.id, policy["attrs"], "module aliases are forbidden: " + ast.dump(node))
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    base, attr = node.func.value.id, node.func.attr
                    if base in policy["attrs"]:
                        self.assertIn(attr, policy["attrs"][base], ast.dump(node))
                    if base == "os" and attr in {"close", "fstat", "fsync", "listdir", "read", "write"}:
                        self.assertTrue(node.args and not isinstance(node.args[0], ast.Constant), "raw descriptor operations require a tracked descriptor: " + ast.dump(node))

        def enclosing_function(tree, parent, node):
            while node in parent:
                node = parent[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node.name
            return "<module>"

        primitive_tree = trees["_controlled_g08_primitives.py"]
        primitive_parent = parents["_controlled_g08_primitives.py"]
        def control_flow_ancestors(parent, node):
            result = []
            while node in parent:
                node = parent[node]
                if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.For, ast.AsyncFor, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    result.append(node)
            return result

        allowed_os_loop_contexts = {
            ("write_all", "os.write(raw_fd, raw[written:])", "written < len(raw)"),
            ("read_bounded", "os.read(raw_fd, min(remaining, 4096))", "remaining"),
        }
        allowed_os_branch_contexts = {
            ("_register_directory", "os.close(raw)", "existing is None and raw in _PENDING_DIRECTORY_FDS"),
            ("_register_opened_file", "os.close(fd)", "fd in _PENDING_FILE_FDS"),
        }

        for call in ast.walk(primitive_tree):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "os"
            ):
                continue
            contexts = control_flow_ancestors(primitive_parent, call)
            for branch in (node for node in contexts if isinstance(node, (ast.If, ast.IfExp))):
                self.assertIn(
                    (enclosing_function(primitive_tree, primitive_parent, call), ast.unparse(call), ast.unparse(branch.test)),
                    allowed_os_branch_contexts,
                    "primitive OS branch context is not allowed: " + ast.unparse(call),
                )
            for loop in (node for node in contexts if isinstance(node, ast.While)):
                self.assertIn(
                    (enclosing_function(primitive_tree, primitive_parent, call), ast.unparse(call), ast.unparse(loop.test)),
                    allowed_os_loop_contexts,
                    "primitive OS loop context is not allowed: " + ast.unparse(call),
                )
            self.assertFalse(
                [
                    node
                    for node in contexts
                    if isinstance(node, (ast.For, ast.AsyncFor, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
                ],
                "primitive OS iteration context is not allowed: " + ast.unparse(call),
            )

        primitive_os_calls = sorted(
            (enclosing_function(primitive_tree, primitive_parent, call), call.func.attr, ast.unparse(call))
            for call in ast.walk(primitive_tree)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "os"
        )
        self.assertEqual(primitive_os_calls, sorted([
            ("_close_unadmitted_directory", "close", "os.close(fd)"),
            ("_close_pending_directory", "close", "os.close(fd)"),
            ("_fd_identity", "fstat", "os.fstat(fd)"),
            ("_close_pending_file", "close", "os.close(fd)"),
            ("fstat", "fstat", "os.fstat(raw)"),
            ("fsync", "fsync", "os.fsync(raw)"),
            ("close", "close", "os.close(raw)"),
            ("listdir", "listdir", "os.listdir(_raw_directory(fd))"),
            ("open_directory", "open", "os.open(name, _DIR_FLAGS, dir_fd=_require_entry(capability, parent_fd, name))"),
            ("create_directory", "mkdir", "os.mkdir(name, 448, dir_fd=parent_raw)"),
            ("create_directory", "fsync", "os.fsync(parent_raw)"),
            ("create_directory", "fstat", "os.fstat(parent_raw)"),
            ("create_directory", "fstat", "os.fstat(fd)"),
            ("create_directory", "fsync", "os.fsync(parent_raw)"),
            ("create_directory", "close", "os.close(fd)"),
            ("open_readonly", "open", "os.open(name, _READ_FLAGS, dir_fd=_require_entry(capability, parent_fd, name))"),
            ("create_writeonly", "open", "os.open(name, _WRITE_FLAGS, 384, dir_fd=_require_entry(capability, parent_fd, name))"),
            ("set_mode", "chmod", "os.chmod(name, mode, dir_fd=parent_raw, follow_symlinks=False)"),
            ("write_all", "write", "os.write(raw_fd, raw[written:])"),
            ("read_bounded", "read", "os.read(raw_fd, min(remaining, 4096))"),
            ("stat_entry", "stat", "os.stat(name, dir_fd=_require_entry(capability, parent_fd, name), follow_symlinks=False)"),
            ("replace_ledger", "replace", "os.replace('g08-c-ledger.next', 'g08-c-ledger.json', src_dir_fd=evidence_raw, dst_dir_fd=evidence_raw)"),
            ("cleanup_next", "unlink", "os.unlink('g08-c-ledger.next', dir_fd=evidence_raw)"),
            ("cleanup_next", "fsync", "os.fsync(evidence_raw)"),
        ]))

        # No direct OS helper may accept an unvalidated raw descriptor; the
        # exhaustive tuple matrix above is intentionally closed against dormant
        # helpers such as ``def bad(fd): os.read(fd, 1)``.

        controller = trees["_controlled_g08.py"]
        cparent = parents["_controlled_g08.py"]
        calls = [node for node in ast.walk(controller) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)]
        def direct(base, attr):
            return [(enclosing_function(controller, cparent, call), call) for call in calls if call.func.value.id == base and call.func.attr == attr]

        # The sole pathname bootstrap is exact; no root pathname use follows its open.
        mkdtemp = direct("tempfile", "mkdtemp")
        self.assertEqual(len(mkdtemp), 1)
        self.assertEqual(mkdtemp[0][0], "_controlled_g08_for_test")
        self.assertEqual({kw.arg: ast.literal_eval(kw.value) for kw in mkdtemp[0][1].keywords}, {"prefix": "controlled-g08-c-", "suffix": "", "dir": None})
        opens = direct("os", "open")
        self.assertEqual(len(opens), 1)
        self.assertEqual((opens[0][0], ast.unparse(opens[0][1].args[0]), ast.unparse(opens[0][1].args[1]), opens[0][1].keywords), ("_controlled_g08_for_test", "root_path", "primitive._DIR_FLAGS", []))
        factory = next(node for node in controller.body if isinstance(node, ast.FunctionDef) and node.name == "_controlled_g08_for_test")
        factory_body = factory.body
        bootstrap_assignment = next(index for index, node in enumerate(factory_body) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "root_path" for target in node.targets))
        bootstrap_open = next(index for index, node in enumerate(factory_body) if node is opens[0][1] or (isinstance(node, ast.Assign) and any(child is opens[0][1] for child in ast.walk(node))))
        self.assertEqual(bootstrap_open, bootstrap_assignment + 2)
        self.assertIsInstance(factory_body[bootstrap_assignment + 1], ast.Assign)
        self.assertEqual(ast.unparse(factory_body[bootstrap_assignment + 1].value), "root_path + '/fixture'")
        flags = next(node for node in ast.walk(trees["_controlled_g08_primitives.py"]) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_DIR_FLAGS" for target in node.targets))
        self.assertEqual(ast.unparse(flags.value), "os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC")
        open_line = opens[0][1].lineno
        later_root_uses = [node for node in ast.walk(factory) if isinstance(node, ast.Name) and node.id == "root_path" and isinstance(node.ctx, ast.Load) and node.lineno > open_line]
        self.assertEqual(later_root_uses, [])

        # Every direct primitive call must occur only in the listed matrix phase/helper.
        exact_contexts = {
            "create_directory": {"_controlled_g08_for_test", "run"},
            "open_directory": {"_controlled_g08_for_test", "run"},
            "_register_directory": {"_controlled_g08_for_test"},
            "_mark_pending_directory": {"_controlled_g08_for_test"},
            "_close_pending_directory": {"_controlled_g08_for_test"},
            "_close_unadmitted_directory": {"_controlled_g08_for_test"},
            "_register_child": {"_controlled_g08_for_test", "run"},
            "create_writeonly": {"_factory_leaf", "_transition", "_write_leaf"},
            "open_readonly": {"_factory_leaf", "_read_exact", "_bind_ledger", "_pin_tree_leaf", "_write_leaf"},
            "write_all": {"_factory_leaf", "_transition", "_write_leaf"},
            "set_mode": {"_factory_leaf", "_transition", "_write_leaf"},
            "read_bounded": {"_factory_leaf", "_read_exact"},
            "fstat": {"_factory_leaf", "_directory", "_read_exact", "_read_pinned", "_ledger", "_bind_ledger", "_transition", "_pin_tree_leaf", "_verify_tree_leaf", "_write_leaf", "_controlled_g08_for_test"},
            "fsync": {"_factory_leaf", "_transition", "_write_leaf"},
            "close": {"_factory_leaf", "_read_exact", "_bind_ledger", "_pin_tree_leaf", "_transition", "_write_leaf", "run", "_close", "_controlled_g08_for_test"},
            "listdir": {"_entries"},
            "is_directory": {"_directory", "_assert_child_binding", "_controlled_g08_for_test"},
            "is_regular": {"_factory_leaf", "_read_exact", "_bind_ledger", "_transition", "_pin_tree_leaf", "_verify_tree_leaf", "_write_leaf"},
            "mode": {"_directory", "_assert_child_binding", "_factory_leaf", "_read_exact", "_bind_ledger", "_transition", "_pin_tree_leaf", "_verify_tree_leaf", "_write_leaf", "_controlled_g08_for_test"},
            "replace_ledger": {"_transition"},
            "cleanup_next": {"_transition"},
            "stat_entry": {"_factory_leaf", "_read_exact", "_read_pinned", "_assert_child_binding", "_bind_ledger", "_ledger", "_transition", "_pin_tree_leaf", "_verify_tree_leaf", "_write_leaf"},
        }
        primitive_calls = [(enclosing_function(controller, cparent, call), call) for call in calls if call.func.value.id == "primitive"]
        unexpected_primitive_calls = [
            (function, call.func.attr, ast.unparse(call))
            for function, call in primitive_calls
            if call.func.attr not in exact_contexts or function not in exact_contexts[call.func.attr]
        ]
        self.assertEqual(
            unexpected_primitive_calls,
            [],
            "controller primitive call is absent from the closed operation matrix",
        )
        # Closed direct primitive-call tuples: capability, phase, descriptor variables and literals.
        expected_primitive_calls = [
            ('_controlled_g08_for_test', '_mark_pending_directory', ('primitive._CAPABILITY', 'root_fd')),
            ('_controlled_g08_for_test', '_register_directory', ('primitive._CAPABILITY', 'root_fd', "'<root>'")),
            ('_controlled_g08_for_test', '_close_pending_directory', ('primitive._CAPABILITY', 'root_fd')),
            ('_controlled_g08_for_test', '_close_unadmitted_directory', ('primitive._CAPABILITY', 'root_fd')),
            ('_controlled_g08_for_test', '_register_child', ('primitive._CAPABILITY', "primitive.create_directory(primitive._CAPABILITY, root_fd, 'repository')", "'repository'")),
            ('_controlled_g08_for_test', '_register_child', ('primitive._CAPABILITY', "primitive.create_directory(primitive._CAPABILITY, root_fd, 'evidence')", "'evidence'", '()')),
            ('_controlled_g08_for_test', '_register_child', ('primitive._CAPABILITY', "primitive.create_directory(primitive._CAPABILITY, root_fd, 'fixture')", "'fixture'")),
            ('_controlled_g08_for_test', '_register_child', ('primitive._CAPABILITY', "primitive.create_directory(primitive._CAPABILITY, repository_fd, '.beads')", "'.beads'")),
            ('_controlled_g08_for_test', '_register_child', ('primitive._CAPABILITY', "primitive.create_directory(primitive._CAPABILITY, beads_fd, 'backup')", "'backup'")),
            ('_controlled_g08_for_test', '_register_directory', ('primitive._CAPABILITY', 'evidence_fd', "'evidence'", "{g06_name, g07_name, 'g08-c-ledger.json', 'g08-c-ledger.next'}")),
            ('run', '_register_child', ('primitive._CAPABILITY', 'created_fd', "'.specify'")),
            ('run', '_register_child', ('primitive._CAPABILITY', 'created_fd', "'memory'")),
            ('_factory_leaf', 'create_writeonly', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_factory_leaf', 'write_all', ('primitive._CAPABILITY', 'writer', 'raw')),
            ('_factory_leaf', 'set_mode', ('primitive._CAPABILITY', 'parent_fd', 'name', '384')),
            ('_factory_leaf', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_factory_leaf', 'open_readonly', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_factory_leaf', 'read_bounded', ('primitive._CAPABILITY', 'reader', 'maximum')),
            ('_factory_leaf', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_read_exact', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_read_exact', 'open_readonly', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_read_exact', 'read_bounded', ('primitive._CAPABILITY', 'fd', 'maximum')),
            ('_read_exact', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_read_pinned', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_read_pinned', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_assert_child_binding', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_bind_ledger', 'open_readonly', ('primitive._CAPABILITY', 'self._evidence_fd', "'g08-c-ledger.json'")),
            ('_bind_ledger', 'stat_entry', ('primitive._CAPABILITY', 'self._evidence_fd', "'g08-c-ledger.json'")),
            ('_ledger', 'stat_entry', ('primitive._CAPABILITY', 'self._evidence_fd', "'g08-c-ledger.json'")),
            ('_ledger', 'stat_entry', ('primitive._CAPABILITY', 'self._evidence_fd', "'g08-c-ledger.json'")),
            ('_transition', 'create_writeonly', ('primitive._CAPABILITY', 'self._evidence_fd', "'g08-c-ledger.next'")),
            ('_transition', 'write_all', ('primitive._CAPABILITY', 'transient', 'raw')),
            ('_transition', 'set_mode', ('primitive._CAPABILITY', 'self._evidence_fd', "'g08-c-ledger.next'", '384')),
            ('_transition', 'replace_ledger', ('primitive._CAPABILITY', 'self._evidence_fd', 'held')),
            ('_transition', 'stat_entry', ('primitive._CAPABILITY', 'self._evidence_fd', "'g08-c-ledger.json'")),
            ('_transition', 'cleanup_next', ('primitive._CAPABILITY', 'self._evidence_fd', 'held')),
            ('_pin_tree_leaf', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_verify_tree_leaf', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_verify_tree_leaf', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_write_leaf', 'create_writeonly', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_write_leaf', 'write_all', ('primitive._CAPABILITY', 'fd', 'raw')),
            ('_write_leaf', 'set_mode', ('primitive._CAPABILITY', 'parent_fd', 'name', '384')),
            ('_write_leaf', 'open_readonly', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_write_leaf', 'stat_entry', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('run', 'create_directory', ('primitive._CAPABILITY', 'parent_fd', 'name')),
            ('_controlled_g08_for_test', 'create_directory', ('primitive._CAPABILITY', 'root_fd', "'repository'")),
            ('_controlled_g08_for_test', 'create_directory', ('primitive._CAPABILITY', 'root_fd', "'evidence'")),
            ('_controlled_g08_for_test', 'create_directory', ('primitive._CAPABILITY', 'root_fd', "'fixture'")),
            ('_controlled_g08_for_test', 'create_directory', ('primitive._CAPABILITY', 'repository_fd', "'.beads'")),
            ('_controlled_g08_for_test', 'create_directory', ('primitive._CAPABILITY', 'beads_fd', "'backup'")),
        ]
        direct_primitive_calls = [
            (
                function,
                call.func.attr,
                tuple(ast.unparse(arg) for arg in call.args),
                tuple((keyword.arg, ast.unparse(keyword.value)) for keyword in call.keywords),
            )
            for function, call in primitive_calls
        ]
        self.assertEqual(
            hashlib.sha256(
                json.dumps(sorted(direct_primitive_calls), separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "85ebbbec935b231911c39b57fcfaa6699e66c442b0039944daa9df72d421a510",
        )
        matrix_operations = {
            "create_directory", "open_directory", "_register_directory", "_mark_pending_directory",
            "_close_pending_directory", "_close_unadmitted_directory", "_register_child", "create_writeonly", "open_readonly",
            "write_all", "set_mode", "read_bounded", "replace_ledger", "cleanup_next", "stat_entry",
        }
        actual_primitive_calls = [
            (function, call.func.attr, tuple(ast.unparse(arg) for arg in call.args))
            for function, call in primitive_calls
            if call.func.attr in matrix_operations
        ]
        self.assertEqual(sorted(actual_primitive_calls), sorted(expected_primitive_calls))
        self.assertEqual(len(actual_primitive_calls), len(expected_primitive_calls))
        self.assertEqual(
            [(function, call.func.attr) for function, call in primitive_calls if function == "run"],
            [("run", "create_directory"), ("run", "_register_child"), ("run", "_register_child"), ("run", "close")],
        )
        self.assertEqual(
            [(ast.unparse(call.args[1]), ast.unparse(call.args[2])) for function, call in direct("primitive", "create_directory") if function == "_controlled_g08_for_test"],
            [("root_fd", "'repository'"), ("root_fd", "'evidence'"), ("root_fd", "'fixture'"), ("repository_fd", "'.beads'"), ("beads_fd", "'backup'")],
        )
        self.assertEqual(
            [(ast.unparse(call.args[1]), ast.unparse(call.args[2])) for function, call in direct("primitive", "open_directory") if function == "_controlled_g08_for_test"],
            [],
        )
        action_assignments = [node for node in ast.walk(factory) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "actions" for target in node.targets)]
        run = next(node for node in ast.walk(controller) if isinstance(node, ast.FunctionDef) and node.name == "run")
        action_assignments = [node for node in ast.walk(run) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "actions" for target in node.targets)]
        self.assertEqual(len(action_assignments), 1)
        self.assertEqual([
            tuple(ast.unparse(element) for element in item.elts)
            for item in action_assignments[0].value.elts
        ], [
            ("'mkdir:.specify'", "'mkdir'", "'.specify'", "None"),
            ("'mkdir:.specify/memory'", "'mkdir'", "'memory'", "None"),
            ("'write:.specify/integration.json'", "'write'", "'integration.json'", "_canonical(_INTEGRATION)"),
            ("'write:.specify/components.json'", "'write'", "'components.json'", "_canonical(_COMPONENTS)"),
            ("'write:.specify/memory/constitution.md'", "'write'", "'constitution.md'", "_CONSTITUTION"),
        ])

        primitives = trees["_controlled_g08_primitives.py"]
        pparent = parents["_controlled_g08_primitives.py"]
        pcalls = [node for node in ast.walk(primitives) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"]
        def pcall(attr):
            return [(enclosing_function(primitives, pparent, call), call) for call in pcalls if call.func.attr == attr]
        self.assertEqual([(name, [ast.unparse(arg) for arg in call.args], [(kw.arg, ast.unparse(kw.value)) for kw in call.keywords]) for name, call in pcall("open")], [
            ("open_directory", ["name", "_DIR_FLAGS"], [("dir_fd", "_require_entry(capability, parent_fd, name)")]),
            ("open_readonly", ["name", "_READ_FLAGS"], [("dir_fd", "_require_entry(capability, parent_fd, name)")]),
            ("create_writeonly", ["name", "_WRITE_FLAGS", "384"], [("dir_fd", "_require_entry(capability, parent_fd, name)")]),
        ])
        self.assertEqual([(name, ast.unparse(call.args[0]), ast.unparse(call.args[1]), [(kw.arg, ast.unparse(kw.value)) for kw in call.keywords]) for name, call in pcall("mkdir")], [("create_directory", "name", "448", [("dir_fd", "parent_raw")])])
        self.assertEqual([(name, ast.unparse(call.args[0]), ast.unparse(call.args[1]), [(kw.arg, ast.unparse(kw.value)) for kw in call.keywords]) for name, call in pcall("chmod")], [("set_mode", "name", "mode", [("dir_fd", "parent_raw"), ("follow_symlinks", "False")])])
        self.assertEqual([(name, [ast.unparse(arg) for arg in call.args], [(kw.arg, ast.unparse(kw.value)) for kw in call.keywords]) for name, call in pcall("replace")], [("replace_ledger", ["'g08-c-ledger.next'", "'g08-c-ledger.json'"], [("src_dir_fd", "evidence_raw"), ("dst_dir_fd", "evidence_raw")])])
        self.assertEqual([(name, ast.unparse(call.args[0]), [(kw.arg, ast.unparse(kw.value)) for kw in call.keywords]) for name, call in pcall("unlink")], [("cleanup_next", "'g08-c-ledger.next'", [("dir_fd", "evidence_raw")])])
        self.assertEqual([(name, ast.unparse(call.args[0]), [(kw.arg, ast.unparse(kw.value)) for kw in call.keywords]) for name, call in pcall("stat")], [("stat_entry", "name", [("dir_fd", "_require_entry(capability, parent_fd, name)"), ("follow_symlinks", "False")])])
        self.assertEqual(
            [ast.unparse(node.value) for node in ast.walk(primitives) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_WRITE_FLAGS" for target in node.targets)],
            ["os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC"],
        )
        self.assertEqual(
            [ast.unparse(node.value) for node in ast.walk(primitives) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_READ_FLAGS" for target in node.targets)],
            ["os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC"],
        )
        cleanup = next(node for node in ast.walk(primitives) if isinstance(node, ast.FunctionDef) and node.name == "cleanup_next")
        cleanup_calls = [node.func.attr for node in ast.walk(cleanup) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"]
        self.assertEqual(cleanup_calls[-2:], ["unlink", "fsync"])

    def test_no_public_cli_or_live_adapter_wiring(self):
        for path in (SKILL_ROOT / "scripts").glob("*.py"):
            if path.name in {"_controlled_g08.py", "_controlled_g08_primitives.py"}:
                continue
            self.assertNotIn("_controlled_g08", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
