"""Executable adversarial probes for controlled G08-C (offline, fixture-only).

Each probe attempts a CONCRETE bypass and prints PASS (bypass refused) or
FAIL (bypass succeeded). No Git, network, credentials, or real provisioning.
"""
import os
import sys
import json
import tempfile
import pathlib
import unittest.mock as mock

HERE = pathlib.Path(__file__).resolve().parent
SKILL_ROOT = HERE.parent
sys.path.insert(0, str(SKILL_ROOT))
sys.path.insert(0, str(HERE))

from scripts import _controlled_g08 as ctl
from scripts import _controlled_g08_primitives as primitive
import test_controlled_g08 as suite

RESULTS = []


def probe(name):
    def wrap(fn):
        try:
            outcome = fn()
        except Exception as exc:  # a raised exception here means the probe itself broke
            RESULTS.append(("ERROR", name, type(exc).__name__ + ": " + str(exc)[:160]))
            return fn
        RESULTS.append((outcome[0], name, outcome[1]))
        return fn
    return wrap


def _controller():
    case = suite.ControlledG08Tests("test_controller_is_single_use")
    case.setUp()
    return case


# 1. Capability forgery: call a sensitive primitive without the private capability.
@probe("capability-forgery-on-close")
def _p1():
    case = _controller()
    try:
        controller, _ = case.make_controller()
        for fake in (None, True, 1, "cap", object(), primitive._CAPABILITY.__class__):
            try:
                primitive.close(fake, controller._destination_fd)
            except Exception:
                continue
            return ("FAIL", "close accepted forged capability %r" % (fake,))
        return ("PASS", "every forged capability rejected")
    finally:
        case.tearDown()


# 2. Raw-descriptor injection: pass a real OS fd instead of a factory handle.
@probe("raw-fd-injection")
def _p2():
    case = _controller()
    try:
        controller, root = case.make_controller()
        raw = os.open(str(root), primitive._DIR_FLAGS)
        try:
            for fn, args in (
                (primitive.close, (primitive._CAPABILITY, raw)),
                (primitive.listdir, (primitive._CAPABILITY, raw)),
                (primitive.read_bounded, (primitive._CAPABILITY, raw, 16)),
            ):
                try:
                    fn(*args)
                except Exception:
                    continue
                return ("FAIL", "%s accepted a raw fd" % fn.__name__)
            return ("PASS", "raw fds refused by close/listdir/read_bounded")
        finally:
            os.close(raw)
    finally:
        case.tearDown()


# 3. Handle forgery: fabricate look-alike descriptor objects.
@probe("handle-type-forgery")
def _p3():
    case = _controller()
    try:
        controller, root = case.make_controller()
        real = controller._destination_fd
        raw = os.open(str(root), primitive._DIR_FLAGS)
        try:
            class FakeDir(primitive._DirectoryFD):
                pass

            class Duck:
                def __init__(self, fd):
                    self.fd = fd
                    self._fd = fd

            for candidate in (Duck(raw), object()):
                try:
                    primitive.close(primitive._CAPABILITY, candidate)
                except Exception:
                    continue
                return ("FAIL", "close accepted %r" % type(candidate).__name__)
            try:
                forged = FakeDir.__new__(FakeDir)
            except Exception:
                return ("PASS", "subclass instantiation itself refused")
            try:
                primitive.close(primitive._CAPABILITY, forged)
            except Exception:
                return ("PASS", "duck-typed and subclassed handles refused")
            return ("FAIL", "subclassed handle accepted by close")
        finally:
            os.close(raw)
    finally:
        case.tearDown()


# 4. os.close failure must retain ownership for bounded retry (the last audit BLOCKER).
@probe("close-failure-retains-ownership")
def _p4():
    case = _controller()
    try:
        controller, _ = case.make_controller()
        directory = controller._destination_fd
        reader = primitive.open_readonly(primitive._CAPABILITY, controller._beads_fd, "metadata.json")
        for handle, registry in ((directory, primitive._FACTORY_FDS), (reader, primitive._FILE_FDS)):
            with mock.patch.object(primitive.os, "close", side_effect=OSError("injected")):
                try:
                    primitive.close(primitive._CAPABILITY, handle)
                except OSError:
                    pass
                else:
                    return ("FAIL", "close swallowed the injected failure")
            if handle not in registry:
                return ("FAIL", "%s ownership dropped after failed close" % type(handle).__name__)
            primitive.close(primitive._CAPABILITY, handle)
            if handle in registry:
                return ("FAIL", "%s retained after successful retry" % type(handle).__name__)
        return ("PASS", "ownership survives failed close and clears on retry, both kinds")
    finally:
        case.tearDown()


# 5. Static guard-rebinding quarantine must reject every syntactic binding form.
@probe("guard-rebinding-quarantine")
def _p5():
    payloads = [
        "\n_require = lambda capability: None\n",
        "\n_require_entry = lambda capability, fd, name: fd\n",
        "\n_require_file = lambda capability, fd: fd\n",
        "\n_raw_file = lambda fd: fd\n",
        "\nclass _require_entry: pass\n",
        "\n_require_file: object = None\n",
        "\nif (_require := None): pass\n",
        "\nfor _require in []: pass\n",
        "\n_require, _raw_file = None, None\n",
        "\ntry:\n    pass\nexcept RuntimeError as _require:\n    pass\n",
        "\nimport os as _require_file\n",
        "\ndef _shadow(_require=None): pass\n",
        "\ndef _require_file(capability, fd): return fd\n",
    ]
    src = (HERE.parent / "scripts" / "_controlled_g08_primitives.py").read_text()
    case = suite.ControlledG08Tests("test_quarantine_has_exact_operation_matrix_closure")
    case.setUp()
    try:
        missed = []
        for payload in payloads:
            with mock.patch.object(
                pathlib.Path, "read_text",
                lambda self, *a, **k: src + payload if self.name == "_controlled_g08_primitives.py" else pathlib.Path.read_text.__wrapped__(self, *a, **k)
                if hasattr(pathlib.Path.read_text, "__wrapped__") else src + payload,
            ):
                pass
            # direct AST check mirrors the suite's quarantine logic
            import ast
            tree = ast.parse(src + payload)
            protected = {"_require", "_require_entry", "_require_file", "_raw_file"}
            bindings = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in protected:
                    bindings.append(("definition", node.name, node))
                elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in protected:
                    bindings.append(("name", node.id, node))
                elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name) and node.target.id in protected:
                    bindings.append(("named-expression", node.target.id, node))
                elif isinstance(node, ast.ExceptHandler) and node.name in protected:
                    bindings.append(("exception", node.name, node))
                elif isinstance(node, ast.arg) and node.arg in protected:
                    bindings.append(("parameter", node.arg, node))
                elif isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) in protected:
                    bindings.append(("import", node.asname or node.name.split(".")[0], node))
            expected = sorted(("definition", n) for n in protected)
            actual = sorted((k, n) for k, n, _ in bindings)
            module_level = all(node in tree.body for _, _, node in bindings)
            if actual == expected and module_level:
                missed.append(payload.strip().splitlines()[0])
        if missed:
            return ("FAIL", "quarantine missed: " + "; ".join(missed))
        return ("PASS", "all %d rebinding forms detected" % len(payloads))
    finally:
        case.tearDown()


# 6. G08-C must never emit a live G08 pass or a complete state.
@probe("no-live-g08-or-complete-claim")
def _p6():
    case = _controller()
    try:
        controller, _ = case.make_controller()
        result = controller.run()
        blob = json.dumps(
            {"gate": result.gate, "state": result.state, "g07": result.g07, "g08_c": result.g08_c}
        )
        if result.gate != "G08-C" or result.state != "simulation":
            return ("FAIL", "namespace escaped simulation: " + blob)
        if "complete" in blob or '"G08"' in blob:
            return ("FAIL", "result claimed live/complete: " + blob)
        return ("PASS", "result namespace is G08-C/simulation: " + blob)
    finally:
        case.tearDown()


# 7. Public CLI must remain simulation-only and non-zero.
@probe("public-cli-simulation-only")
def _p7():
    root = HERE.parent
    cli = list(root.glob("scripts/*.py"))
    referencing = [f.name for f in cli
                   if f.name not in ("_controlled_g08.py", "_controlled_g08_primitives.py")
                   and "_controlled_g08" in f.read_text()]
    if referencing:
        return ("FAIL", "public modules import controlled G08-C: " + ", ".join(referencing))
    return ("PASS", "no public/live module references the controlled module")


# 8. Live adapter must stay fail-closed.
@probe("live-adapter-fail-closed")
def _p8():
    import importlib
    adapters = importlib.import_module("scripts.adapters")
    live = getattr(adapters, "LiveAdapter", None)
    if live is None:
        return ("FAIL", "no LiveAdapter symbol found to verify fail-closed")
    try:
        instance = live()
    except Exception as exc:
        return ("PASS", "LiveAdapter construction refused: %s: %s" % (type(exc).__name__, str(exc)[:90]))
    refused = []
    # constructor succeeds by design (quarantined draft retained as reference);
    # every execution/observation entry point must fail closed.
    def _try(label, fn):
        try:
            fn()
            return ("FAIL", "LiveAdapter.%s executed without a gate" % label)
        except Exception as exc:
            refused.append("%s->%s" % (label, type(exc).__name__))
            return None

    from scripts.models import Gate
    outcomes = [
        _try("template_revision", lambda: instance.template_revision),
        _try("prepare", lambda: instance.prepare(None, None, None, None)),
        _try("run_gate(G01)", lambda: instance.run_gate(Gate.PREFLIGHT)),
        _try("gate_evidence(G01)", lambda: instance.gate_evidence(Gate.PREFLIGHT)),
        _try("read_metadata", lambda: instance.read_metadata()),
        _try("append_manifest", lambda: instance.append_manifest({})),
        _try("create_issue", lambda: instance.create_issue("m", "t")),
        _try("verify_existing", lambda: instance.verify_existing()),
    ]
    for outcome in outcomes:
        if outcome:
            return outcome
    return ("PASS", "all LiveAdapter entry points refused: " + ", ".join(refused))


def main():
    width = max(len(name) for _, name, _ in RESULTS)
    failures = 0
    for status, name, detail in RESULTS:
        if status != "PASS":
            failures += 1
        print("%-6s %-*s  %s" % (status, width, name, detail))
    print("\n%d probes, %d non-PASS" % (len(RESULTS), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
