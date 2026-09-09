import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_live_gates import ControlledG01G03Tests

t = ControlledG01G03Tests("test_successful_controlled_slice_rechecks_and_reads_disk_without_live_readiness")
case = t.make_case()
_, home, _, request, config, fixture, controller = case
result = controller.run(request, configuration=config, home=home)
print(result.failed_gate)
print([(gate.gate.value, gate.status, gate.detail) for gate in result.gates])
print(result.mutation_attempts, result.mutations_completed)
print(fixture.operations)
case[0].cleanup()
