"""Tamper tests that only run under -O must stay wired into a workflow.

`scripts/test_*_optimization.py` re-runs a verifier in plain, `-O` and `-OO`
modes and requires the tampered packet to be rejected in each. `scripts/` is
not auto-discovered, so a test that no workflow lists is never executed — the
check it documents silently stops protecting anything.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'
WIRED = (
    'test_prepare_locked_cargo_home_admission.py',
    'test_main_checkpoint_optimization.py',
    'test_amm_checkpoint_optimization.py',
    'test_verify_current_checkpoint_optimization.py',
    'test_compared_checkpoint_optimization.py',
    'test_remaining_checkpoint_optimization.py',
    'test_capture_optimization.py',
    'test_captured_loader_optimization.py',
    'test_build_verified_optimization.py',
    'test_identity_audit_optimization.py',
)


class OptimizationWiringTests(unittest.TestCase):
    def test_every_optimization_tamper_test_is_run_by_a_workflow(self):
        text = '\n'.join(path.read_text() for path in sorted(WORKFLOWS.glob('*.yml')))
        missing = [name for name in WIRED if name not in text]
        self.assertEqual(missing, [], 'scripts/ is not auto-discovered; list the test in a workflow')

    def test_the_wired_tests_exist(self):
        missing = [name for name in WIRED if not (ROOT / 'scripts' / name).is_file()]
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
