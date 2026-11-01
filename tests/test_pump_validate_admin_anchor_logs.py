"""The administration differential compares the framework's own log lines.

Its ``event_wrong``, ``missing_event`` and ``missing_program`` mutations exist to
move what the handler logs and which program it calls, so a run that compares only
the error name, the account bytes and the lamports count cannot see either.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS))
TOOL = SCRIPTS / 'pump_validate_admin.py'
CANDIDATE = ROOT / 'evidence/original/pump/deployed.so'


@unittest.skipUnless(importlib.util.find_spec('solders'), 'requires the documented solders runtime')
class AdministrationOutcomeTests(unittest.TestCase):
    def test_every_case_retains_and_compares_the_anchor_lines(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            completed = subprocess.run(
                [sys.executable, '-B', str(TOOL), '--candidate', str(CANDIDATE),
                 '--output', str(output)],
                cwd=ROOT, capture_output=True, text=True, timeout=300)
            self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
            report = json.loads(output.read_bytes())
        self.assertEqual(report['mismatches'], [])
        for case in report['cases']:
            for side in ('original', 'candidate'):
                outcome = case[side]
                self.assertEqual(outcome['anchor_logs'],
                                 [line for line in outcome['logs']
                                  if line.startswith(('Program log: ', 'Program data: '))],
                                 case['instruction'])
        # A case that fails a constraint has one; the comparison is not vacuous.
        self.assertTrue(any(case['original']['anchor_logs'] for case in report['cases']))

    def test_a_log_line_alone_is_a_difference_and_a_compute_tally_is_not(self):
        import pump_validate_admin as tool
        outcome = tool.execute(CANDIDATE, 'toggle_create_v2', b'\x01', 'authority_wrong')
        self.assertTrue(outcome['anchor_logs'])
        logged = dict(outcome, anchor_logs=outcome['anchor_logs'] + ['Program log: extra'])
        tallied = dict(outcome, logs=outcome['logs'] + ['Program x consumed 1 of 200000 compute units'])
        self.assertFalse(all(outcome[key] == logged[key] for key in tool.COMPARED))
        self.assertTrue(all(outcome[key] == tallied[key] for key in tool.COMPARED))


if __name__ == '__main__':
    unittest.main()
