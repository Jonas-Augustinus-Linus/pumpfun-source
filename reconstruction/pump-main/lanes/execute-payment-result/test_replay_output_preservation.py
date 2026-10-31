"""The replay report path must not replace an input the report certifies."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ORIGINAL = ROOT / 'evidence/original/pump/deployed.so'
FIXTURE = HERE / 'fixture.json.gz'

# Same one-case driver as test_replay.py: the unchanged replay.py runs a
# single real buy_v3 case against the retained fixture.
DRIVER = r'''
import importlib.util, runpy, sys, types
root, tool = sys.argv[1], sys.argv[2]
suite = types.ModuleType('pump_v3_configured_fee_differential')
def cases():
    spec = importlib.util.spec_from_file_location(
        'real_suite', root + '/scripts/pump_v3_configured_fee_differential.py')
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    suite.run = real.run
    return [next(c for c in real.cases() if c['operation'] == 'buy_v3')]
suite.cases = cases
sys.modules[suite.__name__] = suite
sys.argv = [tool] + sys.argv[3:]
runpy.run_path(tool, run_name='__main__')
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReplayOutputPreservationTests(unittest.TestCase):
    def run_replay(self, control, candidate, output):
        return subprocess.run(
            [sys.executable, '-B', '-c', DRIVER, str(ROOT), str(HERE / 'replay.py'),
             '--control', str(control), '--candidate', str(candidate),
             '--output', str(output)],
            capture_output=True, text=True, timeout=300)

    def exercise(self, collision):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            control = root / 'control.so'
            candidate = root / 'candidate.so'
            control.write_bytes(ORIGINAL.read_bytes())
            candidate.write_bytes(ORIGINAL.read_bytes())
            before = {path: digest(path) for path in (control, candidate, FIXTURE)}
            targets = {'candidate': candidate, 'control': control, 'fixture': FIXTURE}
            output = targets[collision] if collision else root / 'runtime.json.gz'
            result = self.run_replay(control, candidate, output)
            for path, sha in before.items():
                self.assertEqual(digest(path), sha, f'{path.name} input was overwritten')
            if collision:
                self.assertEqual(result.returncode, 2, result.stderr[-600:])
                self.assertIn('output overlaps an input', result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr[-600:])
                report = json.loads(gzip.decompress(output.read_bytes()))
                self.assertEqual(report['case_count'], 1)
                self.assertEqual(report['images']['candidate'], before[candidate])

    def test_output_cannot_replace_the_candidate(self):
        self.exercise('candidate')

    def test_output_cannot_replace_the_control(self):
        self.exercise('control')

    def test_output_cannot_replace_the_fixture(self):
        self.exercise('fixture')

    def test_separate_output_still_replays(self):
        self.exercise(None)


if __name__ == '__main__':
    unittest.main()
