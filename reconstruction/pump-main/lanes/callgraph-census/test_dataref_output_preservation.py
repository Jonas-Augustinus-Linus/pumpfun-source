"""The dataref audit report path must not replace an input it audits."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = ROOT / 'reconstruction/base'
ORIGINAL = BASE / 'original.so'
INVENTORY = BASE / 'functions.tsv'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DatarefOutputPreservationTests(unittest.TestCase):
    def run_audit(self, candidate, report):
        return subprocess.run(
            [sys.executable, '-B', str(HERE / 'dataref_audit.py'),
             '--cand', str(candidate), '--json', str(report)],
            capture_output=True, text=True, timeout=300)

    def exercise(self, collision):
        with tempfile.TemporaryDirectory() as scratch:
            candidate = Path(scratch) / 'candidate.so'
            candidate.write_bytes(ORIGINAL.read_bytes())
            targets = {'candidate': candidate, 'original': ORIGINAL,
                       'inventory': INVENTORY}
            watched = {path: digest(path) for path in targets.values()}
            report = targets[collision] if collision else Path(scratch) / 'dataref.json'
            result = self.run_audit(candidate, report)
            for path, sha in watched.items():
                self.assertEqual(digest(path), sha, f'{path.name} input was overwritten')
            if collision:
                self.assertEqual(result.returncode, 2, result.stderr[-600:])
                self.assertIn('report destination aliases an input', result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr[-600:])
                published = json.loads(report.read_text())
                self.assertEqual(published['candidate'], str(candidate))

    def test_json_cannot_replace_the_candidate(self):
        self.exercise('candidate')

    def test_json_cannot_replace_the_shared_original(self):
        self.exercise('original')

    def test_json_cannot_replace_the_window_inventory(self):
        self.exercise('inventory')

    def test_separate_json_still_audits(self):
        self.exercise(None)


if __name__ == '__main__':
    unittest.main()
