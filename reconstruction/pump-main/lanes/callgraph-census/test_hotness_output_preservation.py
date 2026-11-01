"""The hotness report paths must not replace an input the tool consumes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

CENSUS = {'targets': [{'original': '0x1e7c0', 'candidate': 'create_v2::execute',
                       'error_format_forms': {'orig': [{'line': 'create_v2.rs:10',
                                                         'form': 'fmt'}]}}]}
REMARK = ("note: src/create_v2.rs:10:5 inline (success): "
          "'<T as alloc::string::ToString>::to_string' inlined into "
          "'create_v2::execute' with (cost=130, threshold=325)\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class HotnessOutputPreservationTests(unittest.TestCase):
    def run_tool(self, scratch, *extra):
        return subprocess.run(
            [sys.executable, '-B', str(HERE / 'hotness.py'),
             '--remarks', str(scratch / 'remarks.log'),
             '--census', str(scratch / 'census.json'), *extra],
            capture_output=True, text=True, timeout=60)

    def exercise(self, collision):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            census = root / 'census.json'
            census.write_text(json.dumps(CENSUS, indent=1) + '\n')
            remarks = root / 'remarks.log'
            remarks.write_text(REMARK)
            watched = {path: digest(path) for path in (census, remarks)}
            if collision:
                flag, target = collision
                result = self.run_tool(root, flag, str(target(root)))
            else:
                result = self.run_tool(root, '--json', str(root / 'report.json'),
                                       '--md', str(root / 'report.md'))
            for path, sha in watched.items():
                self.assertEqual(digest(path), sha, f'{path.name} input was overwritten')
            if collision:
                self.assertEqual(result.returncode, 2, result.stderr[-600:])
                self.assertIn('report destination aliases an input', result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr[-600:])
                published = json.loads((root / 'report.json').read_text())
                self.assertEqual(len(published['0x1e7c0']['ours']), 1)
                self.assertIn('# Per-site hot/cold map',
                              (root / 'report.md').read_text())
                self.assertEqual(json.loads(result.stdout)['0x1e7c0'], 1)

    def test_json_cannot_replace_the_census(self):
        self.exercise(('--json', lambda root: root / 'census.json'))

    def test_json_cannot_replace_the_remarks(self):
        self.exercise(('--json', lambda root: root / 'remarks.log'))

    def test_md_cannot_replace_the_census(self):
        self.exercise(('--md', lambda root: root / 'census.json'))

    def test_md_cannot_replace_the_remarks(self):
        self.exercise(('--md', lambda root: root / 'remarks.log'))

    def test_separate_reports_still_publish(self):
        self.exercise(None)


if __name__ == '__main__':
    unittest.main()
