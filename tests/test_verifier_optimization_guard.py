"""Evidence verifiers must refuse to run under -O, where assert disappears.

`research/pump-plain-receipts/verify.py` performs every acceptance check with a
bare `assert`, so `python -O verify.py` prints its "verified" line whether or
not any evidence check ran. The repository's other verifiers guard with
`if not __debug__: raise SystemExit("Run without -O")`; this module holds that
line for the tracked verifiers and exercises the packet end to end.
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = 'research/pump-plain-receipts'
ASSERT = re.compile(r'^\s*assert\s', re.MULTILINE)
PASS_LINE = 'Retained eleven-producer before/after wire reports verified'


def tracked_verifiers():
    """Every tracked research verifier, listed by git so ignored packets never count."""
    listed = subprocess.run(['git', 'ls-files', 'research/*/verify.py'], cwd=ROOT,
                            capture_output=True, text=True, timeout=120)
    if listed.returncode == 0:
        return [ROOT / line for line in listed.stdout.splitlines() if line.strip()]
    return sorted((ROOT / 'research').glob('*/verify.py'))


class OptimizationGuardTests(unittest.TestCase):
    def test_every_asserting_verifier_refuses_optimized_mode(self):
        offenders = []
        for path in tracked_verifiers():
            text = path.read_text()
            if ASSERT.search(text) and '__debug__' not in text:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [], 'add `if not __debug__: raise SystemExit(...)`')

    def test_optimized_mode_does_not_report_tampered_receipts_as_verified(self):
        with tempfile.TemporaryDirectory(prefix='opt-guard-') as directory:
            root = Path(directory)
            shutil.copytree(ROOT / PACKET, root / 'pump-plain-receipts')
            packet = root / 'pump-plain-receipts'
            pristine = subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py')],
                                      text=True, capture_output=True, timeout=300)
            self.assertEqual(pristine.returncode, 0, pristine.stdout + pristine.stderr)
            self.assertIn(PASS_LINE, pristine.stdout)
            hashes = json.loads((packet / 'receipt-files.json').read_text())
            tampered = packet / sorted(hashes)[0]
            tampered.write_bytes(tampered.read_bytes() + b'\0')
            optimized = subprocess.run([sys.executable, '-O', '-I', '-B', str(packet / 'verify.py')],
                                       text=True, capture_output=True, timeout=300)
            combined = optimized.stdout + optimized.stderr
            self.assertNotEqual(optimized.returncode, 0, combined)
            self.assertIn('Run without -O', combined)
            self.assertNotIn(PASS_LINE, combined)


if __name__ == '__main__':
    unittest.main()
