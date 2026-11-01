"""A verifier that replays a packet's plan must pin the length of that plan.

The producer template in ``research/*/verify.py`` reads its cases from the
packet's own ``runtime/plan.json.gz`` and decides how many receipts it expects
from that same list. An emptied plan therefore passes every check it still
runs: zero cases, zero receipts expected, and the summary comparison is made
against a report that the same rewrite emptied. The packet's published case
count has to be written down in the verifier for the loop to be load bearing.
"""
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = re.compile(r'for loader in p\.LOADERS')
PIN = re.compile(r'^CASES = (\d+)', re.M)
GUARD = 'if len(cases) != CASES:'
PACKET = 'pump-creator-fee-collect-boundaries-20261030'


def plan_verifiers():
    for path in sorted(ROOT.glob('research/*/verify.py')):
        text = path.read_text()
        if TEMPLATE.search(text):
            yield path, text


class PlanCaseCountPinned(unittest.TestCase):
    def test_every_plan_verifier_pins_the_plan_length(self):
        seen = 0
        for path, text in plan_verifiers():
            seen += 1
            with self.subTest(packet=path.parent.name):
                match = PIN.search(text)
                self.assertIsNotNone(match, 'a plan-driven verifier pins no case count')
                self.assertIn(GUARD, text, 'the pinned count is never compared with the plan')
                plan = json.loads(gzip.decompress((path.parent / 'runtime/plan.json.gz').read_bytes()))
                self.assertEqual(int(match.group(1)), len(plan),
                                 'the pinned count differs from the plan this packet ships')
        self.assertGreater(seen, 0, 'no plan-driven verifier was found to check')

    def test_an_emptied_plan_is_refused_before_any_image_is_read(self):
        with tempfile.TemporaryDirectory(prefix='plan-count-') as temporary:
            packet = Path(temporary) / 'packet'
            shutil.copytree(ROOT / 'research' / PACKET, packet)
            changed = gzip.compress(b'[]', mtime=0)
            (packet / 'runtime/plan.json.gz').write_bytes(changed)
            # Reach the independent plan-count gate after the manifest check.
            manifest_path = packet / 'MANIFEST.json'
            manifest = json.loads(manifest_path.read_text())
            for entry in manifest['files']:
                if entry['path'] == 'runtime/plan.json.gz':
                    entry.update(sha256=hashlib.sha256(changed).hexdigest(), bytes=len(changed))
            manifest_path.write_text(json.dumps(manifest, indent=1) + '\n')
            result = subprocess.run(
                [sys.executable, '-I', '-B', str(packet / 'verify.py'), '--images', '{}'],
                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('FAIL: plan holds 0 cases, not 66', result.stdout)


if __name__ == '__main__':
    unittest.main()
