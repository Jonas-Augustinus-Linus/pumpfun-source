"""A packet verifier must check its manifest before the module-scope producer import runs.

10 packets import ``producer`` at module scope, which executes it before ``main``
is called. Their ``MANIFEST.json`` pins ``producer.py``, the runtime receipts, the
report and ``verify.py`` itself, and none of the verifiers read it, so a drifted
producer supplied both the replay and the summary the verdict is built from.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = 'pump-fees-tier-lookup-cost-20261030'
IMPORT = '^import producer'


def tracked_verifiers():
    listed = subprocess.run(['git', 'ls-files', 'research/*/verify.py'], cwd=ROOT,
                            text=True, capture_output=True, check=True).stdout.split()
    return [ROOT / path for path in listed]


def run(packet):
    return subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py'),
                           '--images', '{"original": "none", "candidate": "none"}'],
                          text=True, capture_output=True, timeout=300)


class ModuleScopeProducerTests(unittest.TestCase):
    def test_every_module_scope_producer_import_is_guarded(self):
        import re
        offenders = []
        for path in tracked_verifiers():
            text = path.read_text()
            match = re.search(IMPORT, text, re.M)
            if not match:
                continue
            gate = text.find('verify_manifest()')
            if gate == -1 or gate > match.start():
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [], 'check MANIFEST.json before importing producer')

    def test_a_drifted_producer_stops_the_import(self):
        with tempfile.TemporaryDirectory(prefix='module-gate-') as directory:
            packet = Path(directory) / PACKET
            shutil.copytree(ROOT / 'research' / PACKET, packet)
            pristine = run(packet)
            self.assertNotIn('packet member differs', pristine.stdout + pristine.stderr)
            with (packet / 'producer.py').open('a') as handle:
                handle.write('\n# drift\n')
            tampered = run(packet)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn('packet member differs from MANIFEST.json: producer.py',
                          tampered.stdout + tampered.stderr)
            self.assertNotIn('Traceback', tampered.stderr)


if __name__ == '__main__':
    unittest.main()
