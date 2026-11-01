"""A packet verifier may not execute its producer before checking the packet's own digests.

21 packets ship a ``MANIFEST.json`` that pins ``producer.py``, the runtime plan,
the receipt files, the report and ``verify.py`` itself, and none of their
verifiers read it. ``producer.py`` supplies both the replay and the summary the
verdict is built from, so a producer or runtime file that no longer matches the
packet's record was executed and decided the result anyway.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = 'pump-trade-cu-scaling-20261030'
LOADER = 'p = load_producer()'
GATE = 'verify_manifest()'


def tracked_verifiers():
    listed = subprocess.run(['git', 'ls-files', 'research/*/verify.py'], cwd=ROOT,
                            text=True, capture_output=True, check=True).stdout.split()
    return [ROOT / path for path in listed]


def run(packet):
    return subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py'),
                           '--images', '{"original": "none", "candidate": "none"}'],
                          text=True, capture_output=True, timeout=300)


class ProducerManifestTests(unittest.TestCase):
    def test_every_producer_execution_is_preceded_by_the_manifest_gate(self):
        offenders = []
        for path in tracked_verifiers():
            text = path.read_text()
            if LOADER not in text:
                continue
            gate = text.find(GATE)
            if gate == -1 or gate > text.find(LOADER):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [], 'check MANIFEST.json before executing producer.py')

    def test_a_drifted_producer_is_rejected_before_it_runs(self):
        with tempfile.TemporaryDirectory(prefix='manifest-gate-') as directory:
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

    def test_a_drifted_runtime_file_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='manifest-runtime-') as directory:
            packet = Path(directory) / PACKET
            shutil.copytree(ROOT / 'research' / PACKET, packet)
            plan = packet / 'runtime/plan.json.gz'
            plan.write_bytes(plan.read_bytes()[:-1])
            tampered = run(packet)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn('packet member differs from MANIFEST.json: runtime/plan.json.gz',
                          tampered.stdout + tampered.stderr)


if __name__ == '__main__':
    unittest.main()
