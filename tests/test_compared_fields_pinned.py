"""A verifier may not take its compared field list from the report it is checking.

Three 20261029/30 sequence verifiers read ``compared = report['compared_fields']``
and then decide every step with ``all(o[f] == k[f] for f in compared)``. The list
is written by the producer, so an emptied list makes that expression compare
nothing and the PASS line still claims the fields were compared. The sibling
packet already pins the list against ``producer.COMPARED``; these three did not.
"""
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = 'pump-fees-authority-transition-sequences-20261029'
READ = "report['compared_fields']"
PIN = 'COMPARED = ['


def tracked_verifiers():
    listed = subprocess.run(['git', 'ls-files', 'research/*/verify.py'], cwd=ROOT,
                            text=True, capture_output=True, check=True).stdout.split()
    return [ROOT / path for path in listed]


def run(packet):
    return subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py'),
                           '--images', '{"original": "a", "candidate": "b"}'],
                          text=True, capture_output=True, timeout=300)


def empty_compared_fields(packet):
    report_path = packet / 'runtime/report.json.gz'
    report = json.loads(gzip.decompress(report_path.read_bytes()))
    report['compared_fields'] = []
    data = gzip.compress(json.dumps(report, separators=(',', ':')).encode(), mtime=0)
    report_path.write_bytes(data)
    manifest_path = packet / 'MANIFEST.json'
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest['files']:
        if entry['path'] == 'runtime/report.json.gz':
            entry['sha256'] = hashlib.sha256(data).hexdigest()
            entry['bytes'] = len(data)
    manifest_path.write_text(json.dumps(manifest, indent=1) + '\n')


class ComparedFieldsTests(unittest.TestCase):
    def test_every_report_field_list_is_pinned(self):
        offenders = []
        for path in tracked_verifiers():
            text = path.read_text()
            if READ not in text:
                continue
            pinned = PIN in text or 'producer.COMPARED' in text
            if not pinned or "report['compared_fields'] != " not in text:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [], 'pin the compared fields instead of reading them')

    def test_an_emptied_field_list_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='compared-fields-') as directory:
            packet = Path(directory) / PACKET
            shutil.copytree(ROOT / 'research' / PACKET, packet)
            pristine = run(packet)
            self.assertNotIn('compared fields', pristine.stdout)
            empty_compared_fields(packet)
            tampered = run(packet)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn('FAIL: compared fields [] !=', tampered.stdout)


if __name__ == '__main__':
    unittest.main()
