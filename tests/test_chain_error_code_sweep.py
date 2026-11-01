"""No tracked chain verifier may accept a different program code as a match.

The 20261029 chain family compares an expected program code with the recorded
transaction error using ``exp["error"] not in rec["error"]``. The expectation
is the bare code ("6004") and the record is the full error
("...Custom(6004))"), so the substring test also accepts ``Custom(16004)`` —
and accepts ``Custom(6014)`` for the expectation "1". This module pins the
family to a value comparison and exercises one member end to end.
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
sys.path.insert(0, str(ROOT / 'tests'))
from test_chain_signature_sweep import tracked_verifiers  # noqa: E402

SUBSTRING_GATE = 'exp["error"] not in rec["error"]'
CODE_GATE = 'error_matches(rec["error"], exp["error"])'
PACKET = 'amm-multi-hop-fee-table-split-liquidity-chains-20261029'
SUPPORT = (
    'evidence/original/pump_amm/deployed.so',
    'research/amm-multi-hop-images/control.so.gz',
    'research/amm-multi-hop-images/candidate.so.gz',
)


def recode_errors(packet):
    """Turn every recorded 6004 into 16004, then re-pin what pins the receipts.

    Every image of a step is rewritten, so the three surfaces still agree and
    only the program-code comparison can notice the substitution.
    """
    report_path = packet / 'runtime/report.json.gz'
    report = json.loads(gzip.decompress(report_path.read_bytes()))
    changed = 0
    for part in report['parts']:
        path = packet / part['file']
        records = []
        for line in gzip.decompress(path.read_bytes()).splitlines():
            record = json.loads(line)
            error = record.get('error') or ''
            if 'Custom(6004)' in error:
                record['error'] = error.replace('Custom(6004)', 'Custom(16004)')
                changed += 1
            records.append(json.dumps(record, separators=(',', ':')).encode() + b'\n')
        data = gzip.compress(b''.join(records), mtime=0)
        path.write_bytes(data)
        part['sha256'], part['bytes'] = hashlib.sha256(data).hexdigest(), len(data)
    new_report = gzip.compress(json.dumps(report, separators=(',', ':')).encode(), mtime=0)
    report_path.write_bytes(new_report)
    digests = {part['file']: part['sha256'] for part in report['parts']}
    digests['runtime/report.json.gz'] = hashlib.sha256(new_report).hexdigest()
    manifest_path = packet / 'MANIFEST.json'
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest['files']:
        if entry['path'] in digests:
            entry['sha256'] = digests[entry['path']]
    manifest_path.write_text(json.dumps(manifest, indent=1) + '\n')
    return changed


class ErrorCodeSweepTests(unittest.TestCase):
    def test_no_tracked_verifier_matches_a_program_code_as_a_substring(self):
        offenders = [str(path.relative_to(ROOT)) for path in tracked_verifiers()
                     if SUBSTRING_GATE in path.read_text()]
        self.assertEqual(offenders, [], 'compare the recorded program code by value')

    def test_a_substituted_program_code_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='code-sweep-') as directory:
            root = Path(directory)
            shutil.copytree(ROOT / 'research' / PACKET, root / 'research' / PACKET)
            for relative in SUPPORT:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            packet = root / 'research' / PACKET
            pristine = subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py')],
                                      cwd=root, text=True, capture_output=True, timeout=300)
            self.assertEqual(pristine.returncode, 0, pristine.stdout + pristine.stderr)
            self.assertGreater(recode_errors(packet), 0)
            tampered = subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py')],
                                      cwd=root, text=True, capture_output=True, timeout=300)
            combined = tampered.stdout + tampered.stderr
            self.assertNotEqual(tampered.returncode, 0, combined)
            self.assertIn('expected error 6004, got', combined)
            self.assertNotIn('PASS:', tampered.stdout)


if __name__ == '__main__':
    unittest.main()
