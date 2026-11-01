"""No tracked chain verifier may count events from the receipt's own summary.

The 20261029 chain family compared ``len(rec["events"])`` with the report's
expected count. ``rec["events"]`` is written by the same producer that writes
the report, so the check compares the producer's claim with itself: a receipt
whose logs carry a decoded event that the summary omits still passes, and the
three-image comparison in ``surface()`` agrees on the same summary. Counting
the ``Program data:`` lines in the receipt's own logs makes the check depend on
evidence the receipt records rather than on a number that repeats the claim.
"""
import base64
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

SUMMARY_GATE = 'if len(rec["events"]) != exp["events"]:'
PACKET = 'amm-multi-hop-fee-table-split-liquidity-chains-20261029'
SUPPORT = (
    'evidence/original/pump_amm/deployed.so',
    'research/amm-multi-hop-images/control.so.gz',
    'research/amm-multi-hop-images/candidate.so.gz',
)


def inject_event(packet):
    """Add one decoded event to a step whose expectation says it has none.

    Every image of the step is changed, so the three surfaces still agree and
    only the event count can notice the extra log line.
    """
    report_path = packet / 'runtime/report.json.gz'
    report = json.loads(gzip.decompress(report_path.read_bytes()))
    case, index = None, None
    for entry in report['cases']:
        steps = entry.get('steps', [])
        for sequence in (steps.values() if isinstance(steps, dict) else [steps]):
            for position, expected in enumerate(sequence):
                if isinstance(expected, dict) and expected.get('events') == 0:
                    case, index = entry['label'], position
                    break
            if case:
                break
        if case:
            break
    receipts = {}
    for part in report['parts']:
        for line in gzip.decompress((packet / part['file']).read_bytes()).splitlines():
            record = json.loads(line)
            receipts.setdefault((record['case'], record['image']), []).append(record)
    step = receipts[(case, 'original')][index]['step']
    changed = 0
    for part in report['parts']:
        path = packet / part['file']
        records = []
        for line in gzip.decompress(path.read_bytes()).splitlines():
            record = json.loads(line)
            if record.get('case') == case and record.get('step') == step:
                record['logs'] = list(record.get('logs') or []) + [
                    'Program data: ' + base64.b64encode(b'\x01' * 16).decode()]
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


class EventCountSweepTests(unittest.TestCase):
    def test_no_tracked_verifier_counts_the_producer_summary(self):
        offenders = [str(path.relative_to(ROOT)) for path in tracked_verifiers()
                     if SUMMARY_GATE in path.read_text()]
        self.assertEqual(offenders, [], 'count the decoded events in the receipt logs')

    def test_an_undeclared_event_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='event-sweep-') as directory:
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
            self.assertGreater(inject_event(packet), 0)
            tampered = subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py')],
                                      cwd=root, text=True, capture_output=True, timeout=300)
            combined = tampered.stdout + tampered.stderr
            self.assertNotEqual(tampered.returncode, 0, combined)
            self.assertIn('events 1 != 0', combined)
            self.assertNotIn('PASS:', tampered.stdout)


if __name__ == '__main__':
    unittest.main()
