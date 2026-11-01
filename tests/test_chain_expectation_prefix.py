"""A step may not silently drop a GlobalConfig expectation its sequence declared.

The 20261029 boost family compares the GlobalConfig fields only when the step's
expectation carries a ``cfg`` key (``if "cfg" in exp:``). Every step after the
first that declares it declares it too, so a report that removes the key from
one step of a sequence skips that comparison while the PASS line still claims
"GlobalConfig fields" were checked.
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

OPTIONAL_CHECK = 'if "cfg" in exp:'
PREFIX_GUARD = 'require_prefix(expect, "cfg")'
PACKET = 'amm-multi-hop-split-boost-tf-global-config-validation-chains-20261029'
SUPPORT = (
    'evidence/original/pump_amm/deployed.so',
    'research/amm-multi-hop-images/control.so.gz',
    'research/amm-multi-hop-images/candidate.so.gz',
)


def drop_global_config(packet):
    """Delete one mid-sequence cfg expectation and re-pin the report digest."""
    report_path = packet / 'runtime/report.json.gz'
    report = json.loads(gzip.decompress(report_path.read_bytes()))
    sequences = []
    for entry in report['cases']:
        steps = entry['steps']
        sequences.extend(steps.values() if isinstance(steps, dict) else [steps])
    sequence = next(item for item in sequences
                    if any('cfg' in step for step in item[1:]))
    index = next(i for i, step in enumerate(sequence) if i and 'cfg' in step)
    del sequence[index]['cfg']
    new_report = gzip.compress(json.dumps(report, separators=(',', ':')).encode(), mtime=0)
    report_path.write_bytes(new_report)
    manifest_path = packet / 'MANIFEST.json'
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest['files']:
        if entry['path'] == 'runtime/report.json.gz':
            entry['sha256'] = hashlib.sha256(new_report).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=1) + '\n')
    return index


class ExpectationPrefixTests(unittest.TestCase):
    def test_every_optional_global_config_check_is_guarded(self):
        offenders = [str(path.relative_to(ROOT)) for path in tracked_verifiers()
                     if OPTIONAL_CHECK in path.read_text() and PREFIX_GUARD not in path.read_text()]
        self.assertEqual(offenders, [], 'guard the cfg check against a dropped key')

    def test_a_dropped_global_config_expectation_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='prefix-sweep-') as directory:
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
            index = drop_global_config(packet)
            tampered = subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py')],
                                      cwd=root, text=True, capture_output=True, timeout=300)
            combined = tampered.stdout + tampered.stderr
            self.assertNotEqual(tampered.returncode, 0, combined)
            self.assertIn(f'expectation {index} drops cfg', combined)
            self.assertNotIn('PASS:', tampered.stdout)


if __name__ == '__main__':
    unittest.main()
