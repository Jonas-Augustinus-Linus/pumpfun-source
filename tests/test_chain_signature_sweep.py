"""No tracked chain verifier may accept a receipt with no signatures.

The 20261029 multi-hop chain family gates each retained receipt on
``if not all(tx.verify_with_results())``. solders returns no results for a
transaction that carries no signatures, and ``all([])`` is true, so the gate
accepts a receipt whose signature vector was stripped. This module pins the
whole family to the non-empty form and exercises one member end to end.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from test_chain_verifier_signature_admission import strip_signatures

BARE_GATE = 'not all(tx.verify_with_results())'
PACKET = 'amm-multi-hop-fee-table-split-boost-tf-chains-20261029'
SUPPORT = (
    'evidence/original/pump_amm/deployed.so',
    'research/amm-multi-hop-images/control.so.gz',
    'research/amm-multi-hop-images/candidate.so.gz',
)


def tracked_verifiers():
    """Every tracked research verifier, listed by git so ignored packets never count."""
    listed = subprocess.run(['git', 'ls-files', 'research/*/verify.py'], cwd=ROOT,
                            capture_output=True, text=True, timeout=120)
    if listed.returncode == 0:
        return [ROOT / line for line in listed.stdout.splitlines() if line.strip()]
    return sorted((ROOT / 'research').glob('*/verify.py'))


class SignatureSweepTests(unittest.TestCase):
    def test_no_tracked_verifier_uses_a_bare_all_signature_gate(self):
        offenders = [str(path.relative_to(ROOT)) for path in tracked_verifiers()
                     if BARE_GATE in path.read_text()]
        self.assertEqual(offenders, [], 'use the non-empty result list before all()')

    def test_a_stripped_receipt_is_rejected_by_a_second_packet(self):
        with tempfile.TemporaryDirectory(prefix='chain-sweep-') as directory:
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
            self.assertEqual(strip_signatures(packet), 258)
            stripped = subprocess.run([sys.executable, '-I', '-B', str(packet / 'verify.py')],
                                      cwd=root, text=True, capture_output=True, timeout=300)
            combined = stripped.stdout + stripped.stderr
            self.assertNotEqual(stripped.returncode, 0, combined)
            self.assertIn('signature verification failed', combined)
            self.assertNotIn('PASS:', stripped.stdout)


if __name__ == '__main__':
    unittest.main()
