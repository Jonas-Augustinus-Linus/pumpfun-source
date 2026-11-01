"""No tracked script may treat a transaction with no signatures as signed.

``solders`` returns an empty result list for a transaction whose signature is
absent, and ``all([])`` is true, so ``all(tx.verify_with_results())`` accepted a
stripped transaction. The guard is the signature vector itself: ``tx.signatures
and all(...)``, or, where the results are held in a variable, ``results and
all(results)``.
"""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CALL = re.compile(r'\ball\(')
ASSIGNED = re.compile(r'([A-Za-z_]\w*)\s*=\s*[^;\n]*?\.verify_with_results\(\)')
DIRECT_GUARD = r'\.signatures and $'
HELD_GUARD = r'(?:\.signatures and |\b%s and )$'
# These two are under review with a stronger per-row gate (required signature count
# and the exact result vector) in another change; excluding them here keeps the two
# changes off the same lines. The sweep covers them once that change lands.
PER_FILE = {
    'scripts/pump_amm_boost_differential.py',
    'scripts/pump_amm_migration_create_differential.py',
}


def tracked_scripts():
    listed = subprocess.run(['git', 'ls-files', 'scripts/*.py'], cwd=ROOT,
                            text=True, capture_output=True, check=True).stdout.split()
    return [ROOT / path for path in listed]


def argument(text, open_index):
    """The text between ``text[open_index] == '('`` and its matching ``)``."""
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == '(':
            depth += 1
        elif text[index] == ')':
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index]
    return None


def unguarded_calls(text):
    """Every ``all(...)`` over signature results whose vector is not tested first."""
    variables = set(ASSIGNED.findall(text))
    for match in CALL.finditer(text):
        arg = (argument(text, match.end() - 1) or '').strip()
        if 'verify_with_results()' not in arg and arg not in variables:
            continue
        before = text[max(0, match.start() - 64):match.start()]
        guard = HELD_GUARD % re.escape(arg) if arg in variables else DIRECT_GUARD
        if not re.search(guard, before):
            yield text.count('\n', 0, match.start()) + 1, arg


class SignatureGuardTests(unittest.TestCase):
    def test_every_signature_check_rejects_an_unsigned_transaction(self):
        offenders = []
        for path in tracked_scripts():
            relative = str(path.relative_to(ROOT))
            if relative in PER_FILE:
                continue
            offenders.extend(f'{relative}:{line}' for line, _ in unguarded_calls(path.read_text()))
        self.assertEqual(offenders, [], 'test the signature vector before all() of its results')

    def test_the_guard_is_what_makes_an_empty_vector_false(self):
        class Stripped:
            signatures = []
            def verify_with_results(self): return []
        stripped = Stripped()
        self.assertTrue(all(stripped.verify_with_results()))
        self.assertFalse(stripped.signatures and all(stripped.verify_with_results()))
        held = stripped.verify_with_results()
        self.assertTrue(all(held))
        self.assertFalse(held and all(held))


if __name__ == '__main__':
    unittest.main()
