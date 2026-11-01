"""A saved migration transaction must carry the signatures its header requires.

Both migration differentials replay a saved, signed transaction from
``curve-migrate-v2-signed-surfpool.json``. LiteSVM executes a transaction
without checking signatures, and solders returns no results for a transaction
that carries none, so ``all(tx.verify_with_results())`` is true for a fixture
whose signature vector was stripped: the receipt then claims the saved
migration was signed when nothing was verified.
"""
import base64
import sys
import unittest
from pathlib import Path
from unittest import mock

from solders.transaction import Transaction

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import pump_amm_boost_differential as boost  # noqa: E402
import pump_amm_migration_create_differential as create  # noqa: E402

SCRIPTS = ('pump_amm_migration_create_differential.py', 'pump_amm_boost_differential.py')
BARE_GATE = 'assert all(tx.verify_with_results())'


def strip_signatures(encoded):
    """Return the same transaction with an empty signature vector."""
    tx = Transaction.from_bytes(base64.b64decode(encoded))
    return base64.b64encode(bytes([0]) + bytes(tx.message)).decode()


class SavedMigrationGateTests(unittest.TestCase):
    def test_no_saved_migration_is_gated_by_a_bare_all(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                text = (ROOT / 'scripts' / name).read_text()
                self.assertNotIn(BARE_GATE, text)
                self.assertIn('num_required_signatures', text)

    def test_a_stripped_saved_migration_is_rejected(self):
        for module in (create, boost):
            row = dict(module.p['migration'])
            row['transaction_base64'] = strip_signatures(row['transaction_base64'])
            with self.subTest(script=module.__name__), mock.patch.dict(module.p, {'migration': row}):
                with self.assertRaisesRegex(AssertionError, 'saved migration is not signed'):
                    module.run_migration(label='migration')


if __name__ == '__main__':
    unittest.main()
