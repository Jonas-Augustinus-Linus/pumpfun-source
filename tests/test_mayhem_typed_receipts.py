"""Actual offline verifier CLIs must retain JSON types in saved comparisons."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / 'research/runtime-mayhem-typed-receipts-20261101/probe.py'
spec = importlib.util.spec_from_file_location('mayhem_typed_probe', PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class MayhemTypedReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='mayhem-typed-receipts-')
        cls.addClassCleanup(temporary.cleanup)
        cls.rows = probe.run(ROOT, Path(temporary.name) / 'proof')['rows']

    def test_unchanged_retained_cases_keep_actual_signature_and_state_checks(self):
        rows = [row for row in self.rows if row['variant'] == 'unchanged']
        self.assertEqual(len(rows), 12)
        for row in rows:
            with self.subTest(mode=row['mode'], encoding=row['encoding']):
                self.assertEqual(row['returncode'], 0)
                self.assertTrue(row['published'])
                count = 2 if row['mode'] in ('buy', 'sell') else 1
                self.assertEqual(row['result']['case_count'], count)
                self.assertEqual(row['result']['verified_signed_transactions'], 2 * count)
                self.assertEqual(row['result']['rejection_cases'], 1)
                self.assertEqual(row['result']['complete_failed_transaction_rollback_checks'], 2)

    def test_type_changes_in_parity_payer_and_rollback_snapshots_are_rejected(self):
        rows = [row for row in self.rows if row['variant'] in (*probe.MALFORMED, probe.METADATA_VARIANT)]
        self.assertEqual(len(rows), 76)
        for row in rows:
            with self.subTest(mode=row['mode'], encoding=row['encoding'], variant=row['variant']):
                self.assertNotEqual(row['returncode'], 0)
                self.assertFalse(row['published'])

    def test_existing_invalid_inputs_and_optimized_modes_still_reject(self):
        rows = [row for row in self.rows if row['variant'] in probe.CONTROLS]
        self.assertEqual(len(rows), 84)
        for row in rows:
            with self.subTest(mode=row['mode'], encoding=row['encoding'], variant=row['variant']):
                self.assertNotEqual(row['returncode'], 0)
                self.assertFalse(row['published'])

    def test_every_cli_preserves_inputs_and_leaves_no_staging_files(self):
        self.assertEqual(len(self.rows), 172)
        for row in self.rows:
            with self.subTest(mode=row['mode'], encoding=row['encoding'], variant=row['variant']):
                self.assertTrue(row['input_preserved'])
                self.assertTrue(row['harness_sources_rechecked'])
                self.assertEqual(row['staging_leftovers'], [])


if __name__ == '__main__':
    unittest.main()
