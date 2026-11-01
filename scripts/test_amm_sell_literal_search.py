"""Record accepted notes, then search their unchanged bytes through the actual CLI."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / 'research/amm-literal-search-20261101/probe.py'
spec = importlib.util.spec_from_file_location('amm_literal_search_probe', PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@unittest.skipIf(os.name == 'nt', 'the existing note recorder requires POSIX fcntl')
class LiteralSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory(prefix='amm-literal-search-test-') as folder:
            root = Path(folder) / 'notes'
            tool = ROOT / 'scripts/amm_sell/attempts.py'
            probe.record_notes(tool, root)
            cls.results = probe.search_notes(tool, root)

    def check_rows(self, rows):
        for row in rows:
            with self.subTest(query=row['name']):
                self.assertEqual(row['returncode'], 0, row['stderr'])
                self.assertEqual(row['stderr'], '')
                self.assertEqual(row['actual_lanes'], row['expected_lanes'])

    def test_literal_quotes_unicode_and_backslashes(self):
        self.check_rows(self.results[:6])

    def test_existing_phrases_encoded_queries_and_order(self):
        self.check_rows(self.results[6:])


if __name__ == '__main__':
    unittest.main()
