"""Exercise the maintained signature CLI on the three unchanged captured images."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'signature_register_probe', ROOT / 'research/signature-register-comparisons-20261101/probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class SignatureRegisterComparisonTests(unittest.TestCase):
    def test_default_cli_matches_raw_pairs_and_dependent_reports(self):
        # collect independently decodes each retained window and checks every
        # pattern, signature, summary and generated packet verifier.
        report = probe.collect(ROOT)
        self.assertEqual({name: row['register_pairs'] for name, row in report['programs'].items()},
                         {'pump': 23, 'pump_amm': 16, 'mayhem': 120})
        for name, row in report['programs'].items():
            with self.subTest(program=name):
                self.assertGreater(row['immediate_pairs'], 0)
                self.assertTrue(all(site['reads_loaded_register'] for site in row['register_witnesses']))
        self.assertTrue(report['all_input_bytes_preserved'])


if __name__ == '__main__':
    unittest.main()
