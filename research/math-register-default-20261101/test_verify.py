"""The maintained full CLI must include the already accepted math correction."""
from pathlib import Path
import unittest

import probe


class DefaultMathReportTests(unittest.TestCase):
    def test_actual_default_cli_matches_accepted_archive_and_opcode_oracle(self):
        # No historical Git object is required by CI: the existing source-bound
        # successor supplies both reviewed predicates and checks its own hashes.
        result = probe.reproduce(Path(__file__).resolve().parents[2])
        self.assertEqual(sum(p['logical_instruction_oracle']['register']
                             for p in result['programs'].values()), 496)
        self.assertTrue(result['captures_and_archived_packages_unchanged'])


if __name__ == '__main__':
    unittest.main()
