"""Check the research wrapper preserves experiments and reviewed-helper integrity."""
import hashlib
from pathlib import Path
import unittest
from build_reconstruction_candidate import ROOT, command


class ResearchSelectionTests(unittest.TestCase):
    def test_default_does_not_select_header_incompatible_older_family(self):
        for name in ('pump', 'pump_amm', 'pump_fees'):
            argv=command(['--program',name,'--manifest','sample/Cargo.toml','--output','work/build'])
            self.assertEqual(argv[argv.index('--tools-version')+1], 'v1.44')
            self.assertIn('sample/Cargo.toml', argv)
        argv=command(['--program','mayhem'])
        self.assertEqual(argv[argv.index('--tools-version')+1], 'v1.52')

    def test_explicit_experiment_and_argument_boundaries_are_preserved(self):
        tail=['--program','pump','--tools-version=v1.43','--output','work/path with spaces']
        argv=command(tail)
        self.assertEqual(argv[2:],tail)
        self.assertNotIn('--tools-version',argv)

    def test_current_helper_matches_reviewed_environment_scrubbing_helper(self):
        # The maintained helper now scrubs ambient recipe overrides. This pin
        # admits that reviewed change; historical packet hashes remain unchanged.
        reviewed_sha256='0814a75b036424bf79253664f27c71ed671d5be99eaa565e4eaf8420b2e4f0a8'
        current=(ROOT/'scripts/build_partial_candidate.py').read_bytes()
        self.assertEqual(hashlib.sha256(current).hexdigest(), reviewed_sha256)


if __name__ == '__main__':
    unittest.main()
