"""The bounded corpus check must require a declared case_count too.

`test_real_bounded_publication` compared the two selected cases with
``report.get('case_count', len(report['cases']))``. When the key is absent the
default is the left-hand value, so a writer that stopped declaring case_count
passed every bounded publication test, while the full-corpus check already
requires the key and its type.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import publication_cli_support as support


class BoundedCaseCountTests(unittest.TestCase):
    def bounded(self, report):
        """Run the shared bounded check with the CLI replaced by a fixed report."""
        case = unittest.TestCase()
        temporary = tempfile.TemporaryDirectory(prefix='bounded-report-')
        self.addCleanup(temporary.cleanup)
        case.root = Path(temporary.name)
        case.output = case.root / 'out/report.json'
        case.output.parent.mkdir()
        case.NAMES = ('fake',)
        case.CANDIDATE_REQUIRED = False
        case.LATE_INPUT = 'late.json'
        late = case.root / case.LATE_INPUT
        late.write_bytes(b'bound input')
        case.inputs = {late: b'bound input'}
        case.report = lambda: report

        def invoke(name, mode='bounded', output=None, cwd=None):
            (case.root / 'execution.json').write_text('{"selected": 2}')
            if mode == 'late':
                return support.subprocess.CompletedProcess([], 1, '', 'report output aliases an input')
            if mode == 'failure':
                return support.subprocess.CompletedProcess([], 1, '', 'controlled fsync failure')
            if mode == 'recreate':
                staged = case.root / 'staged'
                staged.write_bytes(b'later staging owner')
                (case.root / 'recreated.txt').write_text(str(staged))
            return support.subprocess.CompletedProcess([], 0, '', '')

        case.invoke = invoke
        support.PublicationCase.test_real_bounded_publication(case)

    def test_a_bounded_report_without_case_count_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'case_count'):
            self.bounded({'mismatches': [], 'cases': [{}, {}]})

    def test_a_bounded_report_with_the_declared_count_is_accepted(self):
        self.bounded({'mismatches': [], 'case_count': 2, 'cases': [{}, {}]})

    def test_a_bounded_report_whose_count_disagrees_is_rejected(self):
        with self.assertRaises(AssertionError):
            self.bounded({'mismatches': [], 'case_count': 3, 'cases': [{}, {}]})

    def test_a_bounded_non_integer_count_is_rejected(self):
        for count in (2.0, True, '2'):
            with self.subTest(count=count), self.assertRaises(AssertionError):
                self.bounded({'mismatches': [], 'case_count': count, 'cases': [{}, {}]})


if __name__ == '__main__':
    unittest.main()
