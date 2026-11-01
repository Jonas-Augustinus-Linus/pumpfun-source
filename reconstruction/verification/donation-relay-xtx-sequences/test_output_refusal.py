"""A new run must not replace a retained sequence report."""
import importlib.util
import hashlib
import io
import json
import shutil
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location('relay_xtx_output', HERE / 'producer.py')
xtx = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = xtx
SPEC.loader.exec_module(xtx)

CANDIDATE = ROOT / 'evidence/dependencies/donation_relay/deployed.so'


class OutputRefusalTests(unittest.TestCase):
    def run_over(self, output):
        with mock.patch.object(xtx, 'run_case', side_effect=RuntimeError('cases started')):
            try:
                with self.assertRaisesRegex(SystemExit, 'refusing to overwrite'):
                    xtx.execute(ROOT, CANDIDATE, output)
            except RuntimeError as error:
                self.fail(f'{error}: an occupied output was accepted')

    def test_existing_report_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            output.write_bytes(b'retained report\n')
            self.run_over(output)
            self.assertEqual(output.read_bytes(), b'retained report\n')

    def test_dangling_output_link_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            target = Path(temporary) / 'elsewhere.json'
            os.symlink(target, output)
            self.run_over(output)
            self.assertFalse(target.exists())

    def test_absent_output_starts_the_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(xtx, 'run_case', side_effect=RuntimeError('cases started')):
                with self.assertRaisesRegex(RuntimeError, 'cases started'):
                    xtx.execute(ROOT, CANDIDATE, Path(temporary) / 'report.json')


class PublicationAndSnapshotTests(unittest.TestCase):
    def test_late_destination_does_not_replace_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / 'candidate.so'
            output = Path(temporary) / 'report.json'
            shutil.copyfile(CANDIDATE, candidate)
            before = candidate.read_bytes()
            real = xtx.run_case
            def late(name, *args):
                row = real(name, *args)
                if name == xtx.CASE_NAMES[-1]:
                    os.link(candidate, output)
                return row
            with mock.patch.object(xtx, 'run_case', side_effect=late):
                with self.assertRaises((ValueError, FileExistsError)):
                    xtx.execute(ROOT, candidate, output)
            self.assertEqual(candidate.read_bytes(), before)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(list(output.parent.glob('.report.json.*')), [])

    def test_input_replacement_does_not_rebind_the_executed_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / 'candidate.so'
            output = Path(temporary) / 'report.json'
            shutil.copyfile(CANDIDATE, candidate)
            before = candidate.read_bytes()
            real = xtx.run_case
            def replace(name, *args):
                row = real(name, *args)
                if name == xtx.CASE_NAMES[0]:
                    candidate.write_bytes(b'changed after snapshot')
                return row
            with mock.patch.object(xtx, 'run_case', side_effect=replace), redirect_stdout(io.StringIO()):
                self.assertTrue(xtx.execute(ROOT, candidate, output))
            report = json.loads(output.read_bytes())
            self.assertEqual(report['candidate']['sha256'], hashlib.sha256(before).hexdigest())
            self.assertNotEqual(hashlib.sha256(candidate.read_bytes()).hexdigest(), report['candidate']['sha256'])
            self.assertEqual((report['case_count'], report['transaction_count'], report['different_cases']), (7, 14, []))

    def test_staging_failure_leaves_no_report_or_partial_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            with mock.patch('pump_differential_output.os.fsync', side_effect=OSError('injected fsync')):
                with self.assertRaisesRegex(OSError, 'injected fsync'):
                    xtx.execute(ROOT, CANDIDATE, output)
            self.assertFalse(output.exists())
            self.assertEqual(list(output.parent.glob('.report.json.*')), [])


if __name__ == '__main__':
    unittest.main()
