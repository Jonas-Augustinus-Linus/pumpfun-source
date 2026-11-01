"""Run the real dispatch CLI on copied captures; never mutate repository evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('scripts/recover_dispatch.py', 'scripts/analyze.py')
CAPTURES = tuple(f'evidence/original/{name}/deployed.so'
                 for name in ('pump', 'pump_amm', 'pump_fees', 'mayhem'))
IDLS = tuple(f'evidence/upstream/{name}.json' for name in ('pump', 'pump_amm', 'pump_fees'))
CASES = ('fresh', 'regular', 'linked-capture', 'linked-idl', 'dangling',
         'hardlinked-capture', 'hardlinked-idl', 'directory', 'invalid-late-idl')
REPORT_SHA256 = '609e4795d796aeed61c7e6d8853407264362166afd05bd9d76687ed673ecc2f9'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run_case(case, checkout=ROOT, revision=None):
    checkout = Path(checkout)
    with tempfile.TemporaryDirectory(prefix='dispatch-publication-') as temporary:
        root = Path(temporary)
        for name in (*SOURCES, *CAPTURES, *IDLS):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = (subprocess.check_output(['git', 'show', f'{revision}:{name}'], cwd=checkout)
                   if revision and name in SOURCES else (checkout / name).read_bytes())
            path.write_bytes(raw)
        target = root / 'evidence/dispatch-map.json'
        capture = root / CAPTURES[0]
        idl = root / IDLS[0]
        if case in ('regular', 'invalid-late-idl'):
            target.write_bytes(b'prior complete report\n')
        elif case.startswith('linked-'):
            source = capture if case == 'linked-capture' else idl
            target.symlink_to(source.relative_to(target.parent))
        elif case.startswith('hardlinked-'):
            target.hardlink_to(capture if case == 'hardlinked-capture' else idl)
        elif case == 'dangling':
            target.symlink_to('unexpected.json')
        elif case == 'directory':
            target.mkdir()
            (target / 'retained.txt').write_bytes(b'prior directory contents\n')
        if case == 'invalid-late-idl':
            (root / IDLS[-1]).write_bytes(b'{ invalid late IDL')
        inputs = {name: sha((root / name).read_bytes()) for name in (*SOURCES, *CAPTURES, *IDLS)}
        run = subprocess.run([sys.executable, '-B', str(root / SOURCES[0])], cwd=root,
                             capture_output=True, text=True, timeout=30)
        report = target.read_bytes() if target.is_file() else None
        rows = json.loads(report) if run.returncode == 0 else None
        return {
            'case': case, 'exit': run.returncode,
            'inputs_preserved': all(sha((root / name).read_bytes()) == digest
                                    for name, digest in inputs.items()),
            'input_sha256': inputs, 'report_sha256': sha(report) if report is not None else None,
            'report_is_symlink': target.is_symlink(),
            'unintended_target_created': (root / 'evidence/unexpected.json').exists(),
            'prior_report_preserved': report == b'prior complete report\n',
            'prior_directory_preserved': (target / 'retained.txt').is_file()
                if target.is_dir() else False,
            'temporary_entries': sorted(p.name for p in target.parent.iterdir() if p.name.startswith('.dispatch-map.json.')),
            'instruction_counts': {name: len(value['instructions']) for name, value in rows.items()} if rows else None,
            'stdout': run.stdout,
        }


class DispatchPublicationTests(unittest.TestCase):
    def test_regular_outputs_keep_the_same_dispatch_bytes(self):
        for case in ('fresh', 'regular'):
            with self.subTest(case=case):
                row = run_case(case)
                self.assertEqual(row['exit'], 0, row)
                self.assertEqual(row['report_sha256'], REPORT_SHA256)
                self.assertTrue(row['inputs_preserved'])
                self.assertFalse(row['temporary_entries'])

    def test_links_are_refused_without_writing_their_targets(self):
        for case in ('linked-capture', 'linked-idl', 'dangling'):
            with self.subTest(case=case):
                row = run_case(case)
                self.assertNotEqual(row['exit'], 0, row)
                self.assertTrue(row['inputs_preserved'])
                self.assertTrue(row['report_is_symlink'])
                self.assertFalse(row['unintended_target_created'])
                self.assertFalse(row['temporary_entries'])

    def test_hardlinks_are_replaced_without_truncating_inputs(self):
        for case in ('hardlinked-capture', 'hardlinked-idl'):
            with self.subTest(case=case):
                row = run_case(case)
                self.assertEqual(row['exit'], 0, row)
                self.assertTrue(row['inputs_preserved'])
                self.assertEqual(row['report_sha256'], REPORT_SHA256)
                self.assertFalse(row['temporary_entries'])

    def test_existing_directory_and_late_analysis_failure_preserve_prior_output(self):
        for case in ('directory', 'invalid-late-idl'):
            with self.subTest(case=case):
                row = run_case(case)
                self.assertNotEqual(row['exit'], 0, row)
                self.assertTrue(row['inputs_preserved'])
                self.assertTrue(row['prior_directory_preserved'] if case == 'directory'
                                else row['prior_report_preserved'])
                self.assertFalse(row['temporary_entries'])


if __name__ == '__main__':
    unittest.main()
