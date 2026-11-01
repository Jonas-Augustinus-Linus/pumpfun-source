"""Isolated one-real-case CLI controls for replay input binding/publication.

The suite adapter selects one genuine buy_v3 case; each admitted run executes
captured-original/control/candidate images. This is transport evidence with
captured images on all three sides, not rebuilt-source parity.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
REL = HERE.relative_to(ROOT)
DRIVER = r'''
import base64, importlib.util, os, runpy, sys, types
from pathlib import Path
root, tool = sys.argv[1], sys.argv[2]
mode = os.environ.get('REPLAY_TEST_MODE', '')
args = sys.argv[3:]
candidate = Path(args[args.index('--candidate') + 1])
output = Path(args[args.index('--output') + 1])
sys.path.insert(0, root + '/scripts')
import pump_differential_output as publication
real_link = os.link
if mode in ('late_entry', 'late_other'):
    def link(source, destination, *args, **kwargs):
        if mode == 'late_entry': real_link(candidate, destination)
        else: Path(destination).write_bytes(b'concurrent report')
        return real_link(source, destination, *args, **kwargs)
    publication.os.link = link
if mode == 'fsync_failure':
    def fail(*args): raise OSError('injected fsync failure')
    publication.os.fsync = fail
if mode == 'partial_write':
    original_open = Path.open
    class Partial:
        def __init__(self, stream): self.stream = stream
        def __enter__(self): return self
        def __exit__(self, *args): return self.stream.__exit__(*args)
        def fileno(self): return self.stream.fileno()
        def write(self, data):
            self.stream.write(data[:len(data)//2])
            raise OSError('injected partial staging write')
    def opening(path, mode='r', *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        return Partial(stream) if mode == 'xb' else stream
    Path.open = opening
suite = types.ModuleType('pump_v3_configured_fee_differential')
count = 0
def cases():
    spec = importlib.util.spec_from_file_location(
        'real_suite', root + '/scripts/pump_v3_configured_fee_differential.py')
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    def run(binary, case):
        global count
        result = real.run(binary, case)
        count += 1
        if count == 1 and mode in ('stripped_signature', 'bad_signature'):
            from solders.transaction import Transaction
            raw = base64.b64decode(result['transaction_base64'])
            if mode == 'stripped_signature':
                raw = bytes([0]) + bytes(Transaction.from_bytes(raw).message)
            else:
                raw = bytearray(raw)
                raw[1] ^= 1
            result = dict(result, transaction_base64=base64.b64encode(raw).decode())
        if count == 1 and mode == 'replace_inputs':
            for path in (candidate,
                         Path(root)/'evidence/original/pump_fees/deployed.so',
                         Path(root)/'evidence/dependencies/spl_token/capture.json',
                         Path(root)/'scripts/pump_trade_fixture.py',
                         Path(root)/'scripts/pump_v3_configured_fee_differential.py',
                         Path(tool).parent/'fixture.json.gz'):
                replacement = path.with_name(path.name + '.replacement')
                replacement.write_bytes(b'changed after snapshot')
                os.replace(replacement, path)
        if count == 3:
            if mode == 'late_hardlink': real_link(candidate, output)
            if mode == 'late_symlink': output.symlink_to(candidate)
            if mode == 'late_parent':
                output.parent.rmdir()
                output.parent.symlink_to(candidate.parent, target_is_directory=True)
        return result
    suite.run = run
    return [next(c for c in real.cases() if c['operation'] == 'buy_v3')]
suite.cases = cases
sys.modules[suite.__name__] = suite
sys.argv = [tool] + args
runpy.run_path(tool, run_name='__main__')
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReplayOutputPreservationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / 'repo'
        paths = [REL/'replay.py', REL/'fixture.json.gz',
                 *[Path('scripts')/name for name in (
                     'pump_trade_fixture.py', 'pump_v3_configured_fee_differential.py',
                     'pump_amm_reusable_harness.py', 'pump_differential_output.py')],
                 *[Path('evidence')/group/name/filename
                   for group, names in (('original', ('pump', 'pump_fees')),
                                        ('dependencies', ('spl_token', 'spl_token_2022', 'associated_token')))
                   for name in names for filename in ('capture.json', 'deployed.so')]]
        for rel in paths:
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, target)
        self.control = self.root / 'control.so'
        self.candidate = self.root / 'candidate.so'
        for path in (self.control, self.candidate):
            shutil.copyfile(self.root/'evidence/original/pump/deployed.so', path)
        self.output = self.root.parent / 'report.json.gz'
        self.before = {p: digest(p) for p in self.root.rglob('*') if p.is_file()}

    def run_replay(self, output=None, mode=''):
        return subprocess.run(
            [sys.executable, '-B', '-c', DRIVER, str(self.root), str(self.root/REL/'replay.py'),
             '--control', str(self.control), '--candidate', str(self.candidate),
             '--output', str(self.output if output is None else output)],
            env={**os.environ, 'REPLAY_TEST_MODE': mode},
            capture_output=True, text=True, timeout=300)

    def unchanged(self):
        for path, sha in self.before.items():
            self.assertEqual(digest(path), sha, f'{path} input was overwritten')

    def rejected(self, result):
        self.assertEqual(result.returncode, 2, result.stderr[-1200:])
        self.assertIn('report', result.stderr)
        self.unchanged()

    def test_direct_declared_input_collisions(self):
        declared = [self.control, self.candidate, self.root/REL/'fixture.json.gz',
                    *[self.root/Path('scripts')/name for name in ('pump_trade_fixture.py', 'pump_v3_configured_fee_differential.py')],
                    *self.root.glob('evidence/*/*/capture.json'),
                    *self.root.glob('evidence/*/*/deployed.so')]
        self.assertEqual(len(declared), 15)
        for path in declared:
            with self.subTest(path=path.relative_to(self.root)):
                self.rejected(self.run_replay(path))

    def test_hardlink_aliases(self):
        for path in (self.control, self.candidate, self.root/REL/'fixture.json.gz',
                     self.root/'evidence/dependencies/spl_token/capture.json'):
            with self.subTest(path=path.name):
                os.link(path, self.output)
                try: self.rejected(self.run_replay())
                finally: self.output.unlink()

    def test_symlink_alias(self):
        self.output.symlink_to(self.candidate)
        self.rejected(self.run_replay())

    def test_case_alias(self):
        alias = self.candidate.with_name(self.candidate.name.upper())
        if not alias.exists() or not alias.samefile(self.candidate):
            self.skipTest('filesystem distinguishes case')
        self.rejected(self.run_replay(alias))

    def test_separate_output_has_exact_input_bindings(self):
        result = self.run_replay()
        self.assertEqual(result.returncode, 0, result.stderr[-1200:])
        self.unchanged()
        report = json.loads(gzip.decompress(self.output.read_bytes()))
        self.assertEqual(report['case_count'], 1)
        self.assertEqual((report['differences'], report['regressions']), ([], []))
        self.assertEqual(report['images']['candidate'], self.before[self.candidate])
        self.assertEqual(report['images']['control'], self.before[self.control])
        self.assertEqual(len(report['declared_input_sha256']), 15)
        for name, sha in report['declared_input_sha256'].items():
            source = self.control if name == 'control' else self.candidate if name == 'candidate' else self.root/REL/'fixture.json.gz' if name == 'fixture' else self.root/name
            self.assertEqual(sha, self.before[source])
        for receipt in report['rows'][0]['receipts'].values():
            self.assertTrue(receipt['signature_verified'])

    def test_replaced_inputs_do_not_change_execution_or_report_binding(self):
        result = self.run_replay(mode='replace_inputs')
        self.assertEqual(result.returncode, 0, result.stderr[-1200:])
        report = json.loads(gzip.decompress(self.output.read_bytes()))
        self.assertEqual((report['case_count'], report['differences'], report['regressions']), (1, [], []))
        self.assertEqual(report['images']['candidate'], self.before[self.candidate])
        self.assertNotEqual(digest(self.candidate), report['images']['candidate'])
        for name, sha in report['source_inputs'].items():
            self.assertEqual(sha, self.before[self.root/name])
        for name in ('evidence/original/pump_fees/deployed.so', 'evidence/dependencies/spl_token/capture.json', 'fixture'):
            path = self.root/REL/'fixture.json.gz' if name == 'fixture' else self.root/name
            self.assertEqual(report['declared_input_sha256'][name], self.before[path])
            self.assertNotEqual(digest(path), self.before[path])

    def test_late_aliases_are_refused(self):
        for mode in ('late_hardlink', 'late_symlink'):
            with self.subTest(mode=mode):
                self.rejected(self.run_replay(mode=mode))
                self.assertTrue(self.output.exists())
                self.output.unlink()

    def test_late_directory_alias_is_refused(self):
        self.output = self.root/'safe'/'candidate.so'
        self.rejected(self.run_replay(mode='late_parent'))
        self.assertTrue(self.output.samefile(self.candidate))

    def test_alias_created_after_final_check_is_not_replaced(self):
        self.rejected(self.run_replay(mode='late_entry'))
        self.assertTrue(self.output.samefile(self.candidate))

    def test_concurrent_unrelated_destination_is_not_replaced(self):
        self.rejected(self.run_replay(mode='late_other'))
        self.assertEqual(self.output.read_bytes(), b'concurrent report')

    def test_staging_failures_leave_no_output_or_partial_file(self):
        for mode in ('partial_write', 'fsync_failure'):
            with self.subTest(mode=mode):
                self.rejected(self.run_replay(mode=mode))
                self.assertFalse(self.output.exists())
                self.assertEqual(list(self.output.parent.glob('.report.json.gz.*')), [])

    def test_unsigned_or_invalid_receipt_signature_is_rejected(self):
        for mode in ('stripped_signature', 'bad_signature'):
            with self.subTest(mode=mode):
                self.output = self.root.parent / (mode + '.json.gz')
                result = self.run_replay(mode=mode)
                self.assertEqual(result.returncode, 2, result.stderr[-1200:])
                self.assertIn('signature verification failed', result.stderr)
                self.assertFalse(self.output.exists())
                self.unchanged()

    def test_existing_report_is_preserved(self):
        self.output.write_bytes(b'prior report')
        self.rejected(self.run_replay())
        self.assertEqual(self.output.read_bytes(), b'prior report')


if __name__ == '__main__':
    unittest.main()
