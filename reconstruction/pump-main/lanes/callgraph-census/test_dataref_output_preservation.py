"""Real dataref CLIs preserve a wholly private cohort of declared inputs."""
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
LANE = HERE.relative_to(ROOT)
ARCHIVE = ROOT / 'research/pump-multihop-sell-fees-20261029/build/candidate/symbols.so.gz'
HELPERS = ('score.py', 'score_admission.py', 'llvm_tools.py', 'original_input.py',
           'elf_symbols.py', 'instruction_stream.py', 'win.py', 'coords.py', 'compare_scores.py')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DatarefOutputPreservationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='pump-dataref-test-')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        # A guard regression must never write a repository input. The original
        # pointer and its target, inventory and candidate all belong here.
        files = [Path('reconstruction/harness') / name for name in HELPERS]
        files += [LANE / name for name in ('census.py', 'dataref_audit.py')]
        files += [Path('reconstruction/base/functions.tsv'), Path('evidence/original/pump/deployed.so')]
        for relative in files:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        base = self.root / 'reconstruction/base'
        original = base / 'original.so'
        original.write_bytes(b'../../evidence/original/pump/deployed.so')
        self.candidate = self.root / 'candidate.so'
        self.candidate.write_bytes(gzip.decompress(ARCHIVE.read_bytes()))
        self.inputs = {'candidate': self.candidate, 'original-pointer': original,
                       'captured-original': self.root / 'evidence/original/pump/deployed.so',
                       'inventory': base / 'functions.tsv'}
        self.watched = {path: digest(path) for path in self.inputs.values()}
        self.report = self.root / 'report.json'

    def assert_inputs_preserved(self, except_candidate=False):
        for path, sha in self.watched.items():
            if except_candidate and path == self.candidate:
                continue
            self.assertEqual(digest(path), sha, f'{path} input was overwritten')

    def run_audit(self, report=None, mode=None):
        command = [sys.executable, '-I', '-B']
        if mode:
            driver = self.root / 'driver.py'
            driver.write_text('''import importlib.util, os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv.pop(1))
spec = importlib.util.spec_from_file_location('dataref', Path(sys.path[0]) / 'dataref_audit.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
mode, public, destination, marker = sys.argv[1:5]
del sys.argv[1:5]
public, destination, marker = map(Path, (public, destination, marker))
if mode == 'snapshot':
    real = m.C.candidate_functions
    def symbols(path):
        result = real(path)
        public.write_bytes(b'replaced public candidate after symbol read')
        marker.write_text('actual symbols read from ' + str(path))
        return result
    m.C.candidate_functions = symbols
elif mode == 'late-admission':
    real = m.audit
    def audit(*args):
        result = real(*args)
        os.link(public, destination)
        marker.write_text('actual analysis finished')
        return result
    m.audit = audit
else:
    real = m.publish_report
    def publish(path, text):
        marker.write_text('actual analysis and destination check finished')
        if mode == 'late-file':
            path.write_bytes(b'concurrent report owner')
        elif mode == 'late-symlink':
            path.symlink_to(public)
        elif mode == 'late-hardlink':
            os.link(public, path)
        elif mode == 'partial-write':
            import resource
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))
        return real(path, text)
    m.publish_report = publish
m.main()
''')
            command += [str(driver), str(self.root / LANE), mode, str(self.candidate),
                        str(report or self.report), str(self.root / 'scheduled')]
        else:
            command += [str(self.root / LANE / 'dataref_audit.py')]
        command += ['--cand', str(self.candidate), '--json', str(report or self.report)]
        return subprocess.run(command, capture_output=True, text=True, timeout=300)

    def assert_refused(self, result, message=None):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        if message:
            self.assertIn(message, result.stderr)
        self.assert_inputs_preserved()

    def test_direct_declared_input_collisions(self):
        for name, target in self.inputs.items():
            with self.subTest(input=name):
                self.assert_refused(self.run_audit(target), 'report destination aliases an input')

    def test_lexical_alias_cannot_replace_candidate(self):
        (self.root / 'sub').mkdir()
        self.assert_refused(self.run_audit(self.root / 'sub/../candidate.so'),
                            'report destination aliases an input')

    def test_symlink_aliases_preserve_every_input(self):
        for name, target in self.inputs.items():
            with self.subTest(input=name):
                report = self.root / (name + '-symlink.json')
                report.symlink_to(target)
                self.assert_refused(self.run_audit(report), 'report destination aliases an input')
                self.assertTrue(report.is_symlink())

    def test_hardlink_aliases_preserve_every_input(self):
        for name, target in self.inputs.items():
            with self.subTest(input=name):
                report = self.root / (name + '-hardlink.json')
                os.link(target, report)
                self.assert_refused(self.run_audit(report), 'report destination aliases an input')
                self.assertTrue(report.samefile(target))

    def test_native_case_alias_cannot_replace_candidate(self):
        report = self.root / 'CANDIDATE.SO'
        if not report.exists() or not report.samefile(self.candidate):
            self.skipTest('filesystem does not expose a native case alias')
        self.assert_refused(self.run_audit(report), 'report destination aliases an input')

    def test_fresh_report_binds_actual_analyzed_bytes(self):
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_inputs_preserved()
        published = json.loads(self.report.read_text())
        self.assertEqual(published['candidate'], str(self.candidate))
        self.assertEqual(published['candidate_sha256'], self.watched[self.candidate])
        self.assertEqual(published['original_sha256'], self.watched[self.inputs['captured-original']])
        self.assertEqual(published['window_inventory_sha256'], self.watched[self.inputs['inventory']])
        self.assertGreater(published['clean'] + published['flagged'], 0)
        self.assertEqual(published['flagged'], len(published['rows']))

    def test_existing_unrelated_report_is_retained(self):
        self.report.write_bytes(b'prior diagnostic')
        self.assert_refused(self.run_audit())
        self.assertEqual(self.report.read_bytes(), b'prior diagnostic')
        self.assertFalse(list(self.root.glob('.comparison-*')))

    def test_alias_created_after_analysis_is_refused(self):
        self.assert_refused(self.run_audit(mode='late-admission'), 'report destination aliases an input')
        self.assertTrue((self.root / 'scheduled').exists())
        self.assertTrue(self.report.samefile(self.candidate))

    def test_output_claimed_after_final_check_is_retained(self):
        for mode in ('late-file', 'late-symlink', 'late-hardlink'):
            with self.subTest(mode=mode):
                report = self.root / (mode + '.json')
                self.assert_refused(self.run_audit(report, mode))
                self.assertTrue((self.root / 'scheduled').exists())
                if mode == 'late-file':
                    self.assertEqual(report.read_bytes(), b'concurrent report owner')
                else:
                    self.assertTrue(report.samefile(self.candidate))
                self.assertFalse(list(self.root.glob('.comparison-*')))

    @unittest.skipIf(os.name == 'nt', 'RLIMIT_FSIZE is a POSIX fault control')
    def test_partial_os_write_leaves_no_report_then_retry_succeeds(self):
        self.assert_refused(self.run_audit(mode='partial-write'))
        self.assertTrue((self.root / 'scheduled').exists())
        self.assertFalse(self.report.exists())
        self.assertFalse(list(self.root.glob('.comparison-*')))
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertGreater(json.loads(self.report.read_text())['clean'], 0)
        self.assert_inputs_preserved()

    def test_public_candidate_replacement_cannot_mix_analysis_reads(self):
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = json.loads(self.report.read_text())
        self.report.unlink()
        result = self.run_audit(mode='snapshot')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('pump-dataref-inputs-', (self.root / 'scheduled').read_text())
        self.assertEqual(json.loads(self.report.read_text()), expected)
        self.assertEqual(self.candidate.read_bytes(), b'replaced public candidate after symbol read')
        self.assert_inputs_preserved(except_candidate=True)


if __name__ == '__main__':
    unittest.main()
