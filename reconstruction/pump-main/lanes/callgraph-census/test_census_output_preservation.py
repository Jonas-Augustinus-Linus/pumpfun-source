"""The census report paths must not replace an input the census reads."""
from collections import Counter
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'census_guard', Path(__file__).with_name('census.py'))
census = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(census)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class FakeImage:
    def __init__(self, path, funcs):
        self.funcs, self.secs, self.blob = funcs, {}, b''

    def raw(self, start):
        return b''

    def calls(self, start):
        return []

    def external_counts(self, start):
        return Counter()

    def text(self, start):
        return {}


class CensusOutputPreservationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        root = Path(self.scratch.name)
        self.base = root / 'base'
        self.base.mkdir()
        (self.base / 'original.so').write_bytes(b'original-bytes')
        (self.base / 'functions.tsv').write_bytes(b'inventory-bytes')
        self.candidate = root / 'candidate.so'
        self.candidate.write_bytes(b'candidate-bytes')
        self.pairs = root / 'pairs.json'
        self.pairs.write_text(json.dumps({'0x10': 'paired$'}), encoding='utf-8')
        self.watched = [self.candidate, self.pairs,
                        self.base / 'original.so', self.base / 'functions.tsv']
        self.before = {path: digest(path) for path in self.watched}

    def tearDown(self):
        self.scratch.cleanup()

    def assert_inputs_unchanged(self):
        for path, sha in self.before.items():
            self.assertEqual(digest(path), sha, f'{path.name} input was overwritten')

    def run_census(self, argv):
        with patch.object(census, 'BASE', self.base), \
             patch.object(census, 'ORIG_PATH', self.base / 'original.so'), \
             patch.object(sys, 'argv', argv), \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            try:
                census.main()
                code = None
            except SystemExit as exit_:
                code = exit_.code
        return code, errors.getvalue()

    def exercise_refusal(self, argv):
        code, errors = self.run_census(argv)
        self.assertEqual(code, 2, errors)
        self.assertIn('report destination aliases an input', errors)
        self.assert_inputs_unchanged()

    def argv(self, *extra):
        return ['census.py', '--cand', str(self.candidate),
                '--pairs', str(self.pairs), *extra]

    def test_json_cannot_replace_the_candidate(self):
        self.exercise_refusal(self.argv('--json', str(self.candidate)))

    def test_md_cannot_replace_the_candidate(self):
        self.exercise_refusal(self.argv('--md', str(self.candidate)))

    def test_json_cannot_replace_the_shared_original(self):
        self.exercise_refusal(self.argv('--json', str(self.base / 'original.so')))

    def test_json_cannot_replace_the_window_inventory(self):
        self.exercise_refusal(self.argv('--json', str(self.base / 'functions.tsv')))

    def test_json_cannot_replace_the_pairs_file(self):
        self.exercise_refusal(self.argv('--json', str(self.pairs)))

    def test_separate_reports_still_publish(self):
        root = Path(self.scratch.name)
        report_json = root / 'census.json'
        report_md = root / 'census.md'
        argv = self.argv('--only', '0x10', '--json', str(report_json),
                         '--md', str(report_md))
        with patch.object(census, 'original_windows',
                          return_value=[{'start': 0x10, 'bytes': 8}]), \
             patch.object(census, 'candidate_functions',
                          return_value=[(0x20, 8, 'paired')]), \
             patch.object(census, 'Image', FakeImage), \
             patch.object(census, 'normalize', return_value=b''), \
             patch.object(census, 'ratio', return_value=1.0), \
             patch.object(census, 'source_sites', return_value=[]), \
             patch.object(census, 'demangle', side_effect=lambda name: name):
            code, errors = self.run_census(argv)
        self.assertIsNone(code, errors)
        published = json.loads(report_json.read_text(encoding='utf-8'))
        self.assertEqual(published['candidate'], str(self.candidate))
        self.assertIn('0x10', report_md.read_text(encoding='utf-8'))
        self.assert_inputs_unchanged()


if __name__ == '__main__':
    unittest.main()
