"""Actual qualification CLI output names and cooperating writer isolation."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load('qualification_names_probe',
             ROOT / 'research/qualified-audit-output-names-20261101/probe.py')
audit = load('qualification_names_adapter', Path(__file__).with_name('audit.py'))


class QualificationOutputNameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = probe.reproduce(ROOT)

    def test_long_outputs_retain_the_complete_static_audit(self):
        rows = self.result['rows']
        control = rows['ordinary']
        for label in ('ordinary', 'ascii_240', 'unicode_240_bytes',
                      'shared_prefix_one', 'shared_prefix_two'):
            with self.subTest(label=label):
                row = rows[label]
                self.assertEqual(row['exit'], 0, row['stderr'])
                self.assertTrue(row['published'])
                self.assertEqual(row['generated_verifier_exit'], 0)
                self.assertEqual(row['summary'], control['summary'])
                self.assertEqual(row['results'], control['results'])
                self.assertEqual(row['static_inputs_sha256'], control['static_inputs_sha256'])
                self.assertEqual(row['auxiliary_entries'], [])
        self.assertEqual(control['summary']['pass'], 1)
        self.assertTrue(self.result['inputs_unchanged'])

    def test_existing_long_outputs_remain_unchanged(self):
        for label in ('occupied_directory', 'occupied_file'):
            with self.subTest(label=label):
                row = self.result['rows'][label]
                self.assertNotEqual(row['exit'], 0)
                self.assertTrue(row['prior_output_unchanged'])
                self.assertFalse(row['published'])
                self.assertEqual(row['auxiliary_entries'], [])

    @unittest.skipUnless(os.name == 'posix', 'RLIMIT_FSIZE control requires POSIX')
    def test_failed_write_cleans_auxiliary_paths_and_allows_retry(self):
        for label in ('write_failure_cleanup', 'long_write_failure_cleanup'):
            with self.subTest(label=label):
                row = self.result['rows'][label]
                self.assertNotEqual(row['exit'], 0)
                self.assertFalse(row['published'])
                self.assertEqual(row['auxiliary_entries'], [])
                self.assertEqual(row['retry_exit'], 0)
                self.assertTrue(row['retry_verified'])

    def test_held_long_output_lock_does_not_block_another_same_prefix_name(self):
        with tempfile.TemporaryDirectory(prefix='qualified-lock-names-') as temporary:
            parent = Path(temporary).resolve()
            root = parent / 'cohort'
            probe.cohort(ROOT, root)
            first = parent / ('s' * 224 + '-first-output-01')
            second = parent / ('s' * 224 + '-second-output02')
            lock = parent / ('.' + audit.auxiliary_stem(first) + '.revalidation.lock')
            lock.mkdir()  # The same directory reservation used by another adapter writer.
            blocked = probe.invoke(root, first)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertFalse(first.exists())
            completed = probe.invoke(root, second)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue(lock.is_dir())
            lock.rmdir()
            retried = probe.invoke(root, first)
            self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
            for output in (first, second):
                verified = subprocess.run([sys.executable, '-B', str(output / 'verify.py')],
                                          capture_output=True, text=True, timeout=30)
                self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            self.assertEqual(sorted(path.name for path in parent.iterdir() if path.name.startswith('.')), [])

    def test_auxiliary_components_leave_encoded_suffix_room(self):
        for name in ('a' * 240, '가' * 80, '😀' * 60):
            with self.subTest(name=name):
                stem = audit.auxiliary_stem(Path(name))
                for suffix in ('.revalidation.lock', '.staging-' + 'x' * 8):
                    encoded = os.fsencode('.' + stem + suffix)
                    self.assertLessEqual(len(encoded), 255)
                    self.assertEqual(os.fsencode(os.fsdecode(encoded)), encoded)
        self.assertEqual(audit.auxiliary_stem(Path('ordinary')), 'ordinary')


if __name__ == '__main__':
    unittest.main()
