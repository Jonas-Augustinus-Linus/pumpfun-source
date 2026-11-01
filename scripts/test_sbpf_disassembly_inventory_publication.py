"""A failed disassembly inventory must not leave a partial output directory."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sbpf_disassembly_inventory as tool


def fake_check_output(command, **kwargs):
    if command[-1] == 'HEAD':
        return 'fixture-revision\n'
    if command[-1] == '--version':
        return 'sbpf fixture\n'
    return b''  # clean `git status --porcelain`


class InventoryPublicationTests(unittest.TestCase):
    def run_main(self, inventory, prepare=None, expected_error=None):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source = directory / 'tool'
        executable = source / 'target/release/sbpf'
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'not executed by this test')
        (source / 'Cargo.lock').write_text('')
        output = directory / 'inventory'
        if prepare is not None:
            prepare(output)
        argv = ['inventory', '--tool-source', str(source), '--output', str(output)]
        inputs = [('one', Path('one.so')), ('two', Path('two.so'))]
        with patch.object(sys, 'argv', argv), \
                patch.object(tool.subprocess, 'check_output', fake_check_output), \
                patch.object(tool, 'program_inputs', lambda root: inputs), \
                patch.object(tool, 'inventory', inventory), \
                patch.object(tool.Path, 'glob', lambda self, pattern: iter(())), \
                contextlib.redirect_stdout(io.StringIO()):
            with (self.assertRaises(expected_error) if expected_error
                  else contextlib.nullcontext()):
                try:
                    tool.main()
                except ValueError:
                    pass
        return output

    def test_failed_program_leaves_no_output_directory(self):
        def inventory(_tool, name, _path, output):
            (output / (name + '.json.gz')).write_bytes(b'partial')
            if name == 'two':
                raise ValueError('two: disassembler emitted diagnostics')
            return {'name': name}

        output = self.run_main(inventory)
        self.assertFalse(output.exists(), 'failed run left a partial inventory that blocks a rerun')

    def test_successful_run_publishes_manifest_and_programs(self):
        def inventory(_tool, name, _path, output):
            (output / (name + '.json.gz')).write_bytes(b'complete')
            return {'name': name}

        output = self.run_main(inventory)
        self.assertEqual(sorted(p.name for p in output.iterdir()),
                         ['manifest.json', 'one.json.gz', 'two.json.gz'])

    def test_existing_output_links_are_refused_without_following(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                def prepare(output):
                    target = output.parent / 'target'
                    if populated:
                        target.mkdir()
                        (target / 'keep').write_bytes(b'existing')
                    output.symlink_to(target, target_is_directory=True)

                def inventory(*_args):
                    self.fail('output link must be rejected before disassembly')

                output = self.run_main(inventory, prepare, FileExistsError)
                self.assertTrue(output.is_symlink())
                target = output.parent / 'target'
                if populated:
                    self.assertEqual((target / 'keep').read_bytes(), b'existing')
                else:
                    self.assertFalse(target.exists())
                self.assertEqual(list(output.parent.glob('.inventory.*')), [])

    def test_existing_empty_and_full_directories_are_preserved(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                identity = []

                def prepare(output):
                    output.mkdir()
                    identity.append(output.stat().st_ino)
                    if populated:
                        (output / 'keep').write_bytes(b'existing')

                def inventory(*_args):
                    self.fail('existing output must be rejected before disassembly')

                output = self.run_main(inventory, prepare, FileExistsError)
                self.assertEqual(output.stat().st_ino, identity[0])
                self.assertEqual(sorted(p.name for p in output.iterdir()),
                                 ['keep'] if populated else [])

    def test_late_empty_directory_is_preserved_and_staging_removed(self):
        identity = []

        def inventory(_tool, name, _path, staging):
            if name == 'one':
                output = staging.parent / 'inventory'
                output.mkdir()
                identity.append(output.stat().st_ino)
            (staging / (name + '.json.gz')).write_bytes(b'complete')
            return {'name': name}

        output = self.run_main(inventory, expected_error=FileExistsError)
        self.assertEqual(output.stat().st_ino, identity[0])
        self.assertEqual(list(output.iterdir()), [])
        self.assertEqual(list(output.parent.glob('.inventory.*')), [])


if __name__ == '__main__':
    unittest.main()
