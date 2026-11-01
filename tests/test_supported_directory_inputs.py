"""Explicit directory assets survive the supported adapter's staging boundary."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT/'scripts/build_supported_sbpf_candidate.py'
spec = importlib.util.spec_from_file_location('supported_directory_tests', ADAPTER)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
RUST = (Path(os.environ['PUMP_TEST_RUST_BIN']) if os.environ.get('PUMP_TEST_RUST_BIN') else
        Path(shutil.which('rustc')).parent if shutil.which('rustc') else None)


def staging_code():
    """Compile the unmodified prepare statements before the registry-cache copy.

    Like the executable-input regression, this exercises the real adapter
    staging on any CI host without substituting a pretend SBF compiler/output.
    """
    module = ast.parse(ADAPTER.read_text())
    execute = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
    prepare = next(n for n in execute.body if isinstance(n, ast.Try)).body
    stop = next(i for i, n in enumerate(prepare) if isinstance(n, ast.Expr) and
                isinstance(n.value, ast.Call) and ast.unparse(n.value.func) == 'shutil.copytree')
    return compile(ast.fix_missing_locations(ast.Module(body=prepare[:stop], type_ignores=[])), str(ADAPTER), 'exec')


def stage(repo, output, planned):
    exec(staging_code(), {'planned': planned, 'repo': repo, 'output': output,
                         'sha': builder.sha, 'shutil': shutil,
                         'extra_input_directories': builder.extra_input_directories})


class SupportedDirectoryInputs(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='supported-directory-test-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repo = self.base/'repo'
        self.repo.mkdir()

    def test_membership_is_sorted_and_matches_per_extra_exclusions(self):
        asset = self.repo/'assets'
        for name in ('a/empty', 'nested/target', 'target/generated', '.git/objects'):
            (asset/name).mkdir(parents=True)
        (asset/'note.txt').write_text('asset')
        result = builder.extra_input_directories(self.repo, [asset, asset/'nested', asset/'note.txt'])
        self.assertEqual(result, ['assets', 'assets/a', 'assets/a/empty', 'assets/nested', 'assets/nested/target'])
        self.assertEqual(result, builder.extra_input_directories(self.repo, [asset/'note.txt', asset, asset]))

    def test_file_only_extras_do_not_admit_sibling_directories(self):
        (self.repo/'assets/empty').mkdir(parents=True)
        file = self.repo/'assets/target'
        file.write_text('explicit file named target')
        self.assertEqual(builder.extra_input_directories(self.repo, [file]), [])

    @unittest.skipUnless(os.name == 'posix', 'requires symlink support')
    def test_symlinked_directories_stay_outside_the_admitted_tree(self):
        (self.repo/'assets/empty').mkdir(parents=True)
        link = self.repo/'link'
        link.symlink_to(self.repo/'assets', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlinked compiler input'):
            builder.extra_input_directories(self.repo, [link])
        (self.repo/'assets/alias').symlink_to(self.repo/'assets/empty', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlinked compiler input'):
            builder.extra_input_directories(self.repo, [self.repo/'assets'])

    def test_membership_changes_fail_before_source_staging(self):
        asset = self.repo/'assets'
        asset.mkdir()
        planned = {'extra_inputs': [str(asset)], 'extra_input_directories': ['assets'], 'source_sha256': {}}
        (asset/'new-empty').mkdir()
        output = self.base/'output'
        with self.assertRaisesRegex(ValueError, 'directories changed after planning'):
            stage(self.repo, output, planned)
        self.assertFalse(output.exists())
        planned['extra_input_directories'] = ['assets', 'assets/new-empty']
        (asset/'new-empty').rmdir()
        with self.assertRaisesRegex(ValueError, 'directories changed after planning'):
            stage(self.repo, output, planned)
        self.assertFalse(output.exists())

    @unittest.skipUnless(RUST and (RUST/'cargo').is_file(), 'requires a host Cargo/rustc toolchain')
    def test_real_host_cargo_builds_the_staged_empty_assets(self):
        for name, relative in [('root', 'assets'), ('nested', 'assets/config/empty')]:
            with self.subTest(name=name):
                source = self.repo/name
                (source/'src').mkdir(parents=True)
                (source/relative).mkdir(parents=True)
                (source/'Cargo.toml').write_text('[package]\nname="directory-host-probe"\nversion="0.1.0"\n[workspace]\n')
                (source/'Cargo.lock').write_text('version=3\n[[package]]\nname="directory-host-probe"\nversion="0.1.0"\n')
                (source/'src/lib.rs').write_text('include!(concat!(env!("OUT_DIR"),"/generated.rs"));\n')
                (source/'build.rs').write_text('fn main(){let n=std::fs::read_dir('+json.dumps(relative)+').unwrap().count();'
                    'std::fs::write(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("generated.rs"),'
                    'format!("pub const COUNT:usize={};",n)).unwrap();}\n')
                files = {p.relative_to(self.repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in source.rglob('*') if p.is_file()}
                planned = {'source_sha256': files, 'extra_inputs': [str(source/'assets')],
                           'extra_input_directories': builder.extra_input_directories(self.repo, [source/'assets'])}
                output = self.base/(name+'-output')
                stage(self.repo, output, planned)
                env = {'PATH': str(RUST)+os.pathsep+os.environ['PATH'], 'RUSTC': str(RUST/'rustc'),
                       'CARGO_HOME': str(self.base/'cargo-home')}
                for kind, directory in [('original', source), ('staged', output/'source'/name)]:
                    result = subprocess.run([str(RUST/'cargo'), 'build', '--offline', '--locked'], cwd=directory,
                        env=dict(env, CARGO_TARGET_DIR=str(self.base/(name+'-'+kind+'-target'))),
                        capture_output=True, text=True, timeout=90)
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((output/'source'/name/relative).is_dir())
                self.assertEqual(files, {p.relative_to(self.repo).as_posix(): builder.sha(p)
                                         for p in source.rglob('*') if p.is_file()})

    @unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('PUMP_SUPPORTED_TEST_TOOLS'),
                         'requires authenticated v1.53 SDK and pinned v1.52 objcopy')
    def test_full_sdk_builds_and_directory_drift_controls(self):
        output = self.base/'proof.json'
        result = subprocess.run([sys.executable, '-B', str(ROOT/'research/supported-directory-inputs-20261101/probe.py'),
            '--repo', str(ROOT), '--tools', os.environ['PUMP_SUPPORTED_TEST_TOOLS'], '--expect', 'fixed',
            '--output', str(output)], capture_output=True, text=True, timeout=240)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(output.read_text())
        self.assertEqual(len(record['rows']), 7)
        self.assertEqual(record['rows']['file_only']['plan_directories'], [])


if __name__ == '__main__':
    unittest.main()
