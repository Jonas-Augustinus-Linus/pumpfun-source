"""Exercise cache preparation against an isolated Cargo home without network access."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CargoHomeTests(unittest.TestCase):
    def test_path_only_lockfile_needs_no_registry_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / 'Cargo.lock'
            lock.write_text('version = 3\n[[package]]\nname = "local-only"\nversion = "1.0.0"\n', encoding='utf-8')
            output = root / 'output'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('prepare_locked_cargo_home.py')),
                                     '--lockfile', str(lock), '--output', str(output)],
                                    env={**os.environ, 'CARGO_HOME': str(root / 'absent-cargo-home')}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / 'cache-manifest.json').read_text())
            self.assertEqual(manifest['packages'], [])
            self.assertIsNone(manifest['registry_config_sha256'])
            self.assertEqual(manifest['lockfile_sha256'], hashlib.sha256(lock.read_bytes()).hexdigest())
            self.assertFalse((output / 'registry').exists())

    def test_supported_cache_namespaces_supply_configuration(self):
        for namespace in ('index.crates.io-1949cf8c6b5b557f', 'index.crates.io-6f17d22bba15001f'):
            with self.subTest(namespace=namespace):
                self.prepare_from_namespace(namespace)

    def test_mixed_case_package_indexes_use_lowercase_paths(self):
        # Cargo's index files use lowercase names and directory prefixes:
        # https://doc.rust-lang.org/cargo/reference/registry-index.html#index-files
        cases = [('A', '1/a'), ('Ab', '2/ab'), ('AbC', '3/a/abc'),
                 ('AbCd', 'ab/cd/abcd'), ('MixedCase', 'mi/xe/mixedcase')]
        for namespace in ('index.crates.io-1949cf8c6b5b557f', 'index.crates.io-6f17d22bba15001f'):
            for name, relative in cases:
                with self.subTest(namespace=namespace, name=name):
                    self.prepare_from_namespace(namespace, name, relative)

    def prepare_from_namespace(self, namespace, name='cache-probe', relative='ca/ch/cache-probe'):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / 'cargo-home'
            archive = home / 'registry/cache' / namespace / f'{name}-1.0.0.crate'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b'isolated archive')
            index = home / 'registry/index' / namespace / '.cache' / relative
            index.parent.mkdir(parents=True)
            index.write_bytes(b'isolated sparse index')
            config = home / 'registry/index' / namespace / 'config.json'
            config.write_text('{}', encoding='utf-8')
            lock = root / 'Cargo.lock'
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            lock.write_text(f'[[package]]\nname="{name}"\nversion="1.0.0"\n'
                            'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                            f'checksum="{digest}"\n', encoding='utf-8')
            output = root / 'output'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('prepare_locked_cargo_home.py')),
                                     '--lockfile', str(lock), '--output', str(output)],
                                    env={**os.environ, 'CARGO_HOME': str(home)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / 'cache-manifest.json').read_text())
            self.assertEqual(manifest['packages'][0]['package'], name)
            self.assertEqual(manifest['packages'][0]['archive_sha256'], digest)
            for target in ('index.crates.io-1949cf8c6b5b557f', 'index.crates.io-6f17d22bba15001f'):
                self.assertEqual((output / 'registry/cache' / target / archive.name).read_bytes(), archive.read_bytes())
                self.assertEqual((output / 'registry/index' / target / '.cache' / relative).read_bytes(), index.read_bytes())
                # Inspect stored spellings: exists/read_bytes can hide a wrong
                # case on case-insensitive filesystems.
                stored = {path.relative_to(output).as_posix() for path in output.rglob('*') if path.is_file()}
                self.assertIn(f'registry/index/{target}/.cache/{relative}', stored)
                self.assertIn(f'registry/cache/{target}/{name}-1.0.0.crate', stored)


if __name__ == '__main__':
    unittest.main()
