"""A paired build must not supply the scorer code that judges it.

``score.py`` imports ``elf_symbols`` inside ``candidate_functions`` and
``instruction_stream`` inside ``_window_rows``, so a pair process first loaded
those readers while scoring, after both crate builds had finished. A build
script that rewrote a reader therefore ran its own code inside the pair, and it
could restore the file so the post-build digest recheck still matched — the pair
then reported on windows produced by the build.

The harness is copied so the build stub can rewrite a module for real, and the
pair runs in a child process so that module is not already imported.
"""

from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_elf_symbols import fixture


HARNESS = Path(__file__).resolve().parent
DRIVER = r'''
import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

harness, root = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(harness))
import build_score_pair as pair

MARKER = root / 'forged-reader-ran'
ORIGINAL = (harness / 'elf_symbols.py').read_text()
FORGED = f"""
from pathlib import Path
Path({str(MARKER)!r}).write_text('ran')
Path({str(harness / 'elf_symbols.py')!r}).write_text({ORIGINAL!r})
def function_symbols(blob):
    return []
"""


def copy_original_inputs(base, destination):
    (destination / 'original.so').write_bytes(b'original image')
    (destination / 'functions.tsv').write_text('broken\t0\n')


calls = 0


def build(source, work, output, quiet=True, recipe=None, timeout=None):
    # The first build plants the reader and its self-restore; the second puts
    # the original file back, so the pair's post-build digest recheck matches.
    global calls
    calls += 1
    (harness / 'elf_symbols.py').write_text(FORGED if calls == 1 else ORIGINAL)
    output.mkdir(parents=True, exist_ok=True)
    image = (root / 'unstripped.so').read_bytes()
    (output / 'unstripped.so').write_bytes(image)
    return {'ok': True, 'runtime_valid': True, 'stack_warnings': [],
            'unstripped_sha256': hashlib.sha256(image).hexdigest()}


seen = []


def score(path, digest):
    # The lazy import score.candidate_functions performs, at scoring time.
    from elf_symbols import function_symbols
    windows = {0: {'bytes': 8, 'normalized': bool(function_symbols(Path(path).read_bytes())),
                   'raw': False}}
    seen.append(windows)
    return windows


receipt = {'revision': 'fixture', 'files': {}, 'sha256': 'fixture'}
with patch.object(pair, 'source_receipt', return_value=receipt), \
        patch.object(pair, 'copy_original_inputs', side_effect=copy_original_inputs), \
        patch.object(pair.fastbuild, 'build', side_effect=build), \
        patch.object(pair.score, 'score', side_effect=score):
    try:
        code = pair.run_pair(root / 'base', root / 'candidate', root / 'out',
                             root / 'sdk', root / 'hybrid')
    except ValueError as error:
        print(f'refused: {error}')
        code = 2
print(json.dumps({'code': code, 'marker': MARKER.exists(),
                  'candidate_windows': seen[-1] if seen else None}))
'''


class PairScorerModuleTests(unittest.TestCase):
    def test_a_build_cannot_supply_the_reader_it_is_scored_with(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = root / 'harness'
            harness.mkdir()
            for path in HARNESS.glob('*'):
                if path.is_file() and not path.name.startswith('test_'):
                    shutil.copy2(path, harness / path.name)
            for name in ('base', 'candidate'):
                (root / name).mkdir()
            (root / 'toolchain').mkdir()
            (root / 'toolchain/v1.44-macos-inventory.json').write_text('{}\n')
            (root / 'unstripped.so').write_bytes(bytes(fixture()))
            for name in ('sdk/llvm/bin/llvm-objdump', 'sdk/llvm/bin/llvm-objcopy', 'sdk/llvm/bin/clang',
                         'sdk/rust/bin/cargo', 'hybrid/rust/bin/rustc'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'tool fixture')
            driver = root / 'driver.py'
            driver.write_text(DRIVER)

            run = subprocess.run([sys.executable, '-B', str(driver), str(harness), str(root)],
                                 capture_output=True, text=True, timeout=120)

            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            outcome = json.loads(run.stdout.strip().splitlines()[-1])
            self.assertFalse(outcome['marker'],
                             'the module a build rewrote ran inside the pair')
            self.assertTrue(outcome['candidate_windows']['0']['normalized'],
                            'the candidate was scored with a reader the build supplied')


if __name__ == '__main__':
    unittest.main()
