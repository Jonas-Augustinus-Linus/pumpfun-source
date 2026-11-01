"""The verify_current report path must not replace an input it compares.

The tool is driven end-to-end in a subprocess against a synthetic harness
(same module-substitution approach as test_replay.py): the fake score/win
modules expose one window and one candidate function whose body carries
exactly the 22 self-calls the tool requires, so a separate --output still
publishes a passing report. The destination guard under test and the
original-path resolver are the real harness modules, copied verbatim.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
HARNESS = ROOT / 'reconstruction/harness'
TOOL = HERE / 'verify_current.py'

FAKE_SCORE = '''\
"""One window, one candidate function, a fixed 22-self-call body."""
import struct
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / 'base'
OBJDUMP = ''

# A filler slot, then 22 slots that each call the function's own start
# (target = start + off + 8 + imm * 8 with imm = -(off + 8) // 8).
BODY = b'\\x00' * 8 + b''.join(
    bytes([0x85, 0x10, 0, 0]) + struct.pack('<i', -(off + 8) // 8)
    for off in range(8, 8 * 23, 8))


def sections(blob):
    return {}


def original_windows():
    return [{'start': 0x83c00, 'bytes': len(BODY), 'raw': BODY, 'norm': BODY}]


def body(blob, secs, start, size):
    return BODY[:size]


def normalize(raw, start, secs):
    return raw


def candidate_functions(path):
    return [(0x1000, len(BODY), 'target')]


def score(path):
    return {0x1000: {'normalized': True, 'raw': False}}
'''

FAKE_WIN = '''\
"""The one fake symbol demangles to the target name the tool requires."""

OBJDUMP = ''


def demangle(name):
    return 'pump_recovered::trade::v3_execute_buy'


def insns(raw, start, secs):
    return [(start, 8, 'insn')]
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class VerifyCurrentOutputPreservationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        root = Path(self.scratch.name)
        self.repo = root / 'repo'
        harness = self.repo / 'reconstruction/harness'
        harness.mkdir(parents=True)
        (harness / 'score.py').write_text(FAKE_SCORE, encoding='utf-8')
        (harness / 'win.py').write_text(FAKE_WIN, encoding='utf-8')
        for name in ('score_admission.py', 'original_input.py'):
            shutil.copyfile(HARNESS / name, harness / name)
        base = self.repo / 'reconstruction/base'
        base.mkdir(parents=True)
        (base / 'original.so').write_bytes(b'original-bytes')
        (base / 'functions.tsv').write_bytes(b'inventory-bytes')
        self.control = root / 'control.so'
        self.control.write_bytes(b'control-bytes')
        self.candidate = root / 'candidate.so'
        self.candidate.write_bytes(b'candidate-bytes')
        self.objdump = root / 'objdump'
        self.objdump.write_bytes(b'objdump-bytes')
        self.watched = [self.control, self.candidate, self.objdump,
                        base / 'original.so', base / 'functions.tsv']
        self.before = {path: digest(path) for path in self.watched}
        self.base = base

    def tearDown(self):
        self.scratch.cleanup()

    def assert_inputs_unchanged(self):
        for path, sha in self.before.items():
            self.assertEqual(digest(path), sha, f'{path.name} input was overwritten')

    def run_tool(self, output):
        return subprocess.run(
            [sys.executable, '-B', str(TOOL), '--repo', str(self.repo),
             '--control', str(self.control), '--candidate', str(self.candidate),
             '--objdump', str(self.objdump), '--output', str(output)],
            capture_output=True, text=True, timeout=300)

    def exercise_refusal(self, output):
        result = self.run_tool(output)
        self.assertEqual(result.returncode, 2, result.stderr[-600:])
        self.assertIn('report destination aliases an input', result.stderr)
        self.assert_inputs_unchanged()

    def test_output_cannot_replace_the_control(self):
        self.exercise_refusal(self.control)

    def test_output_cannot_replace_the_candidate(self):
        self.exercise_refusal(self.candidate)

    def test_output_cannot_replace_the_shared_original(self):
        self.exercise_refusal(self.base / 'original.so')

    def test_output_cannot_replace_the_window_inventory(self):
        self.exercise_refusal(self.base / 'functions.tsv')

    def test_output_cannot_replace_the_declared_objdump(self):
        self.exercise_refusal(self.objdump)

    def test_separate_output_still_publishes(self):
        report = Path(self.scratch.name) / 'report.json'
        result = self.run_tool(report)
        self.assertEqual(result.returncode, 0, result.stderr[-600:])
        self.assertTrue(json.loads(result.stdout)['checks_passed'])
        published = json.loads(report.read_text(encoding='utf-8'))
        self.assertIn('elf_sha256', published['control'])
        self.assert_inputs_unchanged()


if __name__ == '__main__':
    unittest.main()
