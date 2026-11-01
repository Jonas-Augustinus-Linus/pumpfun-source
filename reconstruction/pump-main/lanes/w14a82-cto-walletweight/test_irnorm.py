import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / 'tools' / 'irnorm.py'
SYM = '_ZN14pump_recovered9admin_cto7execute17h1638ff339e793c173E'


def module(first, alloca_size):
    caller = '\n'.join([
        'define i32 @caller() #0 {',
        'entry:',
        f'  %r = call i32 @{SYM}(ptr null)',
        '  ret i32 %r',
        '}',
        '',
    ])
    definition = '\n'.join([
        f'define i32 @{SYM}(ptr %0) #0 {{',
        'entry:',
        f'  %x = alloca [{alloca_size} x i8], align 8',
        '  ret i32 0',
        '}',
        '',
    ])
    parts = [caller, definition] if first == 'caller' else [definition, caller]
    return '\n'.join(parts)


class IrnormBodyTests(unittest.TestCase):
    """The diff must canonicalise execute's definition, not the first function
    that mentions its name."""

    def diff(self, a_text, b_text):
        with tempfile.TemporaryDirectory() as d:
            a = Path(d) / 'a.ll'
            b = Path(d) / 'b.ll'
            a.write_text(a_text)
            b.write_text(b_text)
            r = subprocess.run([sys.executable, str(TOOL), str(a), str(b)],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_caller_first_modules_diff_the_definition(self):
        out = self.diff(module('caller', 8), module('caller', 16))
        self.assertIn('alloca [16 x i8]', out)
        self.assertIn('alloca [8 x i8]', out)

    def test_definition_first_modules_keep_their_diff(self):
        out = self.diff(module('definition', 8), module('definition', 16))
        self.assertIn('alloca [16 x i8]', out)

    def test_identical_caller_first_modules_have_no_diff(self):
        out = self.diff(module('caller', 8), module('caller', 8))
        self.assertEqual(out, '')


if __name__ == '__main__':
    unittest.main()
