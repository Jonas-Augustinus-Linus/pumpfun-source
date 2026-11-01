"""Real disassembly must preserve scalar argument values, not treat them as pointers."""
import importlib.util
import os
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import fastbuild
from elf_symbols import function_symbols
from llvm_tools import objdump
from score import normalize, body, original_windows

LANE = Path(__file__).resolve().parents[1] / 'pump-main/lanes/callgraph-census/census.py'
spec = importlib.util.spec_from_file_location('argument_census', LANE)
census = importlib.util.module_from_spec(spec)
spec.loader.exec_module(census)


class CensusArgumentByteTests(unittest.TestCase):
    def test_captured_instruction_bytes_classify_scalar_and_pointer(self):
        # Predecoded rows keep this regression active on CI without objdump.
        # Verify each row against the retained instruction bytes before using it.
        path = Path(__file__).resolve().parents[2] / 'evidence/original/pump/deployed.so'
        scalar_start, scalar_at, scalar_call = 0x1afaf0, 0x1afd68, 0x1afd78
        image = census.Image(path, {scalar_start: (scalar_call + 8 - scalar_start, [])})
        raw = body(image.blob, image.secs, scalar_at, 8)
        self.assertEqual((raw[0], raw[1] & 15, struct.unpack_from('<i', raw, 4)[0]), (0xb7, 3, 0x10001))
        self.assertIn(scalar_call, dict(image.calls(scalar_start)))
        image._txt[scalar_start] = {scalar_at: 'mov64 r3, 0x10001', scalar_call: 'call 0x0'}
        self.assertEqual(census.arg_setup(image, scalar_start, [scalar_call])[scalar_call], ['mov64 r3, 0x10001'])
        image._txt[scalar_start] = {scalar_at: 'r3 = 0x10001', scalar_call: 'call 0x0'}
        self.assertEqual(census.arg_setup(image, scalar_start, [scalar_call])[scalar_call], ['mov64 r3, 0x10001'])

        pointer_start, pointer_at, pointer_call = 0x340, 0x428, 0x460
        image = census.Image(path, {pointer_start: (0x878 - pointer_start, [])})
        raw = body(image.blob, image.secs, pointer_at, 16)
        self.assertEqual((raw[0], raw[1] & 15), (0x18, 1))
        value = struct.unpack_from('<I', raw, 4)[0] | (struct.unpack_from('<I', raw, 12)[0] << 32)
        self.assertNotEqual(raw, normalize(raw, pointer_at, image.secs))
        self.assertIn(pointer_call, dict(image.calls(pointer_start)))
        image._txt[pointer_start] = {pointer_at: f'lddw r1, {value:#x}', pointer_call: 'call 0x0'}
        self.assertEqual(census.arg_setup(image, pointer_start, [pointer_call])[pointer_call], ['lddw r1, ADDR'])
        image._txt[pointer_start] = {pointer_at: f'r1 = {value:#x} ll', pointer_call: 'call 0x0'}
        self.assertEqual(census.arg_setup(image, pointer_start, [pointer_call])[pointer_call], ['lddw r1, ADDR'])
        self.assertEqual(census.argument_text(bytes(8), 'if r1 == r2 goto +0x1'), '')


class CensusArgumentTests(unittest.TestCase):
    def setUp(self):
        try:
            objdump()
        except FileNotFoundError as error:
            self.skipTest(str(error))

    def test_retained_pump_scalar_argument_is_not_an_address(self):
        path = Path(__file__).resolve().parents[2] / 'evidence/original/pump/deployed.so'
        # Real captured window and internal call; never modify captured instructions.
        start, call = 0x1afaf0, 0x1afd78
        window = next(w for w in original_windows() if w["start"] == start)
        image = census.Image(path, {start: (window["bytes"], [])})
        self.assertIn(call, dict(image.calls(start)))
        args = census.arg_setup(image, start, [call])[call]
        self.assertIn('mov64 r3, 0x10001', args)

    def test_retained_section_pointer_arguments_still_mask(self):
        path = Path(__file__).resolve().parents[2] / 'evidence/original/pump/deployed.so'
        image = census.Image(path, {0x340: (0x878 - 0x340, [])})
        raw = body(image.blob, image.secs, 0x428, 16)
        self.assertEqual(raw[0], 0x18)
        self.assertNotEqual(raw, normalize(raw, 0x428, image.secs))
        args = census.arg_setup(image, 0x340, [0x460])[0x460]
        self.assertIn('lddw r1, ADDR', args)
        self.assertIn('mov64 r2, 0x37', args)

    @unittest.skipUnless(os.environ.get('PUMP_BUILD_TEST_SDK'), 'requires the explicit v1.44 SDK')
    def test_real_sbf_call_arguments_keep_mov_and_lddw_constants(self):
        sdk = Path(os.environ['PUMP_BUILD_TEST_SDK']).resolve()
        with tempfile.TemporaryDirectory(prefix='pump-census-arguments-') as temporary:
            root = Path(temporary)
            source = root / 'source'
            (source / 'src').mkdir(parents=True)
            (source / 'Cargo.toml').write_text(
                '[package]\nname="pump-recovered"\nversion="0.1.0"\nedition="2021"\n'
                '[lib]\ncrate-type=["cdylib"]\n'
                '[profile.release]\npanic="abort"\nlto=false\ncodegen-units=1\n[workspace]\n')
            (source / 'Cargo.lock').write_text('version=3\n[[package]]\nname="pump-recovered"\nversion="0.1.0"\n')
            code = '''#![no_std]
static DATA: [u8; 8] = *b"evidence";
#[no_mangle] #[inline(never)]
pub unsafe extern "C" fn consume(out: *mut u8, data: *const u8, amount: u64) -> u64 {
    core::ptr::write_volatile(out, core::ptr::read_volatile(data));
    core::ptr::write_volatile(out.add(1) as *mut u64, amount);
    amount
}
#[no_mangle] pub extern "C" fn entrypoint(input: *mut u8) -> u64 {
    unsafe { consume(input, DATA.as_ptr(), AMOUNT) }
}
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
'''
            recipe = {'triple': 'sbf-solana-solana', 'rustc': sdk / 'rust/bin/rustc', 'template': root / 'no-template'}
            arguments = []
            with patch.object(fastbuild, 'SDK', sdk), patch.dict(fastbuild.RECIPES, {'identity': recipe}), \
                 patch.object(Path, 'home', return_value=root / 'home'):
                for amount in (1000000, 2000000, 0x123456789ab, 0x23456789abc):
                    (source / 'src/lib.rs').write_text(code.replace('AMOUNT', str(amount)))
                    result = fastbuild.build(source, root / 'work', root / 'out', recipe='identity', quiet=True)
                    self.assertTrue(result['ok'], (root / 'out/build.log').read_text())
                    path = root / 'out/unstripped.so'
                    functions = function_symbols(path.read_bytes())
                    start, size, _ = next(f for f in functions if f[2] == 'entrypoint')
                    image = census.Image(path, {start: (size, ['entrypoint'])})
                    calls = image.calls(start)
                    self.assertEqual(len(calls), 1, image.text(start))
                    args = census.arg_setup(image, start, [calls[0][0]])[calls[0][0]]
                    arguments.append(args)
            self.assertNotEqual(arguments[0], arguments[1], 'different real scalar arguments were hidden as ADDR')
            self.assertNotEqual(arguments[2], arguments[3])
            for amount, args in zip((1000000, 2000000, 0x123456789ab, 0x23456789abc), arguments):
                self.assertTrue(any(hex(amount) in arg for arg in args), args)


if __name__ == '__main__':
    unittest.main()
