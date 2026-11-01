"""The verified build report must bind the tool bytes that actually ran.

pump_build_verified.py hashed the SDK tools when it assembled its record,
then executed those paths for the whole build and the strip step. Sources
and target libraries were re-verified after the build; the executables
were not. Replacing rustc at its path mid-build published a comparison
whose tool_sha256 names a compiler that did not produce the artifact.

These tests run the real CLI against a stub SDK. The stub cargo invokes
rustc, optionally replaces it (an SDK update landing mid-build), invokes
the replacement, and emits the target artifact.
"""

import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "pump_build_verified.py"

RUSTC_A = "#!/bin/sh\necho 'rustc 1.75.0-stubA (aaaaaaaa)'\n"
RUSTC_B = "#!/bin/sh\necho 'rustc 1.75.0-stubB (bbbbbbbb)'\n"

CARGO_TEMPLATE = """#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess

rustc = Path(os.environ["RUSTC"])
print(subprocess.run([str(rustc), "--version"], capture_output=True, text=True).stdout.strip())
{swap}
print(subprocess.run([str(rustc), "--version"], capture_output=True, text=True).stdout.strip())
target = Path(os.environ["CARGO_TARGET_DIR"]) / "sbf-solana-solana" / "release"
target.mkdir(parents=True, exist_ok=True)
(target / "pump_recovered.so").write_bytes(b"stub built artifact\\n" * 64)
print("stub cargo build finished")
"""

SWAP = """rustc.write_text("#!/bin/sh\\necho 'rustc 1.75.0-stubB (bbbbbbbb)'\\n")
rustc.chmod(0o755)"""

OBJCOPY = """#!/usr/bin/env python3
import shutil
import sys

shutil.copyfile(sys.argv[-2], sys.argv[-1])
"""


def put(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def make_sdk(base, swap):
    sdk = base / "sdk"
    put(sdk / "rust/bin/rustc", RUSTC_A)
    put(sdk / "rust/bin/cargo", CARGO_TEMPLATE.format(swap=SWAP if swap else ""))
    put(sdk / "llvm/bin/llvm-objcopy", OBJCOPY)
    for name in ("clang", "llvm-ar", "llvm-objdump"):
        put(sdk / f"llvm/bin/{name}", "#!/bin/sh\nexit 0\n")
    libdir = sdk / "rust/lib/rustlib/sbf-solana-solana/lib"
    libdir.mkdir(parents=True)
    (libdir / "libdummy.rlib").write_bytes(b"dummy target library\n")
    (base / "registry").mkdir()
    return sdk


def run_builder(base, swap):
    sdk = make_sdk(base, swap)
    output = base / "out"
    run = subprocess.run(
        [
            sys.executable, "-B", str(BUILDER),
            "--sdk", str(sdk),
            "--registry-home", str(base / "registry"),
            "--output", str(output),
        ],
        cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    return run, sdk, output


class BuildVerifiedToolBindingTests(unittest.TestCase):
    def test_unchanged_tools_publish_a_matching_tool_binding(self):
        with tempfile.TemporaryDirectory(prefix="pump-build-tools-") as temporary:
            run, sdk, output = run_builder(Path(temporary), swap=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads((output / "build-comparison.json").read_text())
            rustc = sdk / "rust/bin/rustc"
            self.assertEqual(
                report["tool_sha256"]["rustc"],
                hashlib.sha256(rustc.read_bytes()).hexdigest(),
            )
            self.assertTrue(report["tools_unchanged"])

    def test_tool_replaced_mid_build_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pump-build-tools-") as temporary:
            run, sdk, output = run_builder(Path(temporary), swap=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn(
                "selected SDK tools changed during compilation", run.stderr
            )
            self.assertFalse((output / "build-comparison.json").exists())


if __name__ == "__main__":
    unittest.main()
