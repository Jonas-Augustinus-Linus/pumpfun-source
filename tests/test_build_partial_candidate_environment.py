"""The partial-candidate build must not inherit ambient recipe overrides.

build_partial_candidate.py records the environment of the recipe it certifies.
Before the fix it copied the whole process environment into the build and
recorded only CARGO_TARGET_DIR and RUSTUP_HOME, so ambient RUSTFLAGS, profile
overrides and target rustflags changed the compiled artifact while the
recorded environment stayed identical. The supported adapter rejects the
same family in validate_environment; the historical helper drops it and
records only the dropped names.

The cargo/rustup/rustc executables here are stubs: the claim under test is
which environment reaches the build process and what the helper records,
not compilation itself.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_partial_candidate.py"
POISON = {
    "RUSTFLAGS": "-C force-frame-pointers=yes",
    "CARGO_PROFILE_RELEASE_DEBUG": "true",
    "CARGO_TARGET_SBPF_SOLANA_SOLANA_RUSTFLAGS": "--cfg ambient_leak",
}

CARGO_STUB = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args and args[0] == 'locate-project':
    print(os.environ['STUB_WORKSPACE_TOML']); sys.exit(0)
if args and args[0] == 'build-sbf':
    if '--version' in args:
        print('cargo-build-sbf 1.44.0'); sys.exit(0)
    out = Path(args[args.index('--sbf-out-dir') + 1]); out.mkdir(parents=True, exist_ok=True)
    (out / 'pump_fees.so').write_bytes(b'STUB-ARTIFACT-BYTES')
    Path(os.environ['STUB_ENV_DUMP']).write_text(json.dumps(dict(os.environ), sort_keys=True))
    sys.exit(0)
sys.exit(1)
"""


class BuildPartialCandidateEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.bin = base / "bin"
        (self.bin / "sdk" / "sbf").mkdir(parents=True)
        (self.bin / "sdk" / "sbf" / "placeholder.txt").write_text("sbf\n")
        self._write(self.bin / "cargo", CARGO_STUB)
        self._write(self.bin / "cargo-build-sbf", "#!/bin/sh\necho 'cargo-build-sbf 1.44.0'\n")
        self._write(self.bin / "rustup", "#!/bin/sh\necho '1.81.0-x86_64-unknown-linux-gnu (default)'\n")
        self.home = base / "home"
        rustc = self.home / ".cache" / "solana" / "v1.44" / "platform-tools" / "rust" / "bin" / "rustc"
        self._write(rustc, "#!/bin/sh\necho 'rustc 1.79.0 (0000000 2024-01-01)'\n")
        self.rustup_home = base / "rustup-home"
        (self.rustup_home / "toolchains" / "1.81.0-x86_64-unknown-linux-gnu").mkdir(parents=True)
        self.dump = base / "build-env.json"
        self.output = base / "out"

    @staticmethod
    def _write(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o755)

    def run_helper(self, extra_env):
        env = {
            "PATH": str(self.bin) + ":/usr/bin:/bin",
            "HOME": str(self.home),
            "RUSTUP_HOME": str(self.rustup_home),
            "STUB_ENV_DUMP": str(self.dump),
            "STUB_WORKSPACE_TOML": str(ROOT / "Cargo.toml"),
            **extra_env,
        }
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT),
             "--manifest", str(ROOT / "programs" / "pump-fees" / "Cargo.toml"),
             "--program", "pump_fees", "--artifact-name", "pump_fees.so",
             "--tools-version", "v1.44", "--output", str(self.output)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        build_env = json.loads(self.dump.read_text())
        attempt = json.loads((self.output / "build-attempt.json").read_text())
        return build_env, attempt

    def test_ambient_overrides_never_reach_the_build(self):
        build_env, attempt = self.run_helper(POISON)
        for name in POISON:
            self.assertNotIn(name, build_env)
        recorded = attempt["environment"]
        self.assertEqual(recorded["CARGO_TARGET_DIR"], "<output>/target")
        self.assertEqual(recorded["RUSTUP_HOME"], "<output>/rustup")
        self.assertEqual(recorded["scrubbed_environment"], sorted(POISON))

    def test_override_values_are_not_recorded(self):
        _, attempt = self.run_helper(POISON)
        text = json.dumps(attempt)
        self.assertNotIn("force-frame-pointers", text)
        self.assertNotIn("ambient_leak", text)

    def test_clean_environment_records_no_scrub(self):
        build_env, attempt = self.run_helper({})
        for name in POISON:
            self.assertNotIn(name, build_env)
        self.assertNotIn("scrubbed_environment", attempt["environment"])


if __name__ == "__main__":
    unittest.main()
