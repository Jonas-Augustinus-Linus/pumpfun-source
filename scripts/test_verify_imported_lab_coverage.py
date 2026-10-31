#!/usr/bin/env python3
"""The imported-lab manifest must cover exactly the files the verifier uses.

scripts/verify_imported_lab.py hash-checked only the files listed in
research/import-manifest.json, then executed the snapshot's verifier scripts
and trusted the docs commit named by the snapshot's program-manifest. When
the executed scripts, the program-manifest, or an extra shadowing module
were absent from the manifest, replacing them changed nothing the verifier
checked: a lab whose honest verifiers fail could be flipped to a published
report claiming all_import_hashes_verified and saved_receipt_verifiers_passed
by rewriting only unlisted files. The verifier now pins the manifest to the
exact snapshot file set before checking any hash.
"""

from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
SCRIPT = "verify_imported_lab.py"
# Sibling modules the script imports from scripts/ (atomic publication helpers).
HELPERS = ["deep_disassembly.py", "window_elf_reader.py", "analyze.py"]
VERIFIERS = [
    "pump_fun_verify_offline",
    "pump_fun_admin_surfpool_verify",
    "pump_fun_amm_v2_surfpool_verify",
    "pump_fun_curve_fresh_surfpool_verify",
    "pump_fun_curve_migration_surfpool_verify",
    "pump_fun_post_migration_amm_surfpool_verify",
    "pump_fun_fees_withdraw_surfpool_verify",
]
PASS = "import sys\nsys.exit(0)\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build_tree(root, omit=(), extra=None, tamper_listed_script=False):
    """Fixture import whose manifest lists every snapshot file, minus `omit`.

    `extra` maps an additional snapshot-relative path to its bytes; those
    files are created on disk but never listed in the manifest.
    """
    snapshot = root / "research" / "imported-lab"
    (snapshot / "scripts").mkdir(parents=True)
    (snapshot / "inputs" / "pump_fun").mkdir(parents=True)
    (snapshot / "analysis" / "pump_fun").mkdir(parents=True)
    (root / "scripts").mkdir(exist_ok=True)
    for name in (SCRIPT, *HELPERS):
        shutil.copy2(SCRIPTS / name, root / "scripts" / name)
    for name in VERIFIERS:
        (snapshot / "scripts" / f"{name}.py").write_text(PASS, encoding="utf-8")
    blob = b"fake-program-bytes"
    for name in ("pump", "pump_amm", "pump_fees"):
        (snapshot / f"inputs/pump_fun/{name}.so").write_bytes(blob)
        original = root / "evidence" / "original" / name
        original.mkdir(parents=True)
        (original / "deployed.so").write_bytes(blob)
    (snapshot / "notes.txt").write_bytes(b"lab notes")
    docs = root / "docsrepo"
    docs.mkdir()
    subprocess.run(["git", "init", "-q", str(docs)], check=True)
    subprocess.run(["git", "-C", str(docs), "config", "user.email", "t@t"],
                   check=True)
    subprocess.run(["git", "-C", str(docs), "config", "user.name", "t"],
                   check=True)
    (docs / "README").write_text("docs\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(docs), "add", "."], check=True)
    subprocess.run(["git", "-C", str(docs), "commit", "-qm", "docs"],
                   check=True)
    commit = subprocess.run(
        ["git", "-C", str(docs), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()
    (snapshot / "analysis" / "pump_fun" / "program-manifest.json").write_text(
        json.dumps({"official_docs_commit": commit}), encoding="utf-8")
    if extra:
        for relative, data in extra.items():
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    unlisted = set(omit) | set(extra or ())
    files = []
    for path in sorted(p for p in snapshot.rglob("*") if p.is_file()):
        relative = path.relative_to(snapshot).as_posix()
        if relative in unlisted:
            continue
        data = path.read_bytes()
        if tamper_listed_script and relative == "scripts/pump_fun_verify_offline.py":
            data = b"import sys\nsys.exit(1)\n"
        files.append({"path": relative, "sha256": sha(data)})
    (root / "research" / "import-manifest.json").write_text(
        json.dumps({"commit": "abc123", "files": files}), encoding="utf-8")
    return docs


def run_script(root, docs, output):
    return subprocess.run(
        [sys.executable, "-B", str(root / "scripts" / SCRIPT),
         "--docs-checkout", str(docs), "--output", str(output)],
        capture_output=True, text=True, check=False)


class ImportedLabCoverageTests(unittest.TestCase):
    def build_and_run(self, temporary, **kwargs):
        root = Path(temporary) / "tree"
        root.mkdir()
        docs = build_tree(root, **kwargs)
        return root, run_script(root, docs, root / "out")

    def test_complete_manifest_passes(self):
        with tempfile.TemporaryDirectory(prefix="imported-lab-cov-") as temporary:
            root, result = self.build_and_run(temporary)
            self.assertEqual(result.returncode, 0,
                             result.stdout[-500:] + result.stderr[-500:])
            report = json.loads(
                (root / "out" / "integration-verification.json").read_text(
                    encoding="utf-8"))
            self.assertTrue(report["all_import_hashes_verified"])
            self.assertTrue(report["saved_receipt_verifiers_passed"])

    def test_unlisted_executed_script_fails(self):
        with tempfile.TemporaryDirectory(prefix="imported-lab-cov-") as temporary:
            root, result = self.build_and_run(
                temporary, omit={"scripts/pump_fun_verify_offline.py"})
            self.assertNotEqual(result.returncode, 0, result.stdout[-500:])
            self.assertIn("pump_fun_verify_offline", result.stderr)
            self.assertFalse((root / "out").exists())

    def test_unlisted_program_manifest_fails(self):
        with tempfile.TemporaryDirectory(prefix="imported-lab-cov-") as temporary:
            root, result = self.build_and_run(
                temporary, omit={"analysis/pump_fun/program-manifest.json"})
            self.assertNotEqual(result.returncode, 0, result.stdout[-500:])
            self.assertIn("program-manifest", result.stderr)
            self.assertFalse((root / "out").exists())

    def test_extra_unlisted_file_fails(self):
        with tempfile.TemporaryDirectory(prefix="imported-lab-cov-") as temporary:
            root, result = self.build_and_run(
                temporary,
                extra={"scripts/json.py": b"# shadow\n"})
            self.assertNotEqual(result.returncode, 0, result.stdout[-500:])
            self.assertIn("json.py", result.stderr)
            self.assertFalse((root / "out").exists())

    def test_tampered_listed_script_still_fails(self):
        with tempfile.TemporaryDirectory(prefix="imported-lab-cov-") as temporary:
            root, result = self.build_and_run(
                temporary, tamper_listed_script=True)
            self.assertNotEqual(result.returncode, 0, result.stdout[-500:])
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
