"""Verify retained artifacts, the 785-window inventory, and offline execution."""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile

if not __debug__:
    raise SystemExit("Run without -O")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def module(path):
    spec = importlib.util.spec_from_file_location("amm_group_slice_analysis", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-runtime", action="store_true")
    args = parser.parse_args()

    expected_files = {
        "README.md",
        "analysis.py",
        "build-provenance.json",
        "decoder-controls.json",
        "test_reachability.py",
        "verify.py",
        "artifacts/candidate-symbols.so.gz",
        "artifacts/candidate.so.gz",
    }
    actual_files = {str(path.relative_to(HERE)) for path in HERE.rglob("*") if path.is_file()}
    assert actual_files == expected_files, sorted(actual_files ^ expected_files)
    assert not any(path.is_symlink() for path in HERE.rglob("*"))

    expected_hashes = {
        "artifacts/candidate-symbols.so.gz": "8d599a955c2ed00d39647edc02a6b90634bfd1553286868706e393a3f9982179",
        "artifacts/candidate.so.gz": "1f25c51a89ed4c269dd7af1732c4a55dbc3fb908b6c9f5ecac69560cfe1026bd",
    }
    for name, sha256 in expected_hashes.items():
        assert digest(HERE / name) == sha256, name
    assert digest(ROOT / "programs/pump-amm/src/instructions/swap/multi_hop_swap.rs") == \
        "98e6623e2c34cba0df64000595e5985843497ebc02bb24c82b6fb7abbaf28caf"
    assert digest(ROOT / "scripts/pump_amm_multi_hop_differential.py") == \
        "f7fa73af1002cc570d2cd80c501671f32364300ccf03a17a7081320e81273b50"
    assert digest(ROOT / "research/amm-mint-fee-reader-recovery/analysis.py") == \
        "492b3fd6cb1f28e06c6a771c07339ae397dc8dc019aafdb71e5b047774c65a63"

    provenance = json.loads((HERE / "build-provenance.json").read_text())
    assert provenance["linux_v144"]["unstripped_sha256"] == provenance["linux_v144"]["repeat_unstripped_sha256"]
    assert provenance["strip"]["stripped_sha256"] == provenance["strip"]["repeat_stripped_sha256"]
    controls = json.loads((HERE / "decoder-controls.json").read_text())
    assert controls["target"]["bytes"] == 664
    assert controls["maintained_control"]["bytes"] == 656
    assert all(not control["matched"] for control in controls["controls_run"])

    comparison = module(HERE / "analysis.py").recompute()
    assert comparison["inventory"] == {
        "original_windows": 785,
        "baseline_normalized": 660,
        "candidate_normalized": 661,
        "baseline_raw": 159,
        "candidate_raw": 159,
        "new_normalized_windows": 1,
        "lost_normalized_windows": 0,
        "new_raw_windows": 0,
        "lost_raw_windows": 0,
    }
    target = comparison["target"]
    assert target["original_offset"] == 0x40100 and target["candidate_offset"] == 0x3B4F0
    assert target["bytes"] == 520 and target["normalized_equal"] and not target["raw_equal"]
    assert len(target["direct_calls"]) == 4
    assert all(call["normalized_equal"] for call in target["direct_calls"])
    assert len(target["relocations"]) == 7

    if not args.skip_runtime:
        with tempfile.TemporaryDirectory(prefix="amm-group-slice-") as temporary:
            temporary = Path(temporary)
            candidate = temporary / "candidate.so"
            candidate.write_bytes(gzip.decompress((HERE / "artifacts/candidate.so.gz").read_bytes()))
            output = temporary / "multi-hop.json"
            subprocess.run([
                sys.executable, "-B", str(ROOT / "scripts/pump_amm_multi_hop_differential.py"),
                "--candidate", str(candidate), "--output", str(output),
            ], cwd=ROOT, check=True)
            report = json.loads(output.read_text())
            assert report["original_sha256"] == "6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7"
            assert report["candidate_sha256"] == "7a300434dced61413bde10788594b427d5649563e0223efcf09e6b214aff7ad3"
            assert report["case_count"] == report["passed"] == 735
            assert report["mismatches"] == []

    runtime = "735 offline cases replayed" if not args.skip_runtime else "static checks only; runtime not verified"
    print(f"PASS: 661/785 normalized, 159 raw, one 520-byte gain, no losses; {runtime}")


if __name__ == "__main__":
    main()
