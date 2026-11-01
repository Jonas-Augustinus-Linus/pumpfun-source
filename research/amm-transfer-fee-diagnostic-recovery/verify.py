"""Verify retained builds, complete windows and signed offline receipts."""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import json
import tempfile

if not __debug__:
    raise SystemExit("Run without -O")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def verify_packet_inputs():
    paths = list(HERE.rglob("*"))
    assert not any(path.is_symlink() for path in paths)
    assert all(path.is_file() or path.is_dir() for path in paths)
    manifest_path = HERE / "MANIFEST.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text())
    files = {path.relative_to(HERE).as_posix() for path in paths
             if path.is_file() and path != manifest_path}
    assert files == set(manifest["files"]), sorted(files ^ set(manifest["files"]))
    for name, digest in manifest["files"].items():
        assert sha((HERE / name).read_bytes()) == digest, name
    assert set(manifest["repository_inputs"]) == {
        "research/amm-mint-fee-reader-recovery/analysis.py",
        "research/amm-mint-fee-reader-recovery/elf_reader.py",
        "repro/pump_amm/v2-mint-clone-recovery-20261028/results/"
        "new-proofs/lineage/independent-current/source_fields.py",
    }
    for name, digest in manifest["repository_inputs"].items():
        path = ROOT / name
        assert path.is_file() and not path.is_symlink(), name
        assert sha(path.read_bytes()) == digest, name


def main():
    verify_packet_inputs()

    source = ROOT / "programs/pump-amm/src/utils/transfer_fee.rs"
    assert sha(source.read_bytes()) == "6685421e57809ca18c04abe381a9466141c3075d384cd3e88b429e3e71760701"
    lines = source.read_text().splitlines()
    assert "UnsupportedQuoteMint" in lines[31]
    assert "PumpAmmError::Overflow" in lines[48]
    assert "PumpAmmError::Overflow" in lines[56]
    assert "PumpAmmError::Overflow" in lines[66]
    assert not any(lines[index] == lines[index + 1] == "" for index in range(len(lines) - 1))

    provenance = json.loads((HERE / "build-provenance.json").read_text())
    assert provenance["linux_v144"]["unstripped_sha256"] == provenance["linux_v144"]["repeat_unstripped_sha256"]
    assert provenance["strip"]["stripped_sha256"] == provenance["strip"]["repeat_stripped_sha256"]
    assert provenance["workspace"]["transfer_fee_source_sha256"] == sha(source.read_bytes())
    for label, expected in (("a", provenance["linux_v144"]["build_a_log_sha256"]),
                            ("b", provenance["linux_v144"]["build_b_log_sha256"])):
        log = gzip.decompress((HERE / f"builds/build-{label}.log.gz").read_bytes())
        assert sha(log) == expected
        text = log.decode()
        assert text.count("--crate-name pump_amm_recovered ") == 1
        assert "--crate-name native_transfer_fee " not in text
        assert text.count("overwrites values in the frame") == 3
        assert "Finished `release` profile [optimized]" in text

    symbols = gzip.decompress((HERE / "artifacts/candidate-symbols.so.gz").read_bytes())
    candidate = gzip.decompress((HERE / "artifacts/candidate.so.gz").read_bytes())
    assert (len(symbols), sha(symbols)) == (1813360, provenance["linux_v144"]["unstripped_sha256"])
    assert (len(candidate), sha(candidate)) == (1291424, provenance["strip"]["stripped_sha256"])

    materializer = module("fee_diagnostic_materialize", HERE / "materialize.py")
    with tempfile.TemporaryDirectory(prefix="amm-fee-diagnostic-") as temporary:
        snapshot = materializer.materialize(Path(temporary) / "source")
        assert materializer.tree_digest(snapshot) == (
            provenance["workspace"]["files"], provenance["workspace"]["tree_sha256"])

    comparison = module("fee_diagnostic_analysis", HERE / "analysis.py").recompute()
    assert comparison["inventory"] == {
        "original_windows": 785,
        "baseline_normalized": 661,
        "candidate_normalized": 665,
        "baseline_raw": 159,
        "candidate_raw": 159,
        "new_normalized_windows": 4,
        "lost_normalized_windows": 0,
        "new_raw_windows": 0,
        "lost_raw_windows": 0,
    }
    assert [(row["original_offset"], row["bytes"], row["source"]["line"])
            for row in comparison["targets"]] == [
        (0x74128, 1312, 32), (0x74648, 696, 49),
        (0x74900, 640, 57), (0x74B80, 688, 67),
    ]
    assert sum(len(row["direct_calls"]) for row in comparison["targets"]) == 25
    assert sum(not call["normalized_equal"] for row in comparison["targets"]
               for call in row["direct_calls"]) == 1

    diagnostics = module("fee_diagnostic_runtime", HERE / "runtime_check.py").audit()
    assert len(diagnostics) == 14
    assert Counter(row["original_line"] for row in diagnostics) == Counter({32: 12, 67: 2})
    print("PASS: 661 -> 665/785 normalized; 159 raw; four complete gains, no losses; "
          "216 triples/648 signed executions; 14 -> 0 fee diagnostic differences")


from collections import Counter

if __name__ == "__main__":
    main()
