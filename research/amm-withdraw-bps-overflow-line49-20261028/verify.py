"""Verify the retained line-49 withdraw receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, trade fixture, IDL, evidence programs,
  maintained source) hash to the recorded values;
- the maintained transfer_fee.rs still carries the four error sites at the
  original coordinates (lines 32, 49, 57, 67);
- 4 cases x 3 images = 12 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- every receipt's quote-mint account carries a kind-1 TLV fee entry whose
  basis points match the case (or, for the no-patch case, no fee entry);
- the pool quote vault balance in the before snapshot is u64::MAX;
- bps-65535 and bps-10001 cases report Overflow at lines 49 (original),
  22 (control) and 49 (candidate);
- the valid-bps and no-patch cases error identically (14 / 1) on all images;
- failure receipts roll back every account except the payer's 5000 fee.
"""
import base64
import gzip
import hashlib
import json
import struct
from pathlib import Path

from solders.transaction import Transaction

if not __debug__:
    raise SystemExit("Run without -O")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MINT_KEY = "So11111111111111111111111111111111111111112"
VAULT_KEY = None  # resolved from the first receipt's before keys below

EXPECTED = {
    "withdraw-bps-65535-vault-max": (49, 22, 49),
    "withdraw-bps-10001-vault-max": (49, 22, 49),
    "withdraw-bps-100-vault-max-agreement": "14",
    "withdraw-no-patch-vault-max-agreement": "1",
}
IMAGES = ("original", "control", "candidate")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def diag_line(logs):
    for line in logs:
        if "transfer_fee.rs:" in line:
            return int(line.split("transfer_fee.rs:")[1].split(".")[0])
    return None


def main():
    paths = list(HERE.rglob("*"))
    assert not any(p.is_symlink() for p in paths)
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    files = {p.relative_to(HERE).as_posix() for p in paths
             if p.is_file() and p.name != "MANIFEST.json"}
    assert files == set(manifest["files"]), sorted(files ^ set(manifest["files"]))
    for name, digest in manifest["files"].items():
        assert sha((HERE / name).read_bytes()) == digest, name
    for name, digest in manifest["repository_inputs"].items():
        path = ROOT / name
        assert path.is_file() and not path.is_symlink(), name
        assert sha(path.read_bytes()) == digest, name

    source = ROOT / "programs/pump-amm/src/utils/transfer_fee.rs"
    lines = source.read_text().splitlines()
    assert "UnsupportedQuoteMint" in lines[31]
    assert "PumpAmmError::Overflow" in lines[48]
    assert "PumpAmmError::Overflow" in lines[56]
    assert "PumpAmmError::Overflow" in lines[66]

    report = json.loads(gzip.decompress((HERE / "runtime/report.json.gz").read_bytes()))
    receipt_data = (HERE / "runtime/raw-transactions.jsonl.gz").read_bytes()
    receipts = [json.loads(line) for line in gzip.decompress(receipt_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 4
    assert len(receipts) == 12
    assert report["transaction_receipts"] == {
        "path": "raw-transactions.jsonl.gz", "sha256": sha(receipt_data)}
    assert report["counts"] == {"vms": 12, "transactions": 12, "signature_fields": 12}
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress((ROOT / "research/amm-multi-hop-group-slice-recovery"
                                        "/artifacts/candidate.so.gz").read_bytes())),
        "candidate": sha(gzip.decompress((ROOT / "research/amm-transfer-fee-diagnostic-recovery"
                                          "/artifacts/candidate.so.gz").read_bytes())),
    }
    for name, digest in report["input_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    # The pool quote vault key: the token account whose before amount is u64::MAX
    # and whose owner is the Token-2022 program.
    first = receipts[0]["before"]
    vault_keys = [k for k, v in first.items()
                  if v is not None and v["owner"] == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
                  and struct.unpack_from("<Q", bytes.fromhex(v["data_hex"]), 64)[0] == 2**64 - 1]
    assert len(vault_keys) == 1, vault_keys
    vault_key = vault_keys[0]

    for index, row in enumerate(report["cases"]):
        case = row["case"]
        assert case["label"] in EXPECTED, case["label"]
        assert case["vault_quote_balance"] == 2**64 - 1
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": "withdraw",
                                      "mint": "quote", "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": 0, "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"], validate=True)
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == 1
            assert rec["all_signatures_verified"] and rec["signature_fields"] == 1
            assert sha(raw) == rec["transaction_sha256"]
            assert [str(s) for s in tx.signatures] == rec["signatures"]
            assert rec["loaded_programs"][next(
                k for k in rec["loaded_programs"] if k.startswith("pAMM"))]["sha256"] == \
                report["image_sha256"][image]
            vault = bytes.fromhex(rec["before"][vault_key]["data_hex"])
            assert struct.unpack_from("<Q", vault, 64)[0] == 2**64 - 1
            mint = bytes.fromhex(rec["before"][MINT_KEY]["data_hex"])
            if case["bps"] is None:
                assert len(mint) < 166 or mint[166:168] != b"\x01\x00"
            else:
                assert case["bps"] > 10000 or case["label"].endswith("agreement")
                assert mint[166:168] == b"\x01\x00" and int.from_bytes(mint[168:170], "little") == 108
                for bps_off, max_off in ((258, 250), (276, 268)):
                    assert struct.unpack_from("<H", mint, bps_off)[0] == case["bps"]
                    assert struct.unpack_from("<Q", mint, max_off)[0] == case["maximum_fee"]
            value = row[image]
            assert value["error"] == rec["error"] and value["logs"] == rec["metadata"]["logs"]
            want = EXPECTED[case["label"]]
            payer = str(tx.message.account_keys[0])
            assert all(rec["before"][k] == rec["after"][k]
                       for k in rec["before"] if k != payer)
            before, after = dict(rec["before"][payer]), dict(rec["after"][payer])
            assert before.pop("lamports") - after.pop("lamports") == \
                rec["payer_fee_lamports"] == 5000
            assert before == after and rec["rollback_except_payer_fee"] is True
            if isinstance(want, tuple):
                assert diag_line(rec["metadata"]["logs"]) == want[image_offset], (case, image)
                assert rec["error"] is not None and "6023" in rec["error"]
            else:
                assert diag_line(rec["metadata"]["logs"]) is None
                assert rec["error"] is not None and want in rec["error"]
    print("PASS: 4 cases, 12 signed receipts, "
          "withdraw bps>10000 vault-max -> lines 49/22/49, "
          "valid-bps and no-patch agree (14 / 1) on all images")


if __name__ == "__main__":
    main()
