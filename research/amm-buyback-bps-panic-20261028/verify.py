"""Verify the retained buyback-bps panic receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, trade fixture, IDL, evidence programs,
  maintained source) hash to the recorded values;
- the maintained source still carries the `buyback_fee never exceeds
  protocol_fee` expects at trade_v2.rs:122 and pool.rs:21;
- 6 cases x 3 images = 18 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- every receipt's global-config account carries the case's buyback_bps
  at offset 899;
- bps-65535 and bps-10001 cases panic with ProgramFailedToComplete and the
  expected site per image (original: global_config.rs:391; others:
  trade_v2.rs:122 for buys, pool.rs:21 for sells);
- valid-bps cases succeed on all images with identical data-account states;
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
CONFIG_KEY = "ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw"

EXPECTED = {
    "buy_v2-buyback-65535": ("panic", "state/global_config.rs:391:14",
                            "instructions/swap/trade_v2.rs:122:14"),
    "buy_v2-buyback-10001": ("panic", "state/global_config.rs:391:14",
                            "instructions/swap/trade_v2.rs:122:14"),
    "sell_v2-buyback-65535": ("panic", "state/global_config.rs:391:14",
                             "state/pool.rs:21:18"),
    "sell_v2-buyback-10001": ("panic", "state/global_config.rs:391:14",
                             "state/pool.rs:21:18"),
    "buy_v2-buyback-5000-success": ("success",),
    "sell_v2-buyback-10000-success": ("success",),
}
IMAGES = ("original", "control", "candidate")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def panic_site(logs):
    for line in logs:
        if "panicked at programs/pump-amm/src/" in line:
            rest = line.split("programs/pump-amm/src/")[1]
            parts = rest.split(":")
            return parts[0] + ":" + parts[1] + ":" + parts[2].split("\\")[0]
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

    trade_v2 = (ROOT / "programs/pump-amm/src/instructions/swap/trade_v2.rs").read_text()
    assert "buyback_fee never exceeds protocol_fee" in trade_v2
    pool_rs = (ROOT / "programs/pump-amm/src/state/pool.rs").read_text()
    assert "buyback_fee never exceeds protocol_fee" in pool_rs

    report = json.loads(gzip.decompress((HERE / "runtime/report.json.gz").read_bytes()))
    receipt_data = (HERE / "runtime/raw-transactions.jsonl.gz").read_bytes()
    receipts = [json.loads(line) for line in gzip.decompress(receipt_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 6
    assert len(receipts) == 18
    assert report["transaction_receipts"] == {
        "path": "raw-transactions.jsonl.gz", "sha256": sha(receipt_data)}
    assert report["counts"] == {"vms": 18, "transactions": 18, "signature_fields": 18}
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress((ROOT / "research/amm-multi-hop-group-slice-recovery"
                                        "/artifacts/candidate.so.gz").read_bytes())),
        "candidate": sha(gzip.decompress((ROOT / "research/amm-transfer-fee-diagnostic-recovery"
                                          "/artifacts/candidate.so.gz").read_bytes())),
    }
    for name, digest in report["input_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    # The global-config account: the before snapshot's config account is
    # identified by the case's buyback_bps at offset 899.
    for index, row in enumerate(report["cases"]):
        case = row["case"]
        assert case["label"] in EXPECTED, case["label"]
        want = EXPECTED[case["label"]]
        success_afters = []
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
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
            cfg = rec["before"][CONFIG_KEY]
            assert cfg is not None and len(bytes.fromhex(cfg["data_hex"])) > 907
            assert struct.unpack_from("<Q", bytes.fromhex(cfg["data_hex"]), 899)[0] == \
                case["buyback_bps"], (case, image)
            value = row[image]
            assert value["error"] == rec["error"] and value["logs"] == rec["metadata"]["logs"]
            payer = str(tx.message.account_keys[0])
            if want[0] == "panic":
                assert rec["error"] is not None and "ProgramFailedToComplete" in rec["error"]
                assert panic_site(rec["metadata"]["logs"]) == \
                    (want[1] if image == "original" else want[2]), (case, image)
                assert "buyback_fee never exceeds protocol_fee" in "\n".join(rec["metadata"]["logs"])
                assert all(rec["before"][k] == rec["after"][k]
                           for k in rec["before"] if k != payer)
                before, after = dict(rec["before"][payer]), dict(rec["after"][payer])
                assert before.pop("lamports") - after.pop("lamports") == \
                    rec["payer_fee_lamports"] == 5000
                assert before == after and rec["rollback_except_payer_fee"] is True
            else:
                assert rec["error"] is None and panic_site(rec["metadata"]["logs"]) is None
                assert rec["rollback_except_payer_fee"] is False
                success_afters.append({k: v for k, v in rec["after"].items()
                                       if v is None or not v["executable"]})
        if want[0] == "success":
            assert success_afters[0] == success_afters[1] == success_afters[2], case
    print("PASS: 6 cases, 18 signed receipts, "
          "buyback_bps>10000 panics buy and sell on all images, "
          "valid bps succeeds identically")


if __name__ == "__main__":
    main()
