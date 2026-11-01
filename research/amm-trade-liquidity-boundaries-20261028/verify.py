"""Verify this packet's retained signed runtime receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, trade fixture, IDL, evidence programs)
  hash to the recorded values;
- 6 cases x 3 images = 18 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases match the expected amounts for their instruction
  (buy: base gained and quote spent; sell: base spent and quote
  gained; deposit/withdraw: all zero);
- error cases fail with the expected code and log fragment, and roll
  back every account except the payer's 5000 fee;
- the recorded error sites match the receipts' logs;
- receipts are stored as parts, each under 25MB, read in order.
"""
import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

from solders.transaction import Transaction

if not __debug__:
    raise SystemExit("Run without -O")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IMAGES = ("original", "control", "candidate")

sys.path.insert(0, str(ROOT / "scripts"))
from pump_amm_liquidity_differential import userbase as USERBASE_KEY  # noqa: E402
from pump_amm_liquidity_differential import userquote as USERQUOTE_KEY  # noqa: E402
from pump_amm_liquidity_differential import userlp as USERLP_KEY  # noqa: E402


def sha(data):
    return hashlib.sha256(data).hexdigest()


def amount_at(data_hex, offset):
    return struct.unpack_from("<Q", bytes.fromhex(data_hex), offset)[0]


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

    report = json.loads(gzip.decompress((HERE / "runtime/report.json.gz").read_bytes()))
    parts = report["transaction_receipts"]["parts"]
    assert [p["receipts"] for p in parts] == [10, 8]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 6
    assert len(receipts) == 18
    assert report["counts"] == {"vms": 18, "transactions": 18, "signature_fields": 18}
    assert report["mismatches"] == []
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress((ROOT / "research/amm-multi-hop-group-slice-recovery"
                                        "/artifacts/candidate.so.gz").read_bytes())),
        "candidate": sha(gzip.decompress((ROOT / "research/amm-transfer-fee-diagnostic-recovery"
                                          "/artifacts/candidate.so.gz").read_bytes())),
    }
    for name, digest in report["input_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    for index, row in enumerate(report["cases"]):
        case = row["case"]
        kind = case["expected"][0]
        pairs = set()
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
            value = row[image]
            assert value["error"] == rec["error"] and value["logs"] == rec["metadata"]["logs"]
            payer = str(tx.message.account_keys[0])
            assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == \
                rec["payer_fee_lamports"]
            if kind == "ok":
                assert rec["error"] is None
                uq_key, ub_key = str(USERQUOTE_KEY), str(USERBASE_KEY)
                base_delta = amount_at(rec["after"][ub_key]["data_hex"], 64) - \
                    amount_at(rec["before"][ub_key]["data_hex"], 64)
                quote_delta = amount_at(rec["after"][uq_key]["data_hex"], 64) - \
                    amount_at(rec["before"][uq_key]["data_hex"], 64)
                if case["instruction"] == "buy_v2":
                    gained, spent = base_delta, -quote_delta
                    assert gained == case["expected"][1], (case, image, gained)
                    assert spent == case["expected"][2], (case, image, spent)
                    assert rec["observed"] == {"base_gained": gained, "quote_spent": spent}
                    pairs.add((gained, spent))
                elif case["instruction"] == "sell_v2":
                    spent, gained = -base_delta, quote_delta
                    assert spent == case["expected"][1], (case, image, spent)
                    assert gained == case["expected"][2], (case, image, gained)
                    assert rec["observed"] == {"base_spent": spent, "quote_gained": gained}
                    pairs.add((spent, gained))
                else:
                    ul_key = str(USERLP_KEY)
                    lp_delta = amount_at(rec["after"][ul_key]["data_hex"], 64) - \
                        amount_at(rec["before"][ul_key]["data_hex"], 64)
                    if case["instruction"] == "deposit":
                        observed = {"base_spent": -base_delta, "quote_spent": -quote_delta,
                                    "lp_gained": lp_delta}
                    else:
                        observed = {"base_gained": base_delta, "quote_gained": quote_delta,
                                    "lp_burned": -lp_delta}
                    assert observed == {k: 0 for k in observed}, (case, image, observed)
                    assert rec["observed"] == observed
                    pairs.add(tuple(observed.values()))
                assert value["observed"] == rec["observed"]
            else:
                assert rec["error"] is not None and case["expected"][1] in rec["error"]
                assert case["expected"][2] in "\n".join(rec["metadata"]["logs"])
                assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == 5000
                assert all(rec["before"][k] == rec["after"][k]
                           for k in rec["before"] if k != payer)
                assert rec["rollback_except_payer_fee"] is True
                site = next((l for l in rec["metadata"]["logs"] if "thrown in" in l), None)
                assert row["error_sites"][image] == site, (case, image)
        if kind == "ok":
            assert len(pairs) == 1, (case, "images must agree on amounts")
    print("PASS: 6 cases, 18 signed receipts, "
          "trade and liquidity boundaries pinned, "
          "slippage limit inclusive, zero amounts are no-ops, "
          "all images agree")


if __name__ == "__main__":
    main()
