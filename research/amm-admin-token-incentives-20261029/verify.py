"""Verify the retained admin_update_token_incentives receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 32 cases x 3 images = 96 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases store exactly the expected global-volume-accumulator
  state (start, end, period, full 30-slot supply and volume arrays,
  account length, mint), charge only the expected fee, and emit an
  event log; the missing-ATA case creates the token account for
  2039280 rent on top of the 5000 fee;
- error cases fail with the expected code and log fragment, and roll
  back every account except the fee payer's 5000 fee (the unsigned
  case is paid by OUTSIDER, not PAYER);
- the recorded error sites match the receipts' logs (including
  "caused by account" sites, "panicked at" sites, and the per-image
  line-number differences);
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case.
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
CONTROL = ROOT / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz"
CANDIDATE = ROOT / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz"
IMAGES = ("original", "control", "candidate")
MINT_HEX = "e2" * 32


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_gva(entry):
    if entry is None:
        return {"gva_len": None, "start": None, "end": None, "period": None,
                "mint": None, "supplies": None, "volumes": None}
    data = bytes.fromhex(entry["data_hex"])
    if len(data) < 544:
        return {"gva_len": len(data), "start": None, "end": None, "period": None,
                "mint": None, "supplies": None, "volumes": None}
    start, end, period = struct.unpack_from("<qqq", data, 8)
    return {"gva_len": len(data), "start": start, "end": end, "period": period,
            "mint": data[32:64].hex(),
            "supplies": list(struct.unpack_from("<30Q", data, 64)),
            "volumes": list(struct.unpack_from("<30Q", data, 304))}


def ata_amount(entry):
    if entry is None:
        return None
    data = bytes.fromhex(entry["data_hex"])
    return struct.unpack_from("<Q", data, 64)[0] if len(data) >= 72 else None


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
    assert [p["receipts"] for p in parts] == [10] * 9 + [6]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 32
    assert len(receipts) == 96
    assert report["counts"] == {"vms": 96, "transactions": 96, "signature_fields": 96}
    assert report["mismatches"] == []
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress(CONTROL.read_bytes())),
        "candidate": sha(gzip.decompress(CANDIDATE.read_bytes())),
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
                                      "instruction": "admin_update_token_incentives",
                                      "label": case["label"]}
            assert rec["clock"]["slot"] == 100
            assert rec["clock"]["unix_timestamp"] == case["params"].get("now", 10)
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
            keys = [str(k) for k in tx.message.account_keys]
            payer = keys[0]
            assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == \
                rec["payer_fee_lamports"]
            # Instruction account order is [admin, global_config,
            # global_volume_accumulator, mint, global_incentive_token_account,
            # ...]; message account_keys are re-sorted, so resolve via the
            # compiled instruction's account indices, not positions.
            ix_accounts = tx.message.instructions[0].accounts
            gva_key = keys[ix_accounts[2]]
            ata_key = keys[ix_accounts[4]]
            observed = parse_gva(rec["after"][gva_key])
            observed["payer_delta"] = rec["payer_fee_lamports"]
            observed["ata_lamports"] = rec["after"][ata_key]["lamports"] \
                if rec["after"].get(ata_key) else None
            observed["ata_amount"] = ata_amount(rec["after"].get(ata_key))
            if case["params"].get("wrong_mint"):
                observed["mint_before"] = parse_gva(rec["before"][gva_key])["mint"]
            assert rec["observed"] == observed, (case, image, rec["observed"], observed)
            assert value["observed"] == rec["observed"]
            if kind == "ok":
                assert rec["error"] is None
                assert observed["start"] == case["expected"][1], (case, image, observed)
                assert observed["end"] == case["expected"][2], (case, image, observed)
                assert observed["period"] == case["expected"][3], (case, image, observed)
                assert observed["supplies"] == case["expected"][4], (case, image, observed)
                assert observed["volumes"] == case["expected"][5], (case, image, observed)
                assert observed["gva_len"] == case["expected"][6], (case, image, observed)
                assert observed["mint"] == MINT_HEX, (case, image, observed)
                assert rec["payer_fee_lamports"] == case["expected"][7]
                assert any(l.startswith("Program data: ") for l in rec["metadata"]["logs"]), \
                    (case, image, "no event")
                if case["label"] == "missing-ata":
                    assert observed["ata_lamports"] == 2039280, (case, image, observed)
                    assert observed["ata_amount"] == 0, (case, image, observed)
                pairs.add((json.dumps(observed, sort_keys=True),))
            else:
                assert rec["error"] is not None and case["expected"][1] in rec["error"]
                assert case["expected"][2] in "\n".join(rec["metadata"]["logs"])
                assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == 5000
                assert all(rec["before"][k] == rec["after"][k]
                           for k in rec["before"] if k != payer)
                assert rec["rollback_except_payer_fee"] is True
                site = next((l for l in rec["metadata"]["logs"]
                             if "thrown in" in l or "caused by account" in l
                             or "panicked at" in l), None)
                assert row["error_sites"][image] == site, (case, image)
                pairs.add((rec["error"], json.dumps(observed, sort_keys=True)))
        assert len(pairs) == 1, (case, "images must agree")
    print("PASS: 32 cases, 96 signed receipts, "
          "admin_update_token_incentives time/supply rules pinned, "
          "6030-6037 + 6005/3010/2000/3012/3003 errors pinned, "
          "3 panic paths pinned, 544-byte deserialize floor, "
          "ATA init_if_needed rent pinned, all images agree")


if __name__ == "__main__":
    main()
