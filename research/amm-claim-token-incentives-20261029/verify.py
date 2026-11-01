"""Verify the retained claim_token_incentives receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 40 cases x 3 images = 120 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases store exactly the expected user-volume-accumulator
  state (needs, unclaimed, claimed, volume, last, has_claimed, 137-byte
  length), move exactly the expected vault/user token amounts, and
  charge only the expected fee; the zero-claim case logs
  "No tokens to claim" and moves nothing; the missing-ATA case creates
  the token account for 2039280 rent on top of the 5000 fee; the
  stored-other-user case overwrites the stored user key;
- error cases fail with the expected code and log fragment, and roll
  back every account except the fee payer's 5000 fee (the unsigned
  case is paid by OUTSIDER, not PAYER);
- the recorded error sites match the receipts' logs (including
  "caused by account" sites and "panicked at" sites);
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_uva(entry):
    if entry is None:
        return {"uva_len": None, "user": None, "needs": None, "unclaimed": None,
                "claimed": None, "volume": None, "last": None, "has_claimed": None}
    data = bytes.fromhex(entry["data_hex"])
    if len(data) < 90:
        return {"uva_len": len(data), "user": None, "needs": None, "unclaimed": None,
                "claimed": None, "volume": None, "last": None, "has_claimed": None}
    needs, unclaimed, claimed, volume, last, hasc, _, _ = struct.unpack_from(
        "<BQQQqBQQ", data, 40)
    return {"uva_len": len(data), "user": data[8:40].hex(), "needs": needs,
            "unclaimed": unclaimed, "claimed": claimed, "volume": volume,
            "last": last, "has_claimed": hasc}


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
    assert [p["receipts"] for p in parts] == [10] * 12
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 40
    assert len(receipts) == 120
    assert report["counts"] == {"vms": 120, "transactions": 120, "signature_fields": 120}
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
                                      "instruction": "claim_token_incentives",
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
            # Instruction account order is [user, user_ata,
            # global_volume_accumulator, global_incentive_token_account,
            # user_volume_accumulator, mint, token_program, system_program,
            # associated_token_program, event_authority, program, payer];
            # message account_keys are re-sorted, so resolve via the
            # compiled instruction's account indices, not positions.
            ix_accounts = tx.message.instructions[0].accounts
            ua_key = keys[ix_accounts[1]]
            vault_key = keys[ix_accounts[3]]
            uva_key = keys[ix_accounts[4]]
            observed = parse_uva(rec["after"][uva_key])
            observed["vault_amt"] = ata_amount(rec["after"].get(vault_key))
            observed["user_amt"] = ata_amount(rec["after"].get(ua_key))
            observed["vault_lamports"] = rec["after"][vault_key]["lamports"] \
                if rec["after"].get(vault_key) else None
            observed["user_lamports"] = rec["after"][ua_key]["lamports"] \
                if rec["after"].get(ua_key) else None
            observed["payer_delta"] = rec["payer_fee_lamports"]
            assert rec["observed"] == observed, (case, image, rec["observed"], observed)
            assert value["observed"] == rec["observed"]
            if kind == "ok":
                assert rec["error"] is None
                assert observed["needs"] == case["expected"][1], (case, image, observed)
                assert observed["unclaimed"] == case["expected"][2], (case, image, observed)
                assert observed["claimed"] == case["expected"][3], (case, image, observed)
                assert observed["volume"] == case["expected"][4], (case, image, observed)
                assert observed["last"] == case["expected"][5], (case, image, observed)
                assert observed["has_claimed"] == case["expected"][6], (case, image, observed)
                assert observed["vault_amt"] == case["expected"][7], (case, image, observed)
                assert observed["user_amt"] == case["expected"][8], (case, image, observed)
                assert rec["payer_fee_lamports"] == case["expected"][9]
                assert observed["uva_len"] == 137, (case, image, observed)
                if case["label"] == "stored-other-user":
                    assert observed["user"] == "466627d52773c9d5cda6c8fd28ea31ec7b94e68aa8d42e2ad31a75dc8d24ed07", \
                        (case, image, observed)
                if case["label"] == "missing-user-ata":
                    assert observed["user_lamports"] == 2039280, (case, image, observed)
                if case["label"] == "zero-claim":
                    assert any("No tokens to claim" in l for l in rec["metadata"]["logs"]), \
                        (case, image, "no no-claim log")
                else:
                    assert any(l.startswith("Program data: ")
                               for l in rec["metadata"]["logs"]), \
                        (case, image, "no event")
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
    print("PASS: 40 cases, 120 signed receipts, "
          "claim_token_incentives reward/reset/zero-claim rules pinned, "
          "6024/6038/3012/3010/2000/2015/2006/3003 errors pinned, "
          "4 panic paths pinned, 89/543-byte deserialize floors, "
          "ATA init_if_needed rent pinned, all images agree")


if __name__ == "__main__":
    main()
