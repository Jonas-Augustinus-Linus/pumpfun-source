"""Verify the retained collect Token-2022 transfer-fee receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, fixture) hash to the
  recorded values;
- 19 cases x 3 images = 57 receipts, ordered, with contexts matching
  the report, stored as 6 parts (10 x 5 + 7), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each);
- all three images agree on every case (identical error and observed
  values), and the recorded logs match the receipts' logs;
- success cases: the vault drains to 0 (delta -123,394), the
  destination amount, withheld amount, and destination length match
  the case's expected values, the payer pays only the 5,000 fee,
  and exactly one 120-byte CollectCoinCreatorFeeEvent reports the
  gross amount with the case's vault and destination keys;
- no-op cases: the vault stays 0, the destination is unchanged,
  no event is emitted, only the 5,000 payer fee is charged, and
  everything else rolls back;
- error cases: fail with the expected code and log fragment, roll
  back every account except the fee payer's 5,000 fee, and emit no
  event. The 0xd failure is program-level (Token-2022 program) and
  the 3012 failure is an uninitialized-account failure, so no
  "thrown in" / "caused by account" site is required for them; the
  2021/2023 failures carry the Anchor constraint fragment.
"""
import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

from solders.pubkey import Pubkey
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


def tok_amount(snapshot, key):
    row = snapshot.get(str(key))
    assert row is not None, f"missing snapshot row {key}"
    return struct.unpack("<Q", bytes.fromhex(row["data_hex"])[64:72])[0]


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
    assert [p["receipts"] for p in parts] == [10] * 5 + [7]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 19
    assert len(receipts) == 57
    assert report["counts"]["vms"] == 57
    assert report["counts"]["transactions"] == 57
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 57
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
        observed_set = set()
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": case["epoch"], "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"])
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == rec["signature_fields"] == 1
            assert rec["transaction_sha256"] == sha(raw)
            assert rec["all_signatures_verified"] is True
            assert rec["signatures"] == [str(s) for s in tx.signatures]
            amm_entries = [v for v in rec["loaded_programs"].values()
                           if v["path"] == "evidence/original/pump_amm/deployed.so"]
            assert len(amm_entries) == 1
            assert amm_entries[0]["sha256"] == report["image_sha256"][image]
            assert rec["error"] == row[image]["error"]
            assert rec["metadata"]["logs"] == row[image]["logs"]
            assert rec["observed"] == row[image]["observed"]
            observed_set.add(json.dumps(rec["observed"], sort_keys=True))
            before, after = rec["before"], rec["after"]
            payer_key = str(tx.message.account_keys[0])
            logs = rec["metadata"]["logs"]
            # The collect event is the single 120-byte "Program data:"
            # line (8 disc + 8 timestamp + 32 creator + 8 fee
            # + 32 vault + 32 dest); fee at offset 48.
            events = []
            for line in logs:
                if line.startswith("Program data: "):
                    blob = base64.b64decode(line[len("Program data: "):])
                    if len(blob) == 120:
                        events.append({"fee": struct.unpack_from("<Q", blob, 48)[0],
                                       "vault": str(Pubkey.from_bytes(blob[56:88])),
                                       "dest": str(Pubkey.from_bytes(blob[88:120]))})
            # Message account_keys are deduplicated/sorted, so
            # resolve accounts through the compiled instruction's
            # account indices, which preserve metas order:
            # [quote_mint, token_program, creator, vault_authority,
            #  vault_ata, dest, event, program].
            ix_accounts = tx.message.instructions[0].accounts
            vault_key = str(tx.message.account_keys[ix_accounts[4]])
            dest_key = str(tx.message.account_keys[ix_accounts[5]])
            if kind == "collect":
                _, vault_delta, dest_delta, dest_final, withheld, dest_len, event_fee = \
                    case["expected"]
                assert rec["error"] is None
                assert tok_amount(after, vault_key) == 0
                assert tok_amount(after, vault_key) - tok_amount(before, vault_key) \
                    == vault_delta, (case["label"], image)
                assert tok_amount(after, dest_key) == dest_final, (case["label"], image)
                assert tok_amount(after, dest_key) - tok_amount(before, dest_key) \
                    == dest_delta, (case["label"], image)
                assert len(bytes.fromhex(after[dest_key]["data_hex"])) == dest_len
                if withheld is None:
                    assert dest_len == 165, (case["label"], image)
                else:
                    got = struct.unpack_from(
                        "<Q", bytes.fromhex(after[dest_key]["data_hex"]), 174)[0]
                    assert got == withheld, (case["label"], image, got)
                assert rec["payer_delta_lamports"] == 5000
                assert after[payer_key]["lamports"] - before[payer_key]["lamports"] == -5000
                assert events == [{"fee": event_fee, "vault": vault_key,
                                   "dest": dest_key}], (case["label"], image, events)
                obs = rec["observed"]
                assert (obs["vault_delta"], obs["dest_delta"], obs["dest_final"],
                        obs["withheld"], obs["dest_len"], obs["payer_delta"],
                        obs["event_fee"]) == \
                    (vault_delta, dest_delta, dest_final, withheld, dest_len,
                     5000, event_fee), (case["label"], obs)
            elif kind == "noop":
                assert rec["error"] is None
                assert tok_amount(after, vault_key) == 0
                assert tok_amount(after, dest_key) == 0
                assert len(bytes.fromhex(after[dest_key]["data_hex"])) == case["expected"][1]
                assert events == [], (case["label"], image, events)
                assert rec["payer_delta_lamports"] == 5000
                assert all(before[k] == after[k] for k in before if k != payer_key)
                assert rec["observed"] == {"vault_amount": 0, "dest_amount": 0,
                                           "dest_len": case["expected"][1],
                                           "payer_delta": 5000, "events": 0}
            else:
                code = case["expected"][1]
                fragment = case["expected"][2]
                assert rec["error"] is not None and code in rec["error"]
                assert fragment in "\n".join(logs)
                assert events == [], (case["label"], image, events)
                assert rec["payer_delta_lamports"] == 5000
                assert all(before[k] == after[k] for k in before if k != payer_key)
                assert rec["observed"] == {"error": code, "fragment": fragment,
                                           "payer_delta": 5000}
        assert len(observed_set) == 1, (case["label"], "images disagree")
    print("verify PASS: 19 cases x 3 images = 57 receipts, all checks passed")


if __name__ == "__main__":
    main()
