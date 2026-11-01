"""Verify the retained init/close_user_volume_accumulator receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, IDL) hash to the recorded values;
- 40 cases x 3 images = 120 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid; 2 signature fields
  only for init-payer-readonly, 1 everywhere else);
- init success cases create/keep the 137-byte account at the expected
  lamports, charge the expected payer delta, write exactly the
  expected data (fresh: discriminator + user + zeros; existing:
  only bytes 8..40 rewritten to the user key), and emit one event;
- close success cases remove the account, return the expected payer
  delta, and emit one event;
- error cases fail with the expected code and log fragment, roll
  back every account except the fee payer's fee, and emit no event
  except MissingAccount cases, where the event line is already out
  before the failure;
- the recorded error sites match the receipts' logs (including
  "caused by account" sites; PrivilegeEscalation and MissingAccount
  have no such line, so their recorded site is None);
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case.
"""
import base64
import gzip
import hashlib
import json
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

    idl = json.loads((ROOT / "evidence/upstream/pump_amm.json").read_text())
    disc = bytes(next(x for x in idl["accounts"]
                      if x["name"] == "UserVolumeAccumulator")["discriminator"])

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
    assert report["counts"]["vms"] == 120
    assert report["counts"]["transactions"] == 120
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 123
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
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": 0, "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"], validate=True)
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            expected_sigs = 2 if case["label"] == "init-payer-readonly" else 1
            assert checks and all(checks) and len(checks) == expected_sigs
            assert rec["all_signatures_verified"] and rec["signature_fields"] == expected_sigs
            assert sha(raw) == rec["transaction_sha256"]
            assert [str(s) for s in tx.signatures] == rec["signatures"]
            assert rec["loaded_programs"][next(
                k for k in rec["loaded_programs"] if k.startswith("pAMM"))]["sha256"] == \
                report["image_sha256"][image]
            value = row[image]
            assert value["error"] == rec["error"] and value["logs"] == rec["metadata"]["logs"]
            assert value["observed"] == rec["observed"]
            keys = [str(k) for k in tx.message.account_keys]
            payer = keys[0]
            # Message keys are deduped/sorted, NOT instruction order:
            # resolve account roles through the compiled instruction.
            ix_accts = list(tx.message.instructions[0].accounts)
            msg_keys = tx.message.account_keys
            if case["instruction"] == "init_user_volume_accumulator":
                user_key = str(msg_keys[ix_accts[1]])
                acc_key = str(msg_keys[ix_accts[2]])
            else:
                acc_key = str(msg_keys[ix_accts[1]])
            before, after = rec["before"], rec["after"]
            payer_delta = (after[payer]["lamports"] if after[payer] else 0) - \
                          (before[payer]["lamports"] if before[payer] else 0)
            assert payer_delta == rec["payer_delta_lamports"] == value["observed"]["payer_delta"]
            assert value["observed"]["event_count"] == len(rec["metadata"]["events"])
            observed = value["observed"]
            if kind == "ok-init":
                assert value["error"] is None
                assert observed["acc_lamports_after"] == case["expected"][1]
                assert observed["payer_delta"] == case["expected"][2]
                assert observed["event_count"] == 1
                user = bytes(msg_keys[ix_accts[1]])
                if "existing" in case["params"].get("mutation", ""):
                    bdata = bytes.fromhex(before[acc_key]["data_hex"])
                    assert observed["acc_data_hex_after"] == \
                        (bdata[:8] + user + bdata[40:]).hex()
                else:
                    assert observed["acc_data_hex_after"] == \
                        (disc + user + bytes(97)).hex()
            elif kind == "ok-close":
                assert value["error"] is None
                assert observed["acc_lamports_after"] is None
                assert observed["acc_data_hex_after"] is None
                assert observed["payer_delta"] == case["expected"][1]
                assert observed["event_count"] == 1
            else:
                _, code, fragment, fee = case["expected"]
                assert value["error"] is not None and code in value["error"]
                assert fragment in "\n".join(value["logs"])
                assert observed["payer_delta"] == -fee
                assert all(before[k] == after[k] for k in before if k != payer)
                if code == "MissingAccount":
                    assert observed["event_count"] == 1
                else:
                    assert observed["event_count"] == 0
                site = next((l for l in value["logs"]
                             if "thrown in" in l or "caused by account" in l), None)
                assert row.get("error_sites", {}).get(image) == site, (case["label"], image)
            pairs.add((value["error"], tuple(sorted(
                (k, str(v)) for k, v in observed.items()))))
        assert len(pairs) == 1, (case["label"], "images must agree")
    print("verify PASS: 40 cases x 3 images = 120 receipts, all checks passed")


if __name__ == "__main__":
    main()
