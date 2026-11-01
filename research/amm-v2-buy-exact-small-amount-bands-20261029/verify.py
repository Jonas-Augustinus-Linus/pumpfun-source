"""Verify the retained v2 buy_exact_quote_in small-amount-band receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, fixture) hash to the
  recorded values;
- 29 cases x 3 images = 87 receipts, ordered, with contexts matching
  the report, stored as 9 parts (10 x 8 + 7), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each);
- all three images agree on every case (identical error and observed
  values), and the recorded error sites match the receipts' logs
  ("thrown in" and "caused by account" forms);
- success cases: the six token-amount deltas (userbase, userquote,
  vaultbase, vaultquote, buyback, buyback22) match the case's
  expected tuple, the payer is charged exactly 1,849,400 lamports
  (1,844,400 volume-accumulator rent + 5,000 fee), the volume
  account holds 1,844,400 lamports over 137 bytes keyed to the
  payer, and exactly 1 BuyEvent line is emitted whose decoded
  fields (out @16, max @24, quote @64, lp_bps @72, lp_fee @80,
  protocol_bps @88, protocol_fee @96, quote_with_lp @104,
  user_quote_in @112) match the case's expected event tuple;
- error cases: fail with the expected code and log fragment, roll
  back every account except the fee payer's 5,000 fee, and emit no
  event.
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


def tok_amount(snapshot, key):
    row = snapshot.get(key)
    assert row is not None, f"missing snapshot row {key}"
    return struct.unpack("<Q", bytes.fromhex(row["data_hex"])[64:72])[0]


def event_fields(log_lines):
    lines = [l for l in log_lines if l.startswith("Program data: ")]
    assert len(lines) == 1, lines
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    assert len(raw) >= 120, len(raw)
    return tuple(struct.unpack_from("<Q", raw, off)[0]
                 for off in (16, 24, 64, 72, 80, 88, 96, 104, 112))


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
    assert [p["receipts"] for p in parts] == [10] * 8 + [7]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 29
    assert len(receipts) == 87
    assert report["counts"]["vms"] == 87
    assert report["counts"]["transactions"] == 87
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 87
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
        kind = case["expected"]["kind"]
        observed_set = set()
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": 0, "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"])
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == rec["signature_fields"] == 1
            assert rec["transaction_sha256"] == sha(raw)
            assert rec["all_signatures_verified"] is True
            assert rec["signatures"] == [str(s) for s in tx.signatures]
            assert rec["error"] == row[image]["error"]
            assert rec["metadata"]["logs"] == row[image]["logs"]
            assert rec["observed"] == row[image]["observed"]
            observed_set.add(json.dumps(rec["observed"], sort_keys=True))
            before, after = rec["before"], rec["after"]
            roles = rec["roles"]
            fee_key = roles["fee_payer"]
            payer_delta = (after[fee_key]["lamports"] if after.get(fee_key) else 0) - \
                          (before[fee_key]["lamports"] if before.get(fee_key) else 0)
            assert payer_delta == -rec["payer_fee_lamports"]
            if kind == "trade":
                assert rec["error"] is None
                deltas = {}
                for wname, key in (("userbase", roles["userbase"]), ("userquote", roles["userquote"]),
                                   ("vaultbase", roles["vaultbase"]), ("vaultquote", roles["vaultquote"]),
                                   ("buyback", roles["buyback_recipient"])):
                    b, a = before[key], after[key]
                    deltas[wname] = None if b is None or a is None else \
                        tok_amount(after, key) - tok_amount(before, key)
                # buyback22 (the fixed Token-2022 buyback ATA) equals the
                # recipient in tf cases and is absent in nofee cases, so
                # the observed value must track the recipient delta under
                # tf and be None otherwise; it is also checked against
                # the expected tuple and across images.
                if case["quote_tf_bps"] is not None:
                    assert rec["observed"]["deltas"]["buyback22"] == rec["observed"]["deltas"]["buyback"], \
                        (case["label"], image)
                else:
                    assert rec["observed"]["deltas"]["buyback22"] is None, (case["label"], image)
                assert deltas == {k: v for k, v in case["expected"]["deltas"].items()
                                  if k != "buyback22"}, (case["label"], image, deltas)
                assert rec["observed"]["deltas"]["buyback22"] == case["expected"]["deltas"]["buyback22"], \
                    (case["label"], image)
                assert payer_delta == -1849400, (case["label"], image, payer_delta)
                vol = after[roles["volume"]]
                assert vol is not None and vol["lamports"] == 1844400, (case["label"], image, vol)
                assert len(bytes.fromhex(vol["data_hex"])) == 137, (case["label"], image)
                from solders.pubkey import Pubkey as _Pubkey
                assert bytes.fromhex(vol["data_hex"])[8:40] == bytes(_Pubkey.from_string(fee_key)), \
                    (case["label"], image, "volume user")
                assert rec["observed"]["event"] == case["expected"]["event"], \
                    (case["label"], image, rec["observed"]["event"])
                assert event_fields(rec["metadata"]["logs"]) == tuple(case["expected"]["event"]), \
                    (case["label"], image)
            else:
                code, fragment = case["expected"]["code"], case["expected"]["fragment"]
                assert rec["error"] is not None and str(code) in rec["error"], \
                    (case["label"], image, rec["error"])
                assert fragment in "\n".join(rec["metadata"]["logs"]), (case["label"], image)
                site = row.get("error_sites", {}).get(image, "")
                assert site and site in rec["metadata"]["logs"], (case["label"], image, site)
                assert f"Error Number: {code}." in site, (case["label"], image, site)
                assert payer_delta == -5000, (case["label"], image, payer_delta)
                for k in before:
                    if k != fee_key:
                        assert before[k] == after[k], (case["label"], image, k, "rollback")
                assert len([l for l in rec["metadata"]["logs"]
                            if l.startswith("Program data: ")]) == 0, (case["label"], image)
        assert len(observed_set) == 1, (case["label"], "images must agree")

    print("verify PASS: 29 cases x 3 images = 87 receipts, all checks passed")


if __name__ == "__main__":
    main()
