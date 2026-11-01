"""Verify the retained v2 buy small-amount-band receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 21 cases x 3 images = 63 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- the fee config in each before snapshot has exactly the recorded
  length (4097), the recorded tier count, and the recorded tier
  entries (threshold u128 + 3 x u64 fees) at offset 69 + 40*i;
- the pool in each before snapshot has virtual quote reserves 0
  (bytes 245..261), mayhem byte 0 (243), accrued protocol/creator
  fees zeroed (bytes 271..287), and the recorded quote mint;
- the vault balances in each before snapshot equal the recorded
  VB/VQ, the base mint supply equals the recorded supply, and the
  user quote/base before amounts equal the recorded case amounts;
- success cases move exactly the expected token deltas on all six
  watched accounts (userbase, userquote, base vault, quote vault,
  the trade's buyback recipient, and the Token-2022 buyback ATA,
  which stays absent except in transfer-fee cases where it IS the
  recipient), fund the user volume accumulator with exactly
  1,844,400 lamports (137 bytes, payer key at [8:40]), charge the
  payer 1,849,400 lamports (rent + 5,000 fee), and emit exactly 1
  event whose fixed-offset prefix matches the recorded fields
  (quote @64, lp_bps @72, lp_fee @80, protocol_bps @88,
  protocol_fee @96, quote_with_lp_fee @104,
  user_quote_amount_in @112);
- error cases fail with exactly the recorded error code, leave
  all watched token deltas at 0, charge the payer 5,000 only,
  leave the volume account empty, emit 0 events, and carry the
  recorded site line in their logs (original vs rebuilt site
  fragments differ: 6001 is trade_v2.rs:671 original / :431
  rebuilt, 6002 is :672 original / :432 rebuilt, 6004 is :706
  original / :448 rebuilt);
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case (deltas, error code, event).
"""
import base64
import gzip
import hashlib
import json
import re
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

sys.path.insert(0, str(ROOT / "scripts"))
import os
os.chdir(ROOT)
from pump_amm_liquidity_differential import base as BASE_KEY  # noqa: E402
from pump_amm_liquidity_differential import quote as QUOTE_KEY  # noqa: E402
from pump_amm_liquidity_differential import userbase as USERBASE_KEY  # noqa: E402
from pump_amm_liquidity_differential import userquote as USERQUOTE_KEY  # noqa: E402
from pump_amm_liquidity_differential import vaultbase as VB_KEY  # noqa: E402
from pump_amm_liquidity_differential import vaultquote as VQ_KEY  # noqa: E402
from pump_amm_trade_v2_differential import feeconfig as FEECONFIG_KEY  # noqa: E402
from pump_amm_trade_v2_differential import volume as VOLUME_KEY  # noqa: E402

from solders.pubkey import Pubkey as _Pubkey  # noqa: E402
import base64 as _b64  # noqa: E402
from pump_amm_liquidity_differential import f as _f  # noqa: E402
from pump_amm_liquidity_differential import TOKEN22 as _TOKEN22  # noqa: E402
ATA = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
_BB_OWNER = _Pubkey.from_bytes(_b64.b64decode(_f['accounts']['buyback_fee_recipient']['data_base64'])[32:64])
BUYBACK22_KEY = _Pubkey.find_program_address(
    [bytes(_BB_OWNER), bytes(_TOKEN22), bytes(QUOTE_KEY)],
    _Pubkey.from_string(ATA))[0]

WATCH = {
    "userbase": USERBASE_KEY,
    "userquote": USERQUOTE_KEY,
    "vaultbase": VB_KEY,
    "vaultquote": VQ_KEY,
    "buyback22": BUYBACK22_KEY,
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def amount_at(data_hex, offset):
    return struct.unpack_from("<Q", bytes.fromhex(data_hex), offset)[0]


def delta_of(before, after):
    if before is None or after is None:
        return None
    return amount_at(after["data_hex"], 64) - amount_at(before["data_hex"], 64)


def event_fields(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    assert len(lines) == 1, lines
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    assert len(raw) >= 120, len(raw)
    return [struct.unpack_from("<Q", raw, off)[0] for off in (64, 72, 80, 88, 96, 104, 112)]


def error_code(err):
    m = re.search(r"InstructionErrorCustom\((\d+)\)", err or "")
    assert m, err
    return int(m.group(1))


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
    assert [p["receipts"] for p in parts] == [10, 10, 10, 10, 10, 10, 3]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 21
    assert len(receipts) == 63
    assert report["counts"] == {"vms": 63, "transactions": 63, "signature_fields": 63}
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
        assert case["feeconfig_len"] == 4097
        assert case["instruction"] == "buy_v2"
        tiers = case["tiers"]
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
            # Fixture pins: fee table, pool vq/mayhem/fees, vault amounts, supply, user amounts.
            fc = rec["before"][str(FEECONFIG_KEY)]
            assert fc is not None
            fc_data = bytes.fromhex(fc["data_hex"])
            assert len(fc_data) == 4097, (case, image, len(fc_data))
            assert struct.unpack_from("<I", fc_data, 65)[0] == len(tiers), (case, image)
            for i, (t, fs) in enumerate(tiers):
                assert int.from_bytes(fc_data[69 + 40 * i:69 + 40 * i + 16], "little") == t, (case, image, i)
                assert struct.unpack_from("<QQQ", fc_data, 69 + 40 * i + 16) == tuple(fs), (case, image, i)
            pool_key = case["pool_keys"][image]
            pool_data = bytes.fromhex(rec["before"][pool_key]["data_hex"])
            assert pool_data[245:261] == (0).to_bytes(16, "little", signed=True), (case, image)
            assert pool_data[243] == case["mayhem"], (case, image)
            assert pool_data[271:287] == bytes(16), (case, image)
            assert pool_data[75:107] == bytes(QUOTE_KEY), (case, image)
            assert amount_at(rec["before"][str(VB_KEY)]["data_hex"], 64) == case["vaultbase"], (case, image)
            assert amount_at(rec["before"][str(VQ_KEY)]["data_hex"], 64) == case["vaultquote"], (case, image)
            assert amount_at(rec["before"][str(BASE_KEY)]["data_hex"], 36) == case["supply"], (case, image)
            assert amount_at(rec["before"][str(USERQUOTE_KEY)]["data_hex"], 64) == case["userquote_amount"], (case, image)
            assert amount_at(rec["before"][str(USERBASE_KEY)]["data_hex"], 64) == case["userbase_amount"], (case, image)
            payer = str(tx.message.account_keys[0])
            payer_fee = rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"]
            assert payer_fee == rec["payer_fee_lamports"]
            deltas = {name: delta_of(rec["before"][str(key)], rec["after"][str(key)])
                      for name, key in WATCH.items()}
            recipient_key = case["buyback_recipients"][image]
            deltas["buyback"] = delta_of(rec["before"][recipient_key],
                                         rec["after"][recipient_key])
            deltas = {"userbase": deltas["userbase"], "userquote": deltas["userquote"],
                      "vaultbase": deltas["vaultbase"], "vaultquote": deltas["vaultquote"],
                      "buyback": deltas["buyback"], "buyback22": deltas["buyback22"]}
            expected = case["expected"]
            if expected["kind"] == "trade":
                assert rec["error"] is None
                assert payer_fee == 1849400, (case, image, payer_fee)
                assert deltas == expected["deltas"], (case, image, deltas)
                got_ev = event_fields(rec["metadata"]["logs"])
                assert got_ev == expected["event"], (case, image, got_ev)
                assert rec["observed"] == {"deltas": deltas, "payer_lamports_delta": -1849400,
                                           "volume_lamports": 1844400, "volume_data_len": 137,
                                           "event": got_ev}
                vol = rec["after"][str(VOLUME_KEY)]
                assert vol is not None and vol["lamports"] == 1844400, (case, image, vol)
                vdata = bytes.fromhex(vol["data_hex"])
                assert len(vdata) == 137, (case, image, len(vdata))
                assert vdata[8:40] == bytes(tx.message.account_keys[0]), (case, image, "volume user")
                pairs.add((tuple(sorted(deltas.items())), None, tuple(got_ev)))
            else:
                assert rec["error"] is not None
                assert error_code(rec["error"]) == expected["code"], (case, image, rec["error"])
                assert payer_fee == 5000, (case, image, payer_fee)
                bb22_zero = 0 if case["quote_tf_bps"] is not None else None
                assert deltas == {"userbase": 0, "userquote": 0, "vaultbase": 0,
                                 "vaultquote": 0, "buyback": 0, "buyback22": bb22_zero}, (case, image, deltas)
                assert len([l for l in rec["metadata"]["logs"] if l.startswith("Program data: ")]) == 0
                vol = rec["after"][str(VOLUME_KEY)]
                assert vol is None or (vol["lamports"] == 0 and vol["data_hex"] == ""), (case, image, vol)
                site = rec["observed"]["site"]
                assert site in rec["metadata"]["logs"], (case, image, site)
                assert f"Error Number: {expected['code']}." in site, (case, image, site)
                want_site = expected["site_original"] if image == "original" else expected["site_rebuilt"]
                assert want_site in site, (case, image, site)
                assert rec["observed"] == {"deltas": deltas, "payer_lamports_delta": -5000,
                                           "volume_lamports": 0, "volume_data_len": 0,
                                           "event": None, "site": site}
                pairs.add((tuple(sorted(deltas.items())), expected["code"], None))
            assert value["observed"] == rec["observed"]
        assert len(pairs) == 1, (case, "images must agree on amounts/error/event")
    print("verify PASS: 21 cases x 3 images = 63 receipts, all checks passed")


if __name__ == "__main__":
    main()
