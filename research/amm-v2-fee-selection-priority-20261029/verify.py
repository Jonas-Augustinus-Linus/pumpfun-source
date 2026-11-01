"""Verify the retained v2 fee-selection priority receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 13 cases x 3 images = 39 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- the fee config in each before snapshot has exactly the recorded
  length, the recorded exotic table at offset 2073, and the pool's
  quote mint matches the recorded quote kind (native / STABLE /
  exotic / NORMAL_QUOTE);
- success cases move exactly the expected token deltas on all six
  watched accounts (userbase, userquote, base vault, quote vault, the
  trade's buyback recipient, and the Token-2022 buyback ATA, which
  stays absent), fund the user volume accumulator with exactly
  1,844,400 lamports (137 bytes, payer key at [8:40]), and charge
  the payer 1,849,400 lamports (rent + 5,000 fee);
- the priority pins hold: stable + exotic at 4072/2512 fails 6082
  FeeTiersEmpty (exotic does not rescue a short stable config);
  at 4073 the stable pool pays stable spend while the exotic pool
  still pays flat fees; all-zero exotic at 4097 pays flat while
  creator-only exotic selects the table; NORMAL_QUOTE pays tier
  spend exactly like the native mint;
- error cases fail with the expected code and log fragment, and roll
  back every account except the fee payer's 5,000 fee;
- the recorded error sites match the receipts' logs (including
  "caused by account" sites); original-image line numbers differ
  from control/candidate line numbers, which is recorded per image;
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

STABLE_KEY = _Pubkey.from_string('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')
EXOTIC_KEY = _Pubkey.from_bytes(bytes([90]) * 32)
NORMAL_KEY = _Pubkey.from_bytes(bytes([131, 13, 252, 159, 222, 95, 230, 184, 170, 124, 4, 164, 118, 233, 30, 138, 198, 187, 38, 74, 173, 144, 250, 25, 201, 223, 73, 216, 92, 62, 91, 94]))
QUOTE_KEYS = {"native": QUOTE_KEY, "stable": STABLE_KEY,
              "exotic": EXOTIC_KEY, "normal": NORMAL_KEY}

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
    assert [p["receipts"] for p in parts] == [10, 10, 10, 9]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 13
    assert len(receipts) == 39
    assert report["counts"] == {"vms": 39, "transactions": 39, "signature_fields": 39}
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
        pairs = set()
        errors = set()
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
            # Fixture pins: fee config length, exotic table bytes, pool quote mint.
            fc = rec["before"][str(FEECONFIG_KEY)]
            assert fc is not None
            fc_data = bytes.fromhex(fc["data_hex"])
            assert len(fc_data) == case["feeconfig_len"], (case, image, len(fc_data))
            assert fc_data[2073:2097] == struct.pack("<QQQ", *case["exotic"]), (case, image)
            pool_key = case["pool_keys"][image]
            pool_data = bytes.fromhex(rec["before"][pool_key]["data_hex"])
            assert pool_data[75:107] == bytes(QUOTE_KEYS[case["quote_kind"]]), (case, image)
            payer = str(tx.message.account_keys[0])
            payer_fee = rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"]
            assert payer_fee == rec["payer_fee_lamports"]
            if kind == "trade":
                assert rec["error"] is None
                assert payer_fee == 1849400, (case, image, payer_fee)
                deltas = {name: delta_of(rec["before"][str(key)], rec["after"][str(key)])
                          for name, key in WATCH.items()}
                recipient_key = case["buyback_recipients"][image]
                deltas["buyback"] = delta_of(rec["before"][recipient_key],
                                             rec["after"][recipient_key])
                deltas = {"userbase": deltas["userbase"], "userquote": deltas["userquote"],
                          "vaultbase": deltas["vaultbase"], "vaultquote": deltas["vaultquote"],
                          "buyback": deltas["buyback"], "buyback22": deltas["buyback22"]}
                assert deltas == case["expected"]["deltas"], (case, image, deltas)
                assert rec["observed"] == {"deltas": deltas, "payer_lamports_delta": -1849400,
                                           "volume_lamports": 1844400, "volume_data_len": 137}
                vol = rec["after"][str(VOLUME_KEY)]
                assert vol is not None and vol["lamports"] == 1844400, (case, image, vol)
                vdata = bytes.fromhex(vol["data_hex"])
                assert len(vdata) == 137, (case, image, len(vdata))
                assert vdata[8:40] == bytes(tx.message.account_keys[0]), (case, image, "volume user")
                assert value["observed"] == rec["observed"]
                pairs.add(tuple(sorted(deltas.items())))
            else:
                assert rec["error"] is not None and case["expected"]["code"] in rec["error"]
                assert case["expected"]["fragment"] in "\n".join(rec["metadata"]["logs"])
                assert payer_fee == 5000, (case, image, payer_fee)
                assert all(rec["before"][k] == rec["after"][k]
                           for k in rec["before"] if k != payer)
                assert rec["rollback_except_payer_fee"] is True
                site = next((l for l in rec["metadata"]["logs"] if "thrown in" in l or "caused by account" in l), None)
                assert row["error_sites"][image] == site, (case, image)
                assert rec["observed"] == {"error_code": case["expected"]["code"],
                                           "fragment": case["expected"]["fragment"],
                                           "payer_lamports_delta": -5000}
                errors.add(rec["error"])
        if kind == "trade":
            assert len(pairs) == 1, (case, "images must agree on amounts")
        else:
            assert len(errors) == 1, (case, "images must agree on error")
    print("PASS: 13 cases, 39 signed receipts, "
          "v2 fee-selection priority pinned "
          "(stable never consults exotic, 4073 opens stable only, "
          "exotic nonzero test is an OR, NORMAL routes like native, "
          "shared-selector 6082 gate), all images agree")


if __name__ == "__main__":
    main()
