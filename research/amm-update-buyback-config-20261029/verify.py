"""Verify the retained update_buyback_config receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, fixtures, sources) hash to
  the recorded values;
- 34 cases x 3 images = 123 receipts (27 admin cases x 1 step +
  7 chain cases x 2 steps), ordered, with contexts matching the
  report, stored as 13 parts (12 x 10 + 3), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each) and its sha256 matches;
- all three images agree on every case step (identical error,
  observed values, and after-states);
- family A (admin-only): the expected error code (or success) and
  error name in the logs, the expected buyback_basis_points and
  recipient list in the config after-state, the expected config
  length, payer charged exactly 5,000 lamports, 0 events on every
  step, full rollback (config bytes and lamports unchanged) on
  every failure, and config diffs confined to the expected byte
  ranges on every success;
- family B (chains): the update step is silent, charges 5,000,
  and lands the expected bps / recipient list; the trade step
  matches the expected five token-amount deltas, the decoded
  BuyEvent/SellEvent fields, and the pool state
  (virtual_quote_reserves, protocol_fees, creator_fees), with
  payer 1,849,400 on success (volume accumulator 1,844,400
  lamports, 137 bytes, payer key at [8:40]) and payer 5,000 with
  zero deltas, unchanged pool, and no event on the 6053 failure.

Error sites are checked by error NAME, not line number: the
producer records per-image site lines in its own run, and rebuilt
images may report different lines for the same error (the #36
precedent), so only the code and the name are asserted here.
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
BUY_OFFS = (64, 72, 80, 88, 96, 104, 112, 344, 352, 427, 435, 468, 476, 484)
SELL_OFFS = (64, 72, 80, 88, 96, 104, 112, 344, 352, 376, 384, 417, 425, 433)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(b):
    return bytes(b).hex()


def tok_amount(snapshot, key, offset=64):
    row = snapshot.get(key)
    assert row is not None, f"missing snapshot row {key}"
    return struct.unpack("<Q", bytes.fromhex(row["data_hex"])[offset:offset + 8])[0]


def fixture_recipients():
    cfg = next(x for x in json.loads(
        (ROOT / "research/imported-lab/analysis/pump_fun/config-snapshot.json"
         ).read_text())["accounts"] if x["program_name"] == "pump_amm")
    raw = base64.b64decode(cfg["data_base64"])
    return [raw[643 + i * 32:643 + (i + 1) * 32].hex() for i in range(8)]


# family A expected: label -> (err_code, site_name, bps, recipients,
#   length, payer_delta, rollback, diff_ranges)
# recipients: list of hex strings. For bb-trunc-906 the bps field
# (899..907) is unreadable but recipients (643..899) still read.
def admin_expected():
    fix = fixture_recipients()
    new = [bytes([210 + i]) * 32 for i in range(9)]
    unsorted = sorted(new[:8], reverse=True)
    new8 = new[:8]
    return {
        "bb-none-noop": (None, None, 5000, fix, 949, 5000, True, []),
        "bb-set-0": (None, None, 0, fix, 949, 5000, False, [(899, 907)]),
        "bb-set-1": (None, None, 1, fix, 949, 5000, False, [(899, 907)]),
        "bb-set-7500": (None, None, 7500, fix, 949, 5000, False, [(899, 907)]),
        "bb-set-9999": (None, None, 9999, fix, 949, 5000, False, [(899, 907)]),
        "bb-set-10000": (None, None, 10000, fix, 949, 5000, False, [(899, 907)]),
        "bb-set-10001": ("6056", "BuybackBasisPointsOutOfRange", 5000, fix, 949, 5000, True, None),
        "bb-set-u64max": ("6056", "BuybackBasisPointsOutOfRange", 5000, fix, 949, 5000, True, None),
        "bb-recip-unsorted8": (None, None, 5000, [hx(b) for b in unsorted], 949, 5000, False, [(643, 899)]),
        "bb-both-6000-new8": (None, None, 6000, [hx(b) for b in new8], 949, 5000, False, [(643, 907)]),
        "bb-recip-7": ("6057", "WrongBuybackFeeRecipientsCount", 5000, fix, 949, 5000, True, None),
        "bb-recip-9": ("6057", "WrongBuybackFeeRecipientsCount", 5000, fix, 949, 5000, True, None),
        "bb-recip-default": ("6054", "AllBuybackFeeRecipientsShouldBeNonZero", 5000, fix, 949, 5000, True, None),
        "bb-recip-dup": ("6055", "NotUniqueBuybackFeeRecipients", 5000, fix, 949, 5000, True, None),
        "bb-bps6000-duprecip": ("6055", "NotUniqueBuybackFeeRecipients", 5000, fix, 949, 5000, True, None),
        "bb-bps10001-duprecip": ("6056", "BuybackBasisPointsOutOfRange", 5000, fix, 949, 5000, True, None),
        "bb-outsider": ("6005", "InvalidAdmin", 5000, fix, 949, 5000, True, None),
        "bb-unsigned": ("3010", "AccountNotSigner", 5000, fix, 949, 5000, True, None),
        "bb-readonly": ("2000", "ConstraintMut", 5000, fix, 949, 5000, True, None),
        "bb-wrongowner": ("3007", "AccountOwnedByWrongProgram", 5000, fix, 949, 5000, True, None),
        "bb-args-empty": ("102", "InstructionDidNotDeserialize", 5000, fix, 949, 5000, True, None),
        "bb-args-tag2": ("102", "InstructionDidNotDeserialize", 5000, fix, 949, 5000, True, None),
        "bb-args-trailing": (None, None, 6000, fix, 949, 5000, False, [(899, 907)]),
        "bb-trunc-907": ("BorshIoError", "BorshIoError", 5000, fix, 907, 5000, True, None),
        "bb-trunc-948": ("BorshIoError", "BorshIoError", 5000, fix, 948, 5000, True, None),
        "bb-trunc-906": ("InvalidAccountData", "InvalidAccountData", None, fix, 906, 5000, True, None),
        "bb-trunc-907-recip": ("BorshIoError", "BorshIoError", 5000, fix, 907, 5000, True, None),
    }


# family B expected: label -> (update_bps, update_recipients, trade)
# update_recipients: "fixture" | "chain_new8" | "chain_old8"
# trade: ("ok", deltas, event, pool_state) | ("err", code)
def chain_expected():
    fix = fixture_recipients()
    newrec = bytes([240]) * 32
    chain_new8 = [newrec.hex()] + [(bytes([241 + i]) * 32).hex() for i in range(7)]
    chain_old8 = [(bytes([248 + i]) * 32).hex() for i in range(8)]
    return {
        "chain-bps7500-buy": (7500, fix, ("ok",
            {"userbase": 10 ** 6, "userquote": -10425, "vaultbase": -10 ** 6,
             "vaultquote": 10341, "buyback": 84},
            (10001, 10, 11, 111, 112, 10012, 10425, 300, 301, 7500, 84, 0, 0, 301),
            [-329, 28, 301])),
        "chain-bps10000-buy": (10000, fix, ("ok",
            {"userbase": 10 ** 6, "userquote": -10425, "vaultbase": -10 ** 6,
             "vaultquote": 10313, "buyback": 112},
            (10001, 10, 11, 111, 112, 10012, 10425, 300, 301, 10000, 112, 0, 0, 301),
            [-301, 0, 301])),
        "chain-bps0-buy": (0, fix, ("ok",
            {"userbase": 10 ** 6, "userquote": -10425, "vaultbase": -10 ** 6,
             "vaultquote": 10425, "buyback": 0},
            (10001, 10, 11, 111, 112, 10012, 10425, 300, 301, 0, 0, 0, 0, 301),
            [-413, 112, 301])),
        "chain-bps7500-sell": (7500, fix, ("ok",
            {"userbase": -10 ** 6, "userquote": 9578, "vaultbase": 10 ** 6,
             "vaultquote": -9661, "buyback": 83},
            (9999, 10, 10, 111, 111, 9989, 9578, 300, 300, 7500, 83, 0, 0, 300),
            [-328, 28, 300])),
        "chain-recip-new-buy": (5000, chain_new8, ("ok",
            {"userbase": 10 ** 6, "userquote": -10425, "vaultbase": -10 ** 6,
             "vaultquote": 10369, "buyback": 56},
            (10001, 10, 11, 111, 112, 10012, 10425, 300, 301, 5000, 56, 0, 0, 301),
            [-357, 56, 301])),
        "chain-recip-old-buy": (5000, chain_old8, ("err", "6053")),
        "chain-both-buy": (7500, chain_new8, ("ok",
            {"userbase": 10 ** 6, "userquote": -10425, "vaultbase": -10 ** 6,
             "vaultquote": 10341, "buyback": 84},
            (10001, 10, 11, 111, 112, 10012, 10425, 300, 301, 7500, 84, 0, 0, 301),
            [-329, 28, 301])),
    }


def cfg_of(snapshot, key):
    row = snapshot.get(key)
    assert row is not None, f"missing config row {key}"
    return bytes.fromhex(row["data_hex"])


def check_admin_receipt(label, image, step, r, exp):
    code, site, bps, recip, length, payer_delta, rollback, diffs = exp
    obs = r["observed"]
    err = r["error"]
    if code is None:
        assert err is None, (label, image, step, err)
    else:
        assert err is not None and code in err, (label, image, step, err)
    if site is not None:
        logs = "\n".join(r["metadata"]["logs"])
        assert site in logs, (label, image, step, site)
    assert obs["events"] == 0, (label, image, step, obs["events"])
    assert obs["bps"] == bps, (label, image, step, obs["bps"], bps)
    assert obs["recipients"] == recip, (label, image, step, obs["recipients"], recip)
    assert obs["length"] == length, (label, image, step, obs["length"])
    assert obs["payer_delta"] == payer_delta, (label, image, step, obs["payer_delta"])
    # config key: the non-payer key in the before snapshot
    before = r["before"]
    after = r["after"]
    payer_keys = [k for k in before if before[k]["data_hex"] == ""]
    assert len(payer_keys) == 1, (label, image, step, payer_keys)
    cfg_keys = [k for k in before if k not in payer_keys]
    assert len(cfg_keys) == 1, (label, image, step, cfg_keys)
    ck = cfg_keys[0]
    bdata = bytes.fromhex(before[ck]["data_hex"])
    adata = bytes.fromhex(after[ck]["data_hex"])
    assert before[ck]["lamports"] == after[ck]["lamports"], (label, image, step, "cfg lamports moved")
    assert before[payer_keys[0]]["lamports"] - after[payer_keys[0]]["lamports"] == payer_delta, \
        (label, image, step, "payer delta mismatch")
    if rollback:
        assert bdata == adata, (label, image, step, "expected rollback")
        assert obs["rollback"], (label, image, step, "rollback flag")
    if diffs is not None:
        assert len(bdata) == len(adata), (label, image, step, "length changed")
        got = [i for i in range(len(bdata)) if bdata[i] != adata[i]]
        if not diffs:
            assert got == [], (label, image, step, got)
        else:
            assert all(any(lo <= i < hi for lo, hi in diffs) for i in got), \
                (label, image, step, got)


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
    assert [p["receipts"] for p in parts] == [10] * 12 + [3]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 34
    assert len(receipts) == 123
    assert report["counts"]["vms"] == 123
    assert report["counts"]["transactions"] == 123
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 123
    assert report["mismatches"] == []
    for seq, r in enumerate(receipts):
        assert r["sequence"] == seq, seq
        raw = base64.b64decode(r["transaction_base64"])
        tx = Transaction.from_bytes(raw)
        checks = tx.verify_with_results()
        assert checks and all(checks) and len(checks) == 1, seq
        assert r["transaction_sha256"] == sha(raw), seq
        assert r["all_signatures_verified"] and r["signature_fields"] == 1, seq

    # group by (case index, step) and check 3-image agreement
    by_step = {}
    for r in receipts:
        ctx = r["context"]
        by_step.setdefault((ctx["index"], ctx["step"]), {})[ctx["image"]] = r
    assert len(by_step) == 27 * 1 + 7 * 2
    for (index, step), per_image in sorted(by_step.items()):
        assert set(per_image) == set(IMAGES), (index, step, set(per_image))
        first = per_image["original"]
        for image in ("control", "candidate"):
            other = per_image[image]
            assert other["error"] == first["error"], (index, step, image)
            assert other["observed"] == first["observed"], (index, step, image)
            assert other["after"] == first["after"], (index, step, image)

    a_exp = admin_expected()
    c_exp = chain_expected()
    labels = [c["case"]["label"] for c in report["cases"]]
    for idx, case in enumerate(report["cases"]):
        label = case["case"]["label"]
        family = case["case"]["family"]
        assert labels.index(label) == idx, (label, idx)
        if family == "admin":
            assert label in a_exp, label
            assert case["case"]["steps"] == 1
            for image in IMAGES:
                check_admin_receipt(label, image, 0, by_step[(idx, 0)][image], a_exp[label])
        else:
            assert label in c_exp, label
            assert case["case"]["steps"] == 2
            upd_bps, upd_recip, trade = c_exp[label]
            instr = case["case"]["instruction"]
            for image in IMAGES:
                r0 = by_step[(idx, 0)][image]
                assert r0["error"] is None, (label, image, r0["error"])
                assert r0["observed"]["events"] == 0, (label, image, "update must be silent")
                assert r0["observed"]["bps"] == upd_bps, (label, image, r0["observed"]["bps"])
                assert r0["observed"]["recipients"] == upd_recip, (label, image, "update recipients")
                assert r0["observed"]["payer_delta"] == 5000, (label, image)
                r1 = by_step[(idx, 1)][image]
                obs = r1["observed"]
                if trade[0] == "ok":
                    _, deltas, event, pool_state = trade
                    assert obs["error"] is None, (label, image, obs["error"])
                    assert obs["deltas"] == deltas, (label, image, obs["deltas"], deltas)
                    assert obs["event"] == list(event), (label, image, obs["event"], event)
                    assert obs["pool_state"] == pool_state, (label, image, obs["pool_state"])
                    assert obs["payer_delta"] == 1849400, (label, image, obs["payer_delta"])
                    assert obs["volume_lamports"] == 1844400 and obs["volume_len"] == 137, (label, image)
                    # independent volume-accumulator check from snapshots
                    before, after = r1["before"], r1["after"]
                    # pool key: the 300-byte account; volume key: 137-byte after
                    vol_after = [v for v in after.values()
                                 if v is not None and len(bytes.fromhex(v["data_hex"])) == 137]
                    assert len(vol_after) == 1, (label, image, "volume")
                    assert vol_after[0]["lamports"] == 1844400, (label, image)
                    # event line count and fields from raw logs
                    ev_lines = [l for l in r1["metadata"]["logs"] if l.startswith("Program data: ")]
                    assert len(ev_lines) == 1, (label, image, len(ev_lines))
                    raw_ev = base64.b64decode(ev_lines[0].split("Program data: ", 1)[1].strip())
                    offs = BUY_OFFS if instr == "buy_v2" else SELL_OFFS
                    got = tuple(struct.unpack_from("<Q", raw_ev, o)[0] for o in offs)
                    assert got == event, (label, image, got, event)
                else:
                    _, code = trade
                    assert obs["error"] is not None and code in obs["error"], (label, image, obs["error"])
                    assert obs["deltas"] == {"userbase": 0, "userquote": 0, "vaultbase": 0,
                                             "vaultquote": 0, "buyback": 0}, (label, image, obs["deltas"])
                    assert obs["event"] is None, (label, image)
                    assert obs["pool_state"] == [0, 0, 0], (label, image)
                    assert obs["payer_delta"] == 5000, (label, image, obs["payer_delta"])
                    assert obs["volume_lamports"] == 0 and obs["volume_len"] == 0, (label, image)
                    ev_lines = [l for l in r1["metadata"]["logs"] if l.startswith("Program data: ")]
                    assert len(ev_lines) == 0, (label, image, "failure must emit no event")
    print("verify PASS: 34 cases x 3 images = 123 receipts, all checks passed")


if __name__ == "__main__":
    main()
