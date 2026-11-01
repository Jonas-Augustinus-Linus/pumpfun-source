"""Verify the retained update_fee_config receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, fixtures, sources) hash to
  the recorded values;
- 31 cases (36 case-steps: 26 admin x 1 + 5 chain x 2) x 3 images = 108 receipts, ordered, with contexts matching the
  report, stored as 11 parts (10 x 10 + 8), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each) and its sha256 matches;
- all three images agree on every case step (identical error,
  observed values, and after-states);
- family A (admin-only): the expected error code (or success) and
  error name in the logs, the expected lp / protocol / creator /
  authority / recipient fields in the config after-state, the
  expected config length, payer charged exactly 5,000 lamports,
  the expected event (success: the written values echoed; the
  907/948 truncation cases: the ghost event carrying the NEW
  values while the after-state still holds the fixture values),
  full rollback (config bytes and lamports unchanged) on every
  failure, and config diffs confined to the expected byte ranges
  on every success;
- family B (chains): the update step lands the expected recipient
  list with the 1-event echo (or fails 6012 with the fixture list
  intact, for the failed-update case) at payer 5,000; the legacy
  sell step matches the expected seven token-amount deltas, the
  protocol ATA after-state (849, 165 bytes, rent when created),
  1 event on success, and zero deltas, unchanged pool, no event
  and payer 5,000 on the 6013 failure.

Error sites are checked by error NAME, not line number: per-image site lines are present only in the raw receipt logs, and rebuilt
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

from solders.pubkey import Pubkey
from solders.transaction import Transaction

if not __debug__:
    raise SystemExit("Run without -O")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IMAGES = ("original", "control", "candidate")
EVENT_DISC = "5a1741233ef4bcd0"
SELL_DELTAS = {"userbase": -10 ** 9, "userquote": 180212, "vaultbase": 10 ** 9,
               "vaultquote": -182458, "proto": 849, "creator": 548, "buyback": 849}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(b):
    return bytes(b).hex()


def cfg_bytes(snapshot, key):
    row = snapshot.get(key)
    assert row is not None, f"missing snapshot row {key}"
    return bytes.fromhex(row["data_hex"])


def tok_amount(snapshot, key, offset=64):
    row = snapshot.get(key)
    assert row is not None, f"missing snapshot row {key}"
    return struct.unpack("<Q", bytes.fromhex(row["data_hex"])[offset:offset + 8])[0]


def fixture_config():
    cfg = next(x for x in json.loads(
        (ROOT / "research/imported-lab/analysis/pump_fun/config-snapshot.json"
         ).read_text())["accounts"] if x["program_name"] == "pump_amm")
    return base64.b64decode(cfg["data_base64"])


def fixture_fields():
    raw = fixture_config()
    return {
        "lp": struct.unpack_from("<Q", raw, 40)[0],
        "proto": struct.unpack_from("<Q", raw, 48)[0],
        "recipients": [raw[57 + i * 32:57 + (i + 1) * 32].hex() for i in range(8)],
        "creator": struct.unpack_from("<Q", raw, 313)[0],
        "authority": raw[321:353].hex(),
        "admin": raw[8:40].hex(),
    }


# family A expected: label -> (err_code, site_name, state, length,
#   events, event, payer_delta, rollback, diff_ranges)
# state: (lp, proto, recipients, creator, authority); event: None |
#   (lp, proto, recipients, creator, authority) echoed by the event.
def admin_expected():
    fix = fixture_fields()
    new = [bytes([210 + i]) * 32 for i in range(8)]
    new_sorted = sorted(new, key=bytes)
    new_hex = [hx(b) for b in new_sorted]
    desc = sorted(new, key=bytes, reverse=True)
    base_state = (30, 40, new_hex, 100, hx(bytes([99]) * 32))
    all1000_state = (1000, 1000, new_hex, 1000, hx(bytes([99]) * 32))
    fix_state = (fix["lp"], fix["proto"], fix["recipients"], fix["creator"], fix["authority"])
    ok_ranges = [(40, 56), (57, 313), (313, 321), (321, 353)]
    e = {}
    e["fc-base"] = (None, None, base_state, 949, 1, base_state, 5000, False, ok_ranges)
    e["fc-all-1000"] = (None, None, all1000_state, 949, 1, all1000_state, 5000, False, ok_ranges)
    for lbl in ("fc-lp-1001", "fc-proto-1001", "fc-creator-1001", "fc-lp-u64max"):
        e[lbl] = ("6000", "FeeBasisPointsExceedsMaximum", fix_state, 949, 0, None, 5000, True, None)
    for lbl in ("fc-recip-zero-first", "fc-recip-zero-last"):
        e[lbl] = ("6011", "AllProtocolFeeRecipientsShouldBeNonZero", fix_state, 949, 0, None, 5000, True, None)
    for lbl in ("fc-recip-desc", "fc-recip-dup", "fc-recip-oneswap"):
        e[lbl] = ("6012", "UnsortedNotUniqueProtocolFeeRecipients", fix_state, 949, 0, None, 5000, True, None)
    for lbl in ("fc-lp1001-unsorted", "fc-proto1001-unsorted"):
        e[lbl] = ("6000", "FeeBasisPointsExceedsMaximum", fix_state, 949, 0, None, 5000, True, None)
    e["fc-unsorted-creator1001"] = ("6012", "UnsortedNotUniqueProtocolFeeRecipients", fix_state, 949, 0, None, 5000, True, None)
    e["fc-zero-unsorted"] = ("6011", "AllProtocolFeeRecipientsShouldBeNonZero", fix_state, 949, 0, None, 5000, True, None)
    e["fc-trailing"] = (None, None, base_state, 949, 1, base_state, 5000, False, ok_ranges)
    for lbl in ("fc-args-empty", "fc-args-lp-only", "fc-args-lp-proto"):
        e[lbl] = ("102", "InstructionDidNotDeserialize", fix_state, 949, 0, None, 5000, True, None)
    # ghost events: event echoes the NEW values, state keeps fixture values
    e["fc-trunc-907"] = ("BorshIoError", "BorshIoError", fix_state, 907, 1, base_state, 5000, True, None)
    e["fc-trunc-948"] = ("BorshIoError", "BorshIoError", fix_state, 948, 1, base_state, 5000, True, None)
    e["fc-trunc-906"] = ("InvalidAccountData", "InvalidAccountData", fix_state, 906, 0, None, 5000, True, None)
    e["fc-outsider"] = ("6005", "InvalidAdmin", fix_state, 949, 0, None, 5000, True, None)
    e["fc-unsigned"] = ("3010", "AccountNotSigner", fix_state, 949, 0, None, 5000, True, None)
    e["fc-readonly"] = ("2000", "ConstraintMut", fix_state, 949, 0, None, 5000, True, None)
    e["fc-wrongowner"] = ("3007", "AccountOwnedByWrongProgram", fix_state, 949, 0, None, 5000, True, None)
    return e


# family B expected: label -> (upd, sell)
# upd: ("ok", recip_hex) | ("err", code, site_name)
# sell: ("ok", payer_delta, proto_lamports_or_None) | ("err", code, site_name)
def chain_expected():
    fix = fixture_fields()
    new = [bytes([210 + i]) * 32 for i in range(8)]
    new_hex = [hx(b) for b in sorted(new, key=bytes)]
    return {
        "chain-newrec-sell": (("ok", new_hex), ("ok", 2044280, 2040129)),
        "chain-newrec2-presell": (("ok", new_hex), ("ok", 5000, 2040129)),
        "chain-oldrec-sell": (("ok", new_hex), ("err", "6013", "InvalidProtocolFeeRecipient")),
        "chain-fixture-sell": (("ok", fix["recipients"]), ("ok", 5000, None)),
        "chain-failedupdate-sell": (("err", "6012", "UnsortedNotUniqueProtocolFeeRecipients"), ("ok", 5000, None)),
    }


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    for rel, want in manifest["files"].items():
        got = sha((HERE / rel).read_bytes())
        assert got == want, f"manifest mismatch {rel}: {got} != {want}"
    present = {str(p.relative_to(HERE)) for p in HERE.rglob("*") if p.is_file() and p.name != "MANIFEST.json"}
    assert present == set(manifest["files"]), f"file set mismatch: {present ^ set(manifest['files'])}"
    report = json.loads(gzip.open(HERE / "runtime/report.json.gz", "rt").read())
    assert report["case_count"] == 31, report["case_count"]
    assert report["counts"] == {"vms": 108, "transactions": 108, "signature_fields": 108}, report["counts"]
    assert report["mismatches"] == []
    parts = report["transaction_receipts"]["parts"]
    assert [p["receipts"] for p in parts] == [10] * 10 + [8], parts
    receipts = []
    for part in parts:
        data = (HERE / part["path"]).read_bytes()
        assert sha(data) == part["sha256"], part["path"]
        assert len(data) < 25 * 1024 * 1024, part["path"]
        lines = gzip.decompress(data).decode().splitlines()
        assert len(lines) == part["receipts"], part["path"]
        receipts += [json.loads(l) for l in lines]
    assert len(receipts) == 108, len(receipts)
    for i, r in enumerate(receipts):
        assert r["sequence"] == i and r["vm"] == i, (i, r["sequence"])
        assert r["all_signatures_verified"] and r["signature_fields"] == 1
        raw = base64.b64decode(r["transaction_base64"])
        tx = Transaction.from_bytes(raw)
        checks = tx.verify_with_results()
        assert checks and all(checks) and len(checks) == 1
        assert r["transaction_sha256"] == sha(raw)
        assert r["signatures"] == [str(s) for s in tx.signatures]
    for n, want in report["input_sha256"].items():
        # programs/pump-amm sources are pinned at 6589dcaa9 and kept in inputs/,
        # since later commits on main change the live tree.
        source = HERE / "inputs" / n if n.startswith("programs/") else ROOT / n
        got = sha(source.read_bytes())
        assert got == want, f"input mismatch {n}"
    # contexts must match the report cases, in order
    admin_exp = admin_expected()
    chain_exp = chain_expected()
    fix = fixture_fields()
    expected_ctx = []
    for case_idx, case in enumerate(report["cases"]):
        for image in IMAGES:
            for step_index in range(case["case"]["steps"]):
                expected_ctx.append((case_idx, image, case["case"]["label"],
                                     case["case"]["family"], step_index))
    assert len(expected_ctx) == 108
    for r, exp in zip(receipts, expected_ctx):
        ctx = r["context"]
        assert (ctx["index"], ctx["image"], ctx["label"], ctx["family"], ctx["step"]) == exp, (ctx, exp)
    # per-case, per-step agreement across images + expected values
    by_case = {}
    for r in receipts:
        by_case.setdefault((r["context"]["label"], r["context"]["step"]), []).append(r)
    for (label, step), rs in by_case.items():
        assert len(rs) == 3, (label, step)
        first = rs[0]
        for r in rs[1:]:
            assert r["error"] == first["error"], (label, step, r["error"])
            assert r["observed"] == first["observed"], (label, step)
            assert r["after"] == first["after"], (label, step)
        logs = "\n".join(first["metadata"]["logs"])
        obs = first["observed"]
        # The harness overwrites the config admin with its test payer
        # key (seed [201]*32), so the event admin must equal the
        # receipt transaction's fee payer, derived from the receipt
        # itself rather than from the snapshot file.
        payer_key = bytes(Pubkey.from_string(str(Transaction.from_bytes(
            base64.b64decode(first["transaction_base64"])).message.account_keys[0]))).hex()
        if label in admin_exp:
            assert step == 0
            code, site, state, length, events, event, payer, rollback, ranges = admin_exp[label]
            if code is None:
                assert first["error"] is None, (label, first["error"])
            else:
                assert first["error"] is not None and code in first["error"], (label, first["error"])
                assert site in logs, (label, logs[-500:])
            assert obs["events"] == events, (label, obs["events"])
            assert obs["length"] == length, (label, obs["length"])
            assert obs["payer_delta"] == payer, (label, obs["payer_delta"])
            assert (obs["lp"], obs["proto"], obs["recipients"], obs["creator"], obs["authority"]) == state, (label, obs)
            if event is None:
                assert obs["event"] is None, (label, obs["event"])
            else:
                ev = obs["event"]
                assert ev is not None and ev["disc"] == EVENT_DISC, (label, ev)
                assert ev["admin"] == payer_key, (label, ev["admin"], payer_key)
                assert (ev["lp"], ev["proto"], ev["recipients"], ev["creator"], ev["authority"]) == event, (label, ev)
            if rollback:
                # rollback = the CONFIG account (data + lamports) is
                # identical before/after; the payer always pays the
                # 5,000 fee, so its lamports legitimately move.
                cfg_key = [k for k, v in first["before"].items() if v["data_hex"]][0]
                assert first["before"][cfg_key] == first["after"][cfg_key], (label, "rollback mismatch")
            if ranges is not None:
                cfg_key = [k for k, v in first["before"].items() if v["data_hex"]][0]
                before = cfg_bytes(first["before"], cfg_key)
                after = cfg_bytes(first["after"], cfg_key)
                assert len(before) == len(after)
                diffs = [i for i in range(len(before)) if before[i] != after[i]]
                assert all(any(lo <= i < hi for lo, hi in ranges) for i in diffs), (label, diffs)
        else:
            upd_exp, sell_exp = chain_exp[label]
            if step == 0:
                if upd_exp[0] == "ok":
                    assert first["error"] is None, (label, first["error"])
                    assert obs["events"] == 1, (label, obs["events"])
                    assert obs["recipients"] == upd_exp[1], (label, obs["recipients"])
                    assert (obs["lp"], obs["proto"], obs["creator"]) == (fix["lp"], fix["proto"], fix["creator"]), (label, obs)
                    assert obs["authority"] == fix["authority"], (label, obs["authority"])
                    ev = obs["event"]
                    assert ev is not None and ev["disc"] == EVENT_DISC and ev["admin"] == payer_key, (label, ev, payer_key)
                    assert (ev["lp"], ev["proto"], ev["recipients"], ev["creator"], ev["authority"]) == \
                        (fix["lp"], fix["proto"], upd_exp[1], fix["creator"], fix["authority"]), (label, ev)
                else:
                    assert first["error"] is not None and upd_exp[1] in first["error"], (label, first["error"])
                    assert upd_exp[2] in logs, (label, logs[-500:])
                    assert obs["events"] == 0, (label, obs["events"])
                    assert obs["recipients"] == fix["recipients"], (label, obs["recipients"])
                assert obs["payer_delta"] == 5000, (label, obs["payer_delta"])
            else:
                if sell_exp[0] == "ok":
                    assert first["error"] is None, (label, first["error"])
                    assert obs["deltas"] == SELL_DELTAS, (label, obs["deltas"])
                    assert obs["events"] == 1, (label, obs["events"])
                    assert obs["payer_delta"] == sell_exp[1], (label, obs["payer_delta"])
                    assert obs["proto_after_amount"] == 849, (label, obs["proto_after_amount"])
                    assert obs["proto_after_len"] == 165, (label, obs["proto_after_len"])
                    if sell_exp[2] is not None:
                        assert obs["proto_after_lamports"] == sell_exp[2], (label, obs["proto_after_lamports"])
                else:
                    assert first["error"] is not None and sell_exp[1] in first["error"], (label, first["error"])
                    assert sell_exp[2] in logs, (label, logs[-500:])
                    assert obs["deltas"] == {k: 0 for k in SELL_DELTAS}, (label, obs["deltas"])
                    assert obs["events"] == 0, (label, obs["events"])
                    assert obs["pool_unchanged"], (label, "pool moved")
                    assert obs["payer_delta"] == 5000, (label, obs["payer_delta"])
    print("verify PASS: 31 cases / 36 steps x 3 images = 108 receipts, all checks passed")


if __name__ == "__main__":
    main()
