"""Verify the retained create_pool initial-liquidity receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (original image, harness scripts, fixture) hash to the
  recorded values; control/candidate are the in-repo #424/#427 artifacts;
- 19 cases x 3 images = 57 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases: exactly 1 CreatePoolEvent (discriminator
  b1310cd2a076a774) whose fixed-offset fields match the recorded
  values (base_in @116, quote_in @124, pool_base @132,
  pool_quote @140, min_liq @148, init_liq @156, lp_out @164);
  init_liq == floor(sqrt(pool_base * pool_quote)); the pool
  account stores lp_supply == init_liq, a zero coin_creator,
  zero mayhem / cashback flags, zero virtual quote reserves,
  zero creator fee bps, zero protocol / creator fees; the user
  LP account and the LP mint supply both equal lp_out ==
  init_liq - 100; the vaults hold exactly pool_base /
  pool_quote; the user token accounts fall by exactly base_in /
  quote_in; the payer is charged exactly the recorded amount
  (10,507,640 fresh, minus 2,039,280 per pre-existing vault);
- error cases: fail with exactly 6003
  TooLittlePoolTokenLiquidity, carry the recorded per-image
  site line in their logs, emit 0 events, create no pool / LP
  mint / user LP account, leave both vaults and both user
  token accounts exactly as before, and charge the payer
  5,000 only;
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case.
"""
import base64
import gzip
import hashlib
import json
import math
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
EVENT_DISC = "b1310cd2a076a774"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def amount_at(data_hex, offset=64):
    return struct.unpack_from("<Q", bytes.fromhex(data_hex), offset)[0]


def event_fields(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    if raw[:8].hex() != EVENT_DISC or len(raw) < 344:
        return None
    return {
        "base_in": struct.unpack_from("<Q", raw, 116)[0],
        "quote_in": struct.unpack_from("<Q", raw, 124)[0],
        "pool_base": struct.unpack_from("<Q", raw, 132)[0],
        "pool_quote": struct.unpack_from("<Q", raw, 140)[0],
        "min_liq": struct.unpack_from("<Q", raw, 148)[0],
        "init_liq": struct.unpack_from("<Q", raw, 156)[0],
        "lp_out": struct.unpack_from("<Q", raw, 164)[0],
    }


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    present = {str(p.relative_to(HERE)) for p in HERE.rglob("*")
               if p.is_file() and p.name != "MANIFEST.json"}
    assert set(manifest["files"]) == present, (
        "manifest mismatch", set(manifest["files"]) ^ present)
    for rel, digest in manifest["files"].items():
        assert sha((HERE / rel).read_bytes()) == digest, rel
    report = json.loads(gzip.decompress(
        (HERE / "runtime/report.json.gz").read_bytes()))
    assert report["case_count"] == 19, report["case_count"]
    assert report["mismatches"] == [] and report["divergent_cases"] == []
    for rel, digest in report["input_sha256"].items():
        assert sha((ROOT / rel).read_bytes()) == digest, rel
    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (HERE / part["path"]).read_bytes()
        assert len(data) < 25 * 1024 * 1024, part["path"]
        assert sha(data) == part["sha256"], part["path"]
        chunk = [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l]
        assert len(chunk) == part["receipts"], part["path"]
        receipts.extend(chunk)
    assert len(receipts) == 57, len(receipts)
    assert report["counts"] == {"vms": 57, "transactions": 57, "signature_fields": 57}
    for seq, r in enumerate(receipts):
        assert r["sequence"] == seq and r["vm"] == seq, seq
        assert r["all_signatures_verified"] is True and r["signature_fields"] == 1, seq
        tx = Transaction.from_bytes(base64.b64decode(r["transaction_base64"]))
        assert tx.verify_with_results() and all(tx.verify_with_results()), seq
        assert str(tx.signatures[0]) == r["signatures"][0], seq
        assert r["transaction_sha256"] == sha(base64.b64decode(r["transaction_base64"])), seq
    by_case = {}
    for r in receipts:
        by_case.setdefault(r["context"]["label"], {})[r["context"]["image"]] = r
    assert len(by_case) == 19, len(by_case)
    for case in report["cases"]:
        label = case["case"]["label"]
        exp = case["case"]["expected"]
        obs_seen = set()
        for image in IMAGES:
            r = by_case[label][image]
            roles, before, after = r["roles"], r["before"], r["after"]
            logs = r["metadata"]["logs"]
            n_events = len([l for l in logs if l.startswith("Program data: ")])
            assert n_events == r["metadata"]["events"], (label, image)
            payer_delta = (after[roles["fee_payer"]]["lamports"]
                           - before[roles["fee_payer"]]["lamports"])
            assert payer_delta == r["payer_delta_lamports"], (label, image)
            if exp["kind"] == "ok":
                assert r["error"] is None and r["rollback_except_payer_fee"] is False, (label, image)
                assert n_events == 1, (label, image)
                ev = event_fields(logs)
                assert ev is not None, (label, image)
                assert ev["base_in"] == case["case"]["base_in"], (label, image, ev)
                assert ev["quote_in"] == case["case"]["quote_in"], (label, image, ev)
                assert ev["pool_base"] == case["case"]["pool_base"], (label, image, ev)
                assert ev["pool_quote"] == case["case"]["pool_quote"], (label, image, ev)
                assert ev["min_liq"] == 100 and ev["init_liq"] == exp["init_liq"], (label, image, ev)
                assert ev["lp_out"] == exp["lp_out"], (label, image, ev)
                assert ev["init_liq"] == math.isqrt(ev["pool_base"] * ev["pool_quote"]), (label, image)
                assert ev["lp_out"] == ev["init_liq"] - 100, (label, image)
                pool = bytes.fromhex(after[roles["pool"]]["data_hex"])
                assert struct.unpack_from("<Q", pool, 203)[0] == exp["init_liq"], (label, image)
                assert pool[211:243] == bytes(32) and pool[243] == 0 and pool[244] == 0, (label, image)
                assert int.from_bytes(pool[245:261], "little", signed=True) == 0, (label, image)
                assert struct.unpack_from("<Q", pool, 261)[0] == 0 and pool[269] == 0, (label, image)
                assert pool[270] == 0 and struct.unpack_from("<Q", pool, 271)[0] == 0, (label, image)
                assert struct.unpack_from("<Q", pool, 279)[0] == 0, (label, image)
                assert amount_at(after[roles["user_lp"]]["data_hex"]) == exp["lp_out"], (label, image)
                assert amount_at(after[roles["lp_mint"]]["data_hex"], 36) == exp["lp_out"], (label, image)
                assert amount_at(after[roles["vault_base"]]["data_hex"]) == case["case"]["pool_base"], (label, image)
                assert amount_at(after[roles["vault_quote"]]["data_hex"]) == case["case"]["pool_quote"], (label, image)
                assert (before[roles["userbase"]]["data_hex"] is not None
                        and amount_at(before[roles["userbase"]]["data_hex"])
                        - amount_at(after[roles["userbase"]]["data_hex"])
                        == case["case"]["base_in"]), (label, image)
                assert (amount_at(before[roles["userquote"]]["data_hex"])
                        - amount_at(after[roles["userquote"]]["data_hex"])
                        == case["case"]["quote_in"]), (label, image)
                assert payer_delta == exp["payer_delta"], (label, image, payer_delta)
            else:
                assert r["error"] is not None and r["rollback_except_payer_fee"] is True, (label, image)
                assert str(exp["code"]) in r["error"], (label, image, r["error"])
                assert exp["fragment"] in "\n".join(logs), (label, image)
                site = case["error_sites"][image]
                assert site in "\n".join(logs), (label, image, site)
                assert n_events == 0, (label, image)
                assert after[roles["pool"]] is None, (label, image)
                assert after[roles["lp_mint"]] is None, (label, image)
                assert after[roles["user_lp"]] is None, (label, image)
                assert after[roles["vault_base"]] == before[roles["vault_base"]], (label, image)
                assert after[roles["vault_quote"]] == before[roles["vault_quote"]], (label, image)
                assert after[roles["userbase"]] == before[roles["userbase"]], (label, image)
                assert after[roles["userquote"]] == before[roles["userquote"]], (label, image)
                assert payer_delta == -5000, (label, image, payer_delta)
            obs_seen.add(json.dumps(r["observed"], sort_keys=True))
        assert len(obs_seen) == 1, (label, "images must agree", obs_seen)
    print("verify PASS: 19 cases x 3 images = 57 receipts, all checks passed")


if __name__ == "__main__":
    main()
