"""Verify the retained legacy-buy cashback receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 42 cases x 3 images = 126 receipts, ordered, with contexts
  matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases: the recorded error is None, exactly 1 event whose
  decoded fields (buy 497 bytes: curve @64, lp @80, protocol @96,
  quote-with-lp @104, user-quote-in @112, creator_bps @344,
  creator_fee @352, track @360, min_base @393, cashback_bps @408,
  cashback @416, buyback_bps @424, buyback_fee @432; buy_exact
  512 bytes: cashback_bps @423, cashback @431, buyback_bps @439,
  buyback_fee @447) match the recorded event, token deltas
  recomputed from the before/after snapshots via the receipt roles
  match the recorded deltas, the volume accumulator's
  cashback_earned / current_sol_volume / lamports match, the
  cashback ATA lamports match, withheld transfer fees recomputed
  from the snapshots (178-byte accounts @170, 182-byte accounts
  @174) match, and the payer delta matches;
- failure cases: the recorded error code appears (in the error
  string or the logs), 0 events, every non-payer watched account
  is byte identical before/after, the payer delta matches, and
  where a per-image site line was recorded it appears verbatim
  in that image's logs;
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case's observed values.
"""
if not __debug__:
    raise SystemExit("Run without -O")

import base64
import gzip
import hashlib
import json
import struct
import importlib.util
import sys
sys.dont_write_bytecode = True
from pathlib import Path

from solders.transaction import Transaction

if not __debug__:
    raise SystemExit("Run without -O")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IMAGES = ("original", "control", "candidate")

CASE_DEFINITIONS_SHA256 = '967369a1b3a00687b47b6de4cdcadf694d8cd7a602fed282a5abb7d3fd5d4845'
CASE_INPUTS_SHA256 = '2a7a4248bb66b15e44ca474574ce0477661af4838865277949e100bd39965938'
PRODUCER_SHA256 = 'fa9786b81ff126c016f5ffea8330ea585d753684f84ebd811bc6a0b6ff3cad83'
ORIGINAL_INPUT_PINS = {'evidence/original/pump_amm/deployed.so': '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7', 'evidence/original/pump_fees/deployed.so': '4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e', 'evidence/dependencies/spl_token/deployed.so': '8190d3f7ceb6cb7a7a8d8924bff89f9f611e15ce1f806f2b6237f3311a98f697', 'evidence/dependencies/spl_token_2022/deployed.so': '15a2e615a42e20f31714bbaaee43002ae6f1cda2e8d7118243117ab3c1342e2d', 'evidence/dependencies/associated_token/deployed.so': '6804554e69fd3a58caa191dc4a58f4c67223d30ca28ab8987f39fc18d2f7374d', 'scripts/pump_amm_legacy_buy_differential.py': 'f50117d8d9cfb15ab540c467a6bc50c135ad7878b84fba71adb370436ed1097d', 'scripts/pump_amm_legacy_sell_differential.py': 'f9c889069563cc133f29568d185ea068a3b106c67c3f6a75389af824dca8db66', 'scripts/pump_amm_trade_v2_differential.py': 'a66c8bac5eb610392aef041f716428038b297e42e24af0a54a4a4715d9c5c6bb', 'scripts/pump_amm_reusable_harness.py': '19b7b2439db913e8dd187deba0aa561aa537bfe06a35007470e0f215c94f1cf2'}
CORRESPONDENCE_INPUT_PINS = {'evidence/original/pump_amm/deployed.so': '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7', 'evidence/original/pump_fees/deployed.so': '4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e', 'evidence/dependencies/spl_token/deployed.so': '8190d3f7ceb6cb7a7a8d8924bff89f9f611e15ce1f806f2b6237f3311a98f697', 'evidence/dependencies/spl_token_2022/deployed.so': '15a2e615a42e20f31714bbaaee43002ae6f1cda2e8d7118243117ab3c1342e2d', 'evidence/dependencies/associated_token/deployed.so': '6804554e69fd3a58caa191dc4a58f4c67223d30ca28ab8987f39fc18d2f7374d', 'scripts/pump_amm_legacy_buy_differential.py': 'f50117d8d9cfb15ab540c467a6bc50c135ad7878b84fba71adb370436ed1097d', 'scripts/pump_amm_legacy_sell_differential.py': 'f9c889069563cc133f29568d185ea068a3b106c67c3f6a75389af824dca8db66', 'scripts/pump_amm_trade_v2_differential.py': 'a66c8bac5eb610392aef041f716428038b297e42e24af0a54a4a4715d9c5c6bb', 'scripts/pump_amm_reusable_harness.py': '19b7b2439db913e8dd187deba0aa561aa537bfe06a35007470e0f215c94f1cf2', 'evidence/upstream/pump_amm.json': 'b7d8c57a4d9c4dd0109a9ab893052352333252d4eedced10ac091d4d66cab89b', 'research/imported-lab/analysis/pump_fun/amm-v2-trade-fixture.json': '2e775505852caf55203c826ee08b9341aa275f52f59a933c4fb0740535ee316f', 'research/imported-lab/analysis/pump_fun/config-snapshot.json': '17b886a6b4aa7fdc89f2fca9a1b67b318d33998794da59fe4df1fe89ca70bd27', 'scripts/pump_amm_admin_differential.py': 'cc3834231f951e3dbf36f38504d85f3135c0edf3792fabecd12fae10c493a72b', 'scripts/pump_amm_liquidity_differential.py': '08449c9da8c560330eeb5b560a26cdd553d260084e78bd54d4dc7edb914320b4'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def amount_at(data_hex, offset=64):
    if data_hex is None:
        return None
    raw = bytes.fromhex(data_hex)
    if len(raw) < offset + 8:
        return None
    return struct.unpack_from("<Q", raw, offset)[0]


def withheld_at(data_hex):
    if data_hex is None:
        return None
    raw = bytes.fromhex(data_hex)
    if len(raw) == 178:
        return struct.unpack_from("<Q", raw, 170)[0]
    if len(raw) == 182:
        return struct.unpack_from("<Q", raw, 174)[0]
    return None


def vol_field(data_hex, offset):
    if data_hex is None:
        return None
    raw = bytes.fromhex(data_hex)
    if len(raw) < offset + 8:
        return None
    return struct.unpack_from("<Q", raw, offset)[0]


def decode_buy_event(logs, exact):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    if raw[:8] != bytes.fromhex("67f4521f2cf57777") or len(raw) != (512 if exact else 497):
        return None
    ev = {"out": struct.unpack_from("<Q", raw, 16)[0],
          "max": struct.unpack_from("<Q", raw, 24)[0],
          "curve": struct.unpack_from("<Q", raw, 64)[0],
          "lp_bps": struct.unpack_from("<Q", raw, 72)[0],
          "lp": struct.unpack_from("<Q", raw, 80)[0],
          "proto_bps": struct.unpack_from("<Q", raw, 88)[0],
          "proto": struct.unpack_from("<Q", raw, 96)[0],
          "qwlp": struct.unpack_from("<Q", raw, 104)[0],
          "uqin": struct.unpack_from("<Q", raw, 112)[0],
          "creator_bps": struct.unpack_from("<Q", raw, 344)[0],
          "creator": struct.unpack_from("<Q", raw, 352)[0],
          "track": raw[360],
          "min_base": struct.unpack_from("<Q", raw, 393)[0]}
    if exact:
        ev.update({"cb_bps": struct.unpack_from("<Q", raw, 423)[0],
                   "cb": struct.unpack_from("<Q", raw, 431)[0],
                   "bb_bps": struct.unpack_from("<Q", raw, 439)[0],
                   "bb": struct.unpack_from("<Q", raw, 447)[0]})
    else:
        ev.update({"cb_bps": struct.unpack_from("<Q", raw, 408)[0],
                   "cb": struct.unpack_from("<Q", raw, 416)[0],
                   "bb_bps": struct.unpack_from("<Q", raw, 424)[0],
                   "bb": struct.unpack_from("<Q", raw, 432)[0]})
    return ev


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
    assert report["input_sha256"] == ORIGINAL_INPUT_PINS, "exact retained repository input map"
    assert report["case_count"] == 42, report["case_count"]
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
    assert len(receipts) == 126, len(receipts)
    assert report["counts"] == {"vms": 126, "transactions": 126, "signature_fields": 126}
    spec = importlib.util.spec_from_file_location("legacy_buy_correspondence", HERE / "correspondence.py")
    proof = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proof)
    bound = proof.prepare(ROOT, HERE, report, receipts, CASE_DEFINITIONS_SHA256, CASE_INPUTS_SHA256, PRODUCER_SHA256, CORRESPONDENCE_INPUT_PINS)
    for seq, r in enumerate(receipts):
        proof.check(r, report["cases"][seq // 3]["case"], bound)
        assert r["sequence"] == seq and r["vm"] == seq, seq
        assert r["all_signatures_verified"] is True and r["signature_fields"] == 1, seq
        tx = Transaction.from_bytes(base64.b64decode(r["transaction_base64"]))
        assert tx.verify_with_results() and all(tx.verify_with_results()), seq
        assert str(tx.signatures[0]) == r["signatures"][0], seq
        assert r["transaction_sha256"] == sha(base64.b64decode(r["transaction_base64"])), seq
        assert r["payer_delta_lamports"] == r["observed"]["payer_paid"], seq
    by_case = {}
    for r in receipts:
        ctx = r["context"]
        by_case.setdefault(ctx["label"], {}).setdefault(ctx["image"], []).append(r)
    assert len(by_case) == 42, len(by_case)
    for case in report["cases"]:
        label = case["case"]["label"]
        ix_name = case["case"]["instruction"]
        exact = ix_name == "buy_exact_quote_in"
        exp = case["case"]["expected"]
        obs_seen = set()
        for image in IMAGES:
            steps = by_case[label][image]
            assert len(steps) == 1, (label, image)
            r = steps[0]
            roles, before, after = r["roles"], r["before"], r["after"]
            logs = r["metadata"]["logs"]
            obs = r["observed"]
            obs_seen.add(json.dumps(obs, sort_keys=True))
            payer = roles["fee_payer"]
            payer_paid = before[payer]["lamports"] - after[payer]["lamports"] \
                if before.get(payer) and after.get(payer) else None
            assert payer_paid == obs["payer_paid"], (label, image, payer_paid)
            vol_b, vol_a = before.get(roles["volume"]), after.get(roles["volume"])
            vol = {"earned_before": vol_field(vol_b["data_hex"], 74) if vol_b else None,
                   "earned_after": vol_field(vol_a["data_hex"], 74) if vol_a else None,
                   "sol_before": vol_field(vol_b["data_hex"], 57) if vol_b else None,
                   "sol_after": vol_field(vol_a["data_hex"], 57) if vol_a else None,
                   "lamports_before": vol_b["lamports"] if vol_b else None,
                   "lamports_after": vol_a["lamports"] if vol_a else None}
            assert vol == obs["volume"], (label, image, vol, obs["volume"])
            uva_b, uva_a = before.get(roles["uvata"]), after.get(roles["uvata"])
            uvata_lamports = [uva_b["lamports"] if uva_b else None,
                              uva_a["lamports"] if uva_a else None]
            assert uvata_lamports == obs["uvata_lamports"], (label, image, uvata_lamports)
            if exp["kind"] == "ok":
                assert r["error"] is None, (label, image, r["error"])
                assert r["metadata"]["events"] == 1, (label, image)
                assert decode_buy_event(logs, exact) == obs["event"], (label, image, "BuyEvent discriminator/fields")
                deltas = {}
                for name in obs["deltas"]:
                    key = roles[name]
                    b, a = before.get(key), after.get(key)
                    assert a, (label, image, name)
                    b_amt = amount_at(b["data_hex"]) if b else 0
                    deltas[name] = amount_at(a["data_hex"]) - b_amt
                assert deltas == obs["deltas"], (label, image, deltas)
                withheld = {}
                for name, key in roles.items():
                    if name in ("fee_payer", "pool", "global_config", "volume"):
                        continue
                    snap = after.get(key)
                    w = withheld_at(snap["data_hex"]) if snap else None
                    if w is not None:
                        withheld[name] = w
                assert withheld == obs["withheld"], (label, image, withheld)
            else:
                assert r["error"] is not None, (label, image)
                assert exp["code"] in r["error"], (label, image, r["error"])
                assert exp["fragment"] in (r["error"] or "") or exp["fragment"] in "\n".join(logs), \
                    (label, image)
                assert r["metadata"]["events"] == 0, (label, image)
                assert obs["rollback"] is True, (label, image)
                for key, snap_b in before.items():
                    if key == payer:
                        continue
                    assert snap_b == after.get(key), (label, image, key, "no rollback")
                site = (case.get("error_sites") or {}).get(image)
                if site:
                    assert site in "\n".join(logs), (label, image, site)
        assert len(obs_seen) == 1, (label, "images must agree", obs_seen)
    print("verify PASS: 42 cases x 3 images = 126 receipts, all checks passed")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    ROOT = parser.parse_args().repo_root.resolve()
    main()
