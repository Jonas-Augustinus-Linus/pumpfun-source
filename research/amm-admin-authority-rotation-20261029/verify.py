#!/usr/bin/env python3
"""Independent re-verification for amm-admin-authority-rotation-20261029.

Checks, without trusting producer.py:
- MANIFEST.json file hashes match the packet files on disk;
- report.json.gz case_count / counts / empty mismatches / repo input
  hashes / image hashes match the repository files;
- receipt parts arrive in order with matching sha256, receipt
  counts, and per-receipt transaction sha256;
- every receipt transaction verifies with exactly 1 signature field;
- the 3 images agree on every case-step's error, decoded events,
  after-state, after-lamports, and payer delta;
- every case-step matches its expected error (or success), log
  site fragment, decoded events (re-decoded from the receipt's
  Program-data log lines, not from the recorded observed values),
  state fields (re-read from the receipt's after-state hex),
  payer delta (recomputed from payer_before / payer_after),
  rollback (before == after state and lamports), zero-filled
  realloc tail, and diff-subset scope for same-length writes;
- the ghost-event cases (admin-trunc-907 / admin-trunc-948) carry
  the UpdateAdminEvent in their logs while the transaction fails
  with BorshIoError and the state rolls back.
"""
import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

import os
os.chdir(Path(__file__).resolve().parents[2])
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "research/amm-admin-authority-rotation-20261029"
PROGRAM = Pubkey.from_string('pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA')
EVENT = Pubkey.find_program_address([b'__event_authority'], PROGRAM)[0]
PAYER = Keypair.from_seed(bytes([201]) * 32)
OUTSIDER = Keypair.from_seed(bytes([202]) * 32)
UNFUNDED77 = Pubkey.from_bytes(bytes([77]) * 32)
UNFUNDED88 = Pubkey.from_bytes(bytes([88]) * 32)
CONFIG = next(x for x in json.loads((ROOT / 'research/imported-lab/analysis/pump_fun/config-snapshot.json').read_text())['accounts'] if x['program_name'] == 'pump_amm')
CONFIG_KEY = Pubkey.from_string(CONFIG['address'])
RAW = bytearray(base64.b64decode(CONFIG['data_base64']))
RAW[8:40] = bytes(PAYER.pubkey())
FIXTURE_BOOST = bytes(RAW[907:939])
RENT949 = 7495920


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(b):
    return bytes(b).hex()


P = PAYER.pubkey()
O = OUTSIDER.pubkey()
EV_ADMIN = lambda admin, new: {"event": "UpdateAdminEvent", "timestamp": 0,
                               "admin": hx(bytes(admin)), "new_admin": hx(bytes(new))}
EV_BOOST = lambda admin, old, new: {"event": "SetBoostAuthorityEvent", "timestamp": 0,
                                     "admin": hx(bytes(admin)), "old": hx(old),
                                     "new": hx(bytes(new))}
EV_CREATOR = lambda admin, cfg, mx: {"event": "UpdateCreatorFeeConfigEvent",
                                      "timestamp": 0, "admin": hx(bytes(admin)),
                                      "configurable": cfg, "max": mx}
EV_DISABLE = lambda admin, flags: {"event": "DisableEvent", "timestamp": 0,
                                    "admin": hx(bytes(admin)), "flags": flags}


def E(err=None, site=None, events=(), payer_delta=5000, rollback=False,
      tail_zero=None, diff_subset=None, **state):
    d = {"err": err, "site": site, "events": list(events),
         "payer_delta": payer_delta, "rollback": rollback,
         "tail_zero": tail_zero, "diff_subset": diff_subset}
    d.update(state)
    return d


# (label, [step expectations]) -- must match producer.py CASES.
EXPECTED = [
    ("admin-rotate-outsider", [E(events=[EV_ADMIN(P, O)], admin=hx(bytes(O)), length=949, cfg_lamports=CONFIG['lamports'], diff_subset=(8, 40))]),
    ("admin-rotate-program", [E(events=[EV_ADMIN(P, PROGRAM)], admin=hx(bytes(PROGRAM)), length=949, diff_subset=(8, 40))]),
    ("admin-rotate-event", [E(events=[EV_ADMIN(P, EVENT)], admin=hx(bytes(EVENT)), length=949, diff_subset=(8, 40))]),
    ("admin-rotate-config", [E(events=[EV_ADMIN(P, CONFIG_KEY)], admin=hx(bytes(CONFIG_KEY)), length=949, diff_subset=(8, 40))]),
    ("admin-rotate-self", [E(events=[EV_ADMIN(P, P)], admin=hx(bytes(P)), length=949, diff_subset=(8, 40))]),
    ("admin-rotate-unfunded", [E(events=[EV_ADMIN(P, UNFUNDED77)], admin=hx(bytes(UNFUNDED77)), length=949, diff_subset=(8, 40))]),
    ("admin-rotate-outsider-signer", [E(err="InstructionErrorCustom(6005)", site="InvalidAdmin", rollback=True)]),
    ("admin-rotate-unsigned", [E(err="InstructionErrorCustom(3010)", site="AccountNotSigner", rollback=True)]),
    ("admin-rotate-readonly-config", [E(err="InstructionErrorCustom(2000)", site="ConstraintMut", rollback=True)]),
    ("admin-rotate-wrong-owner", [E(err="InstructionErrorCustom(3007)", site="AccountOwnedByWrongProgram", rollback=True)]),
    ("admin-trunc-907", [E(err="BorshIoError", site="BorshIoError", events=[EV_ADMIN(P, O)], rollback=True)]),
    ("admin-trunc-948", [E(err="BorshIoError", site="BorshIoError", events=[EV_ADMIN(P, O)], rollback=True)]),
    ("admin-trunc-906", [E(err="InvalidAccountData", site="InvalidAccountData", rollback=True)]),
    ("admin-chain-rotate-disable", [
        E(events=[EV_ADMIN(P, O)], admin=hx(bytes(O)), diff_subset=(8, 40)),
        E(err="InstructionErrorCustom(6005)", site="InvalidAdmin", rollback=True),
        E(events=[EV_DISABLE(O, [1, 0, 0, 0, 0])], flags=1, diff_subset=(56, 57)),
    ]),
    ("admin-chain-rotate-default-brick", [
        E(events=[EV_ADMIN(P, Pubkey.default())], admin=hx(bytes(32)), diff_subset=(8, 40)),
        E(err="InstructionErrorCustom(6005)", site="InvalidAdmin", rollback=True),
        E(err="InstructionErrorCustom(6005)", site="InvalidAdmin", rollback=True),
    ]),
    ("admin-chain-roundtrip", [
        E(events=[EV_ADMIN(P, O)], admin=hx(bytes(O)), diff_subset=(8, 40)),
        E(events=[EV_ADMIN(O, P)], admin=hx(bytes(P)), diff_subset=(8, 40)),
        E(events=[EV_DISABLE(P, [0, 1, 0, 0, 0])], flags=2, diff_subset=(56, 57)),
    ]),
    ("boost-to-outsider", [E(events=[EV_BOOST(P, FIXTURE_BOOST, O)], boost=hx(bytes(O)), length=949, cfg_lamports=CONFIG['lamports'], diff_subset=(907, 939))]),
    ("boost-to-default", [E(events=[EV_BOOST(P, FIXTURE_BOOST, Pubkey.default())], boost=hx(bytes(32)), diff_subset=(907, 939))]),
    ("boost-to-unfunded", [E(events=[EV_BOOST(P, FIXTURE_BOOST, UNFUNDED88)], boost=hx(bytes(UNFUNDED88)), diff_subset=(907, 939))]),
    ("boost-outsider-signer", [E(err="InstructionErrorCustom(6005)", site="InvalidAdmin", rollback=True)]),
    ("boost-unsigned", [E(err="InstructionErrorCustom(3010)", site="AccountNotSigner", rollback=True)]),
    ("boost-readonly-config", [E(err="InstructionErrorCustom(2000)", site="ConstraintMut", rollback=True)]),
    ("boost-wrong-owner", [E(err="InstructionErrorCustom(3007)", site="AccountOwnedByWrongProgram", rollback=True)]),
    ("boost-trunc-907", [E(events=[{"event": "SetBoostAuthorityEvent", "timestamp": 0, "admin": hx(bytes(P)), "old": hx(bytes(32)), "new": hx(bytes(O))}], boost=hx(bytes(O)), length=949, cfg_lamports=CONFIG['lamports'], tail_zero=(939, 949))]),
    ("boost-trunc-906", [E(err="InvalidAccountData", site="InvalidAccountData", rollback=True)]),
    ("boost-trunc-948-lowlamports", [E(events=[EV_BOOST(P, FIXTURE_BOOST, O)], boost=hx(bytes(O)), length=949, cfg_lamports=RENT949, payer_delta=7500820, tail_zero=(948, 949))]),
    ("boost-full-949-lowlamports", [E(events=[EV_BOOST(P, FIXTURE_BOOST, O)], boost=hx(bytes(O)), length=949, cfg_lamports=100, diff_subset=(907, 939))]),
    ("creator-false-max0", [E(events=[EV_CREATOR(P, 0, 0)], conf=0, max=0, diff_subset=(940, 949))]),
    ("creator-true-max10000", [E(events=[EV_CREATOR(P, 1, 10000)], conf=1, max=10000, diff_subset=(940, 949))]),
    ("creator-true-maxu64", [E(events=[EV_CREATOR(P, 1, 2 ** 64 - 1)], conf=1, max=2 ** 64 - 1, diff_subset=(940, 949))]),
    ("creator-bool2", [E(err="InstructionErrorCustom(102)", site="InstructionDidNotDeserialize", rollback=True)]),
    ("creator-args-empty", [E(err="InstructionErrorCustom(102)", site="InstructionDidNotDeserialize", rollback=True)]),
    ("creator-args-trailing", [E(events=[EV_CREATOR(P, 1, 300)], conf=1, max=300, diff_subset=(940, 949))]),
    ("creator-outsider", [E(err="InstructionErrorCustom(6005)", site="InvalidAdmin", rollback=True)]),
    ("creator-wrong-owner", [E(err="InstructionErrorCustom(3007)", site="AccountOwnedByWrongProgram", rollback=True)]),
    ("creator-trunc-907", [E(events=[EV_CREATOR(P, 1, 777)], conf=1, max=777, length=949, cfg_lamports=CONFIG['lamports'], tail_zero=(939, 940))]),
    ("creator-trunc-948-lowlamports", [E(events=[EV_CREATOR(P, 1, 300)], conf=1, max=300, length=949, cfg_lamports=RENT949, payer_delta=7500820)]),
]

EV_DISC = {
    'e198ab57f63f42ea': 'UpdateAdminEvent',
    '5980f08d5bca4769': 'SetBoostAuthorityEvent',
    '98c67c7c6af67fbf': 'UpdateCreatorFeeConfigEvent',
    '6bfdc14ce4ca1b68': 'DisableEvent',
}


def decode_event(raw):
    assert len(raw) >= 8 and raw[:8].hex() in EV_DISC, raw[:8].hex()
    name = EV_DISC[raw[:8].hex()]
    ts = struct.unpack_from('<q', raw, 8)[0]
    if name == 'UpdateAdminEvent':
        assert len(raw) == 80
        return {"event": name, "timestamp": ts, "admin": hx(raw[16:48]),
                "new_admin": hx(raw[48:80])}
    if name == 'SetBoostAuthorityEvent':
        assert len(raw) == 112
        return {"event": name, "timestamp": ts, "admin": hx(raw[16:48]),
                "old": hx(raw[48:80]), "new": hx(raw[80:112])}
    if name == 'UpdateCreatorFeeConfigEvent':
        assert len(raw) == 57
        return {"event": name, "timestamp": ts, "admin": hx(raw[16:48]),
                "configurable": raw[48], "max": struct.unpack_from('<Q', raw, 49)[0]}
    assert len(raw) == 53
    return {"event": name, "timestamp": ts, "admin": hx(raw[16:48]),
            "flags": list(raw[48:53])}


def main():
    manifest = json.loads((PACKET / "MANIFEST.json").read_text())
    for rel, digest in manifest["files"].items():
        actual = sha((PACKET / rel).read_bytes())
        assert actual == digest, (rel, actual, digest)
    report = json.loads(gzip.decompress((PACKET / "runtime/report.json.gz").read_bytes()))
    assert report["case_count"] == len(EXPECTED), report["case_count"]
    assert report["mismatches"] == []
    assert report["counts"] == {"vms": 129, "transactions": 129,
                                "signature_fields": 129}, report["counts"]
    for name, digest in report["input_sha256"].items():
        recorded = ROOT / name
        if name.startswith("programs/pump-amm/"):
            recorded = ROOT / "repro/pump_amm/v2-mint-clone-recovery-20261028/results/canonical-source" / name
        assert sha(recorded.read_bytes()) == digest, name
    for name, digest in report["image_sha256"].items():
        path = {"original": ROOT / "evidence/original/pump_amm/deployed.so",
                "control": ROOT / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz",
                "candidate": ROOT / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz"}[name]
        assert sha(gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()) == digest, name
    assert [c["case"]["label"] for c in report["cases"]] == [l for l, _ in EXPECTED]
    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (PACKET / part["path"]).read_bytes()
        assert sha(data) == part["sha256"], part["path"]
        chunk = [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l]
        assert len(chunk) == part["receipts"], part["path"]
        receipts.extend(chunk)
    assert len(receipts) == 129, len(receipts)
    assert [r["sequence"] for r in receipts] == list(range(129))
    # Group by (case index, step), check 3-image agreement + expectations.
    grouped = {}
    for r in receipts:
        ctx = r["context"]
        grouped.setdefault((ctx["index"], ctx["step"]), {})[ctx["image"]] = r
    assert len(grouped) == 43, len(grouped)
    for (index, step), by_image in grouped.items():
        assert set(by_image) == {"original", "control", "candidate"}, (index, step, set(by_image))
        label, steps = EXPECTED[index]
        assert step < len(steps), (label, step)
        exp = steps[step]
        seen = set()
        for image, r in by_image.items():
            raw = base64.b64decode(r["transaction_base64"])
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == 1, (label, image, checks)
            assert r["transaction_sha256"] == sha(raw), (label, image)
            assert r["signature_fields"] == 1 and r["all_signatures_verified"] is True
            logs = r["metadata"]["logs"]
            events = [decode_event(base64.b64decode(e[len('Program data: '):]))
                      for e in r["metadata"]["events"]]
            after = bytes.fromhex(r["after_hex"]) if r["after_hex"] is not None else None
            before = bytes.fromhex(r["before_hex"]) if r["before_hex"] is not None else None
            obs = {
                "error": r["error"],
                "events": events,
                "admin": hx(after[8:40]) if after and len(after) >= 40 else None,
                "boost": hx(after[907:939]) if after and len(after) >= 939 else None,
                "conf": after[940] if after and len(after) >= 941 else None,
                "max": struct.unpack_from('<Q', after, 941)[0] if after and len(after) >= 949 else None,
                "flags": after[56] if after and len(after) >= 57 else None,
                "length": len(after) if after is not None else None,
                "cfg_lamports": r["after_lamports"],
                "payer_delta": r["payer_before"] - r["payer_after"],
                "rollback": (before == after and r["before_lamports"] == r["after_lamports"]),
            }
            if exp["err"] is None:
                assert obs["error"] is None, (label, image, step, obs["error"])
            else:
                assert obs["error"] is not None and exp["err"] in obs["error"], \
                    (label, image, step, obs["error"])
            if exp["site"]:
                assert exp["site"] in "\n".join(logs), (label, image, step)
            assert obs["events"] == exp["events"], (label, image, step, obs["events"])
            for key in ("admin", "boost", "conf", "max", "flags", "length", "cfg_lamports"):
                if key in exp:
                    assert obs[key] == exp[key], (label, image, step, key, obs[key], exp[key])
            assert obs["payer_delta"] == exp["payer_delta"], (label, image, step, obs["payer_delta"])
            if exp["rollback"]:
                assert obs["rollback"], (label, image, step, "no rollback")
            if exp["tail_zero"]:
                lo, hi = exp["tail_zero"]
                assert all(b == 0 for b in after[lo:hi]), (label, image, step)
            if exp["diff_subset"]:
                lo, hi = exp["diff_subset"]
                assert len(before) == len(after), (label, image, step)
                diffs = [i for i in range(len(before)) if before[i] != after[i]]
                assert all(lo <= i < hi for i in diffs), (label, image, step, diffs)
            seen.add((obs["error"], json.dumps(obs["events"], sort_keys=True),
                      r["after_hex"], r["after_lamports"], obs["payer_delta"]))
        assert len(seen) == 1, (label, step, "images disagree")
    print(f"verify PASS: {len(EXPECTED)} cases x 3 images = 129 receipts, all checks passed")


if __name__ == "__main__":
    main()
