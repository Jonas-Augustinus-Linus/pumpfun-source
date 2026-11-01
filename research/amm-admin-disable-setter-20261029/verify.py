"""Verify the retained admin `disable` setter receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 26 cases across 3 historical images, 111 receipts (family A: 21 cases x 1 step;
  family B: 5 chains x 3-4 steps), ordered, with contexts matching
  the report;
- every transaction verifies (all signatures valid, 1 signature field);
- family A success cases: the config byte 56 lands exactly on the
  expected flags, only byte 56 differs, exactly 1 DisableEvent
  (discriminator 6bfdc14ce4ca1b68, 53 bytes, timestamp 0, admin
  equal to the config's own admin bytes 8..40, bools equal to the
  instruction payload), payer charged exactly 5,000;
- family A failure cases: the recorded error code and fragment
  appear, the config (bytes and lamports) is fully rolled back,
  the payer is charged exactly 5,000, and the event count is 0 —
  except the 907/948-byte truncation cases, where exactly 1 ghost
  DisableEvent with the attempted bools remains in the log; where
  a per-image site line was recorded, it appears verbatim in that
  image's logs;
- family B disable steps: same event/flags/payer checks, with the
  chained-VM clock timestamp 1234567890;
- family B gated steps: the recorded gate code and fragment
  appear, 0 events, every non-payer watched account is byte
  identical before/after, the payer is charged exactly 5,000,
  and the recorded per-image site line appears in the logs;
- family B live trade steps: token deltas recomputed from the
  before/after snapshots via the receipt roles match the recorded
  deltas, the Buy/Sell event fields decoded from the logs match,
  the pool deltas are (-56, +56, 0), exactly 1 event, payer
  charged exactly 1,849,400;
- family B live liquidity steps: token deltas recomputed via
  roles match, exactly 1 event, payer charged exactly 5,000;
- family B create steps: the gated create fails 6017 with no
  pool / LP mint / user LP account created and both vaults
  unchanged; the re-enabled create succeeds with init_liq 1009
  and lp_out 909 (event fields decoded from the logs), user LP
  and mint supply 909, vaults 100 / 10200, payer charged
  exactly 10,507,640;
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case-step's observed values.
"""
if not __debug__:
    raise SystemExit("Run without -O")

import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

from solders.pubkey import Pubkey
from solders.transaction import Transaction

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IMAGES = ("original", "control", "candidate")
DISABLE_DISC = "6bfdc14ce4ca1b68"
CREATE_DISC = "b1310cd2a076a774"


def sha(data):
    return hashlib.sha256(data).hexdigest()


IMAGE_BINDINGS = {
    "original": ("evidence/original/pump_amm/deployed.so", "6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7"),
    "control": ("research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz", "7a300434dced61413bde10788594b427d5649563e0223efcf09e6b214aff7ad3"),
    "candidate": ("research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz", "d17a657baf5cc19736a924c41e75424604411ddbe9f6e72cddf41ab72a695007"),
}
CHAIN_STEPS = {
    "chain-buy-gate": ("disable", "buy_v2", "sell_v2"),
    "chain-sell-gate": ("disable", "sell_v2", "buy_v2"),
    "chain-deposit-gate": ("disable", "deposit", "withdraw"),
    "chain-withdraw-gate": ("disable", "withdraw", "deposit"),
    "chain-create-gate": ("disable", "create_pool", "disable", "create_pool"),
}
EXPECTED_CASES = tuple(("A", name) for name in (
    "dis-all-false", "dis-all-true", "dis-create-only", "dis-deposit-only",
    "dis-withdraw-only", "dis-buy-only", "dis-sell-only", "dis-preset224-false",
    "dis-preset224-true", "dis-preset31-false", "dis-bool2", "dis-args-empty",
    "dis-args-4bytes", "dis-trailing", "dis-trunc-906", "dis-trunc-907",
    "dis-trunc-948", "dis-outsider", "dis-unsigned", "dis-readonly",
    "dis-wrongowner")) + tuple(("B", name) for name in CHAIN_STEPS)
# Pins the 26 retained case definitions, including payloads and expected fixture
# parameters. These definitions are not evidence that a prior VM executed them.
CASE_DEFINITIONS_SHA256 = "4d061cea178af1a0cc8404f3e7aa316046d599dc7ab2d58c49f1ce5841b9711f"
ROLE_ACCOUNTS = {
    "global_config": "global_config", "pool": "pool", "base_mint": "base_mint",
    "quote_mint": "quote_mint", "lp_mint": "lp_mint",
    "userbase": "user_base_token_account", "userquote": "user_quote_token_account",
    "userlp": "user_pool_token_account", "vaultbase": "pool_base_token_account",
    "vaultquote": "pool_quote_token_account", "buyback": "buyback_fee_recipient",
    "volume": "user_volume_accumulator", "feeconfig": "fee_config",
}
TRADE_ROLES = {"fee_payer", "global_config", "pool", "userbase", "userquote",
               "vaultbase", "vaultquote", "buyback", "volume", "feeconfig"}
LIQ_ROLES = {"fee_payer", "global_config", "pool", "base_mint", "quote_mint",
             "lp_mint", "userbase", "userquote", "userlp", "vaultbase", "vaultquote"}
CREATE_ROLES = {"fee_payer", "global_config", "pool", "lp_mint", "userbase",
                "userquote", "userlp", "vaultbase", "vaultquote"}


def signed_accounts(message, ix, descriptor, case):
    assert len(ix.accounts) == len(descriptor["accounts"]), "exact signed account count"
    assert len(set(message.account_keys)) == len(message.account_keys), "unique signed keys"
    header, keys = message.header, message.account_keys
    expected = {0: (True, True)}  # The single fee payer is writable even if IDL user is read-only.
    accounts = {}
    for entry, index in zip(descriptor["accounts"], ix.accounts):
        name = entry["name"]
        assert name not in accounts, "unique IDL account names"
        accounts[name] = str(keys[index])
        signer, writable = bool(entry.get("signer")), bool(entry.get("writable"))
        if descriptor["name"] == "disable":
            if name == "admin" and case["label"] == "dis-unsigned":
                signer = False
            if name == "global_config" and case["label"] == "dis-readonly":
                writable = False
        prior = expected.get(index, (False, False))
        expected[index] = (prior[0] or signer, prior[1] or writable)
    expected.setdefault(ix.program_id_index, (False, False))
    assert set(expected) == set(range(len(keys))), "exact signed key membership"
    for index, privileges in expected.items():
        signer = index < header.num_required_signatures
        writable = (index < header.num_required_signatures - header.num_readonly_signed_accounts) if signer else (index < len(keys) - header.num_readonly_unsigned_accounts)
        assert (signer, writable) == privileges, "signed account privileges"
    return accounts


def watched_bindings(steps, case, account_maps):
    roles = steps[0]["roles"]
    assert all(row["roles"] == roles for row in steps), "same chain roles"
    if case["family"] == "A":
        expected_roles = {"fee_payer", "global_config"}
        watched = set(roles.values())
    else:
        gate = case["label"].split("-")[1]
        expected_roles = TRADE_ROLES if gate in ("buy", "sell") else CREATE_ROLES if gate == "create" else LIQ_ROLES
        downstream = [accounts for row, accounts in zip(steps, account_maps)
                      if row["context"]["step_name"] != "disable"]
        # Trade and liquidity producers watch every downstream instruction key.
        # Create watches only these nine state/payer/config roles. These sets are
        # retained on setter steps too, although disable itself uses four keys.
        watched = set(roles.values()) if gate == "create" else set().union(*(set(accounts.values()) for accounts in downstream))
    assert set(roles) == expected_roles, "exact watched role membership"
    for role, key in roles.items():
        if role == "fee_payer":
            continue  # Bound to key zero independently for every signed wire.
        name = ROLE_ACCOUNTS[role]
        matches = [accounts[name] for accounts in account_maps if name in accounts]
        assert matches and all(value == key for value in matches), "signed watched role: " + role
    for row in steps:
        assert set(row["before"]) == set(row["after"]) == watched, "exact watched snapshot membership"


def verify_wire(r, case, idl):
    raw = base64.b64decode(r["transaction_base64"], validate=True)
    tx = Transaction.from_bytes(raw)
    assert bytes(tx) == raw and len(tx.signatures) == 1, "canonical single-signature wire"
    message = tx.message
    assert len(message.instructions) == 1, "one declared instruction"
    ix = message.instructions[0]
    keys = message.account_keys
    assert str(keys[0]) == r["roles"]["fee_payer"], "signed payer role"
    assert str(keys[ix.program_id_index]) == "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA", "signed AMM program"
    ctx = r["context"]
    name = "disable" if case["family"] == "A" else ctx["step_name"]
    descriptor = next(row for row in idl["instructions"] if row["name"] == name)
    accounts = signed_accounts(message, ix, descriptor, case)
    if name == "disable":
        if case["family"] == "A":
            payload = bytes(case["payload"])
        else:
            gate = case["label"].split("-")[1]
            flags = [int(gate == value) for value in ("create", "deposit", "withdraw", "buy", "sell")]
            payload = bytes(flags if ctx["step"] == 0 else [0] * 5)
    elif name in ("buy_v2", "sell_v2"):
        payload = struct.pack("<QQ", 10**6, (2**64 - 1) if name == "buy_v2" else 1)
    elif name in ("deposit", "withdraw"):
        limit = (2**64 - 1) if name == "deposit" else 0
        payload = struct.pack("<QQQ", 10**9, limit, limit)
    else:
        payload = struct.pack("<HQQ", 0, 100, 10200) + bytes(keys[0]) + b"\0"
    assert bytes(ix.data) == bytes(descriptor["discriminator"]) + payload, "signed instruction payload"
    positions = [i for i, account in enumerate(descriptor["accounts"]) if account["name"] == "global_config"]
    assert len(positions) == 1 and str(keys[ix.accounts[positions[0]]]) == r["roles"]["global_config"], "signed config role"
    config_index = ix.accounts[positions[0]]
    header = message.header
    writable = (config_index < header.num_required_signatures - header.num_readonly_signed_accounts) if config_index < header.num_required_signatures else (config_index < len(keys) - header.num_readonly_unsigned_accounts)
    if name == "disable":
        assert writable == (case["label"] != "dis-readonly"), "signed config privilege"
        admin = str(keys[ix.accounts[0]])
        expected_admin = r["roles"]["fee_payer"] if case["label"] == "dis-outsider" else str(Pubkey.from_bytes(bytes.fromhex(r["before"][r["roles"]["global_config"]]["data_hex"])[8:40]))
        assert admin == expected_admin, "signed admin role"
        assert (ix.accounts[0] < message.header.num_required_signatures) == (case["label"] != "dis-unsigned"), "signed admin privilege"
        if r["error"] is None:
            cfg = r["roles"]["global_config"]
            before, after = r["before"][cfg], r["after"][cfg]
            old, new = bytes.fromhex(before["data_hex"]), bytes.fromhex(after["data_hex"])
            flags = (old[56] & 224) | sum(value << shift for shift, value in enumerate(payload[:5]))
            assert new == old[:56] + bytes([flags]) + old[57:] and before["lamports"] == after["lamports"], "exact disable write footprint"
    payer = r["roles"]["fee_payer"]
    assert r["before"][payer]["lamports"] - r["after"][payer]["lamports"] == r["payer_delta_lamports"], "actual payer delta"
    return accounts


def amount_at(data_hex, offset=64):
    return struct.unpack_from("<Q", bytes.fromhex(data_hex), offset)[0]


def disable_event(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    if raw[:8].hex() != DISABLE_DISC or len(raw) != 53:
        return None
    return {"disc": raw[:8].hex(),
            "timestamp": struct.unpack_from("<q", raw, 8)[0],
            "admin": raw[16:48].hex(),
            "bools": list(raw[48:53])}


def trade_event_fields(ix_name, logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    assert len(lines) == 1, lines
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    offs = (64, 72, 80, 88, 96, 104, 112) if ix_name == "buy_v2" else (64, 72, 80, 88, 96)
    assert len(raw) >= max(offs) + 8, len(raw)
    return tuple(struct.unpack_from("<Q", raw, off)[0] for off in offs)


def create_event_fields(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    if raw[:8].hex() != CREATE_DISC or len(raw) < 344:
        return None
    return {"disc": raw[:8].hex(),
            "base_in": struct.unpack_from("<Q", raw, 116)[0],
            "quote_in": struct.unpack_from("<Q", raw, 124)[0],
            "pool_base": struct.unpack_from("<Q", raw, 132)[0],
            "pool_quote": struct.unpack_from("<Q", raw, 140)[0],
            "min_liq": struct.unpack_from("<Q", raw, 148)[0],
            "init_liq": struct.unpack_from("<Q", raw, 156)[0],
            "lp_out": struct.unpack_from("<Q", raw, 164)[0]}


def pool_deltas(before_hex, after_hex):
    b, a = bytes.fromhex(before_hex), bytes.fromhex(after_hex)
    return (int.from_bytes(a[245:261], "little", signed=True) - int.from_bytes(b[245:261], "little", signed=True),
            struct.unpack_from("<Q", a, 271)[0] - struct.unpack_from("<Q", b, 271)[0],
            struct.unpack_from("<Q", a, 279)[0] - struct.unpack_from("<Q", b, 279)[0])


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
    assert report["case_count"] == 26, report["case_count"]
    assert tuple((row["case"]["family"], row["case"]["label"]) for row in report["cases"]) == EXPECTED_CASES, "exact case membership"
    assert sha(json.dumps([row["case"] for row in report["cases"]], sort_keys=True, separators=(",", ":")).encode()) == CASE_DEFINITIONS_SHA256, "exact case definitions"
    assert report["mismatches"] == [] and report["divergent_cases"] == []
    for rel, digest in report["input_sha256"].items():
        assert sha((ROOT / rel).read_bytes()) == digest, rel
    expected_images = {label: digest for label, (_, digest) in IMAGE_BINDINGS.items()}
    assert report["image_sha256"] == expected_images, "declared historical image binding"
    for label, (name, digest) in IMAGE_BINDINGS.items():
        raw = (ROOT / name).read_bytes()
        raw = gzip.decompress(raw) if name.endswith(".gz") else raw
        assert sha(raw) == digest, "authenticated historical image " + label
    idl = json.loads((ROOT / "evidence/upstream/pump_amm.json").read_text())
    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (HERE / part["path"]).read_bytes()
        assert len(data) < 25 * 1024 * 1024, part["path"]
        assert sha(data) == part["sha256"], part["path"]
        chunk = [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l]
        assert len(chunk) == part["receipts"], part["path"]
        receipts.extend(chunk)
    assert len(receipts) == 111, len(receipts)
    assert report["counts"] == {"vms": 111, "transactions": 111, "signature_fields": 111}
    for seq, r in enumerate(receipts):
        assert r["sequence"] == seq and r["vm"] == seq, seq
        assert r["all_signatures_verified"] is True and r["signature_fields"] == 1, seq
        tx = Transaction.from_bytes(base64.b64decode(r["transaction_base64"]))
        assert tx.verify_with_results() and all(tx.verify_with_results()), seq
        assert str(tx.signatures[0]) == r["signatures"][0], seq
        assert r["transaction_sha256"] == sha(base64.b64decode(r["transaction_base64"])), seq
        assert r["payer_delta_lamports"] == r["observed"]["payer_paid"], seq
        ctx = r["context"]
        assert ctx["image"] in IMAGES, "exact image membership"
        assert (ctx["family"], ctx["label"]) == EXPECTED_CASES[ctx["index"]], "receipt case membership"
        assert ctx["instruction"] == ("disable" if ctx["family"] == "A" else "disable-chain"), "receipt instruction family"
        if ctx["family"] == "A":
            assert ctx.get("step", 0) == 0, "single setter step"
    by_case = {}
    for r in receipts:
        ctx = r["context"]
        by_case.setdefault(ctx["label"], {}).setdefault(ctx["image"], []).append(r)
    assert len(by_case) == 26, len(by_case)
    assert len(report["cases"]) == len({row["case"]["label"] for row in report["cases"]}) == 26, "unique case membership"
    wires = {}
    for r in receipts:
        key = (r["context"]["label"], r["context"].get("step", 0))
        wires.setdefault(key, set()).add(r["transaction_base64"])
    assert all(len(values) == 1 for values in wires.values()), "same signed wire across images"
    consumed = set()
    for case_index, case in enumerate(report["cases"]):
        label = case["case"]["label"]
        family = case["case"]["family"]
        exp = case["case"]["expected"] if family == "A" else None
        obs_seen = {}
        for image in IMAGES:
            steps = sorted(by_case[label][image], key=lambda r: r["context"].get("step", 0))
            assert set(by_case[label]) == set(IMAGES), "exact case image membership"
            assert {r["context"]["index"] for r in steps} == {case_index}, "case index binding"
            assert all(r["context"]["family"] == family for r in steps), "case family binding"
            if family == "B":
                assert tuple(r["context"]["step_name"] for r in steps) == CHAIN_STEPS[label], "exact downstream chain"
                for previous, current in zip(steps, steps[1:]):
                    assert previous["after"] == current["before"], "chained account continuity"
            for receipt in steps:
                assert receipt["sequence"] not in consumed, "receipt consumed once"
                consumed.add(receipt["sequence"])
            account_maps = [verify_wire(receipt, case["case"], idl) for receipt in steps]
            watched_bindings(steps, case["case"], account_maps)
            if family == "A":
                assert len(steps) == 1, (label, image)
                r = steps[0]
                roles, before, after = r["roles"], r["before"], r["after"]
                logs = r["metadata"]["logs"]
                cfg = roles["global_config"]
                payer = roles["fee_payer"]
                b_hex = before[cfg]["data_hex"]
                a_hex = after[cfg]["data_hex"]
                b, a = bytes.fromhex(b_hex), bytes.fromhex(a_hex)
                admin_hex = b[8:40].hex()
                obs = r["observed"]
                obs_seen.setdefault("all", set()).add(json.dumps(obs, sort_keys=True))
                assert obs["payer_paid"] == 5000, (label, image)
                assert obs["length"] == len(a), (label, image)
                if exp["kind"] == "ok":
                    assert r["error"] is None, (label, image, r["error"])
                    assert a[56] == exp["flags"], (label, image, a[56])
                    diffs = [i for i in range(min(len(b), len(a))) if b[i] != a[i]]
                    assert diffs == exp["diffs"], (label, image, diffs)
                    assert r["metadata"]["events"] == 1, (label, image)
                    assert disable_event(logs) == {
                        "disc": DISABLE_DISC, "timestamp": 0, "admin": admin_hex,
                        "bools": case["case"]["payload"][:5]}, (label, image)
                else:
                    assert r["error"] is not None and exp["code"] in r["error"], (label, image, r["error"])
                    assert exp["fragment"] in "\n".join(logs), (label, image)
                    assert before[cfg] == after[cfg], (label, image, "no rollback")
                    assert a[56] == b[56], (label, image, "flags moved on failure")
                    if exp.get("ghost"):
                        assert r["metadata"]["events"] == 1, (label, image)
                        assert disable_event(logs) == {
                            "disc": DISABLE_DISC, "timestamp": 0, "admin": admin_hex,
                            "bools": case["case"]["payload"][:5]}, (label, image)
                    else:
                        assert r["metadata"]["events"] == 0, (label, image)
                    site = (case.get("error_sites") or {}).get(image)
                    if site:
                        assert site in "\n".join(logs), (label, image, site)
            else:
                for step_index, r in enumerate(steps):
                    ctx = r["context"]
                    assert ctx["step"] == step_index and ctx["step_name"] in (
                        "disable", "buy_v2", "sell_v2", "deposit", "withdraw", "create_pool"), ctx
                    roles, before, after = r["roles"], r["before"], r["after"]
                    logs = r["metadata"]["logs"]
                    obs = r["observed"]
                    obs_seen.setdefault(step_index, set()).add(json.dumps(obs, sort_keys=True))
                    payer = roles["fee_payer"]
                    assert obs["payer_paid"] == r["payer_delta_lamports"]
                    if ctx["step_name"] == "disable":
                        assert r["error"] is None, (label, image, step_index, r["error"])
                        cfg = roles["global_config"]
                        admin_hex = bytes.fromhex(before[cfg]["data_hex"])[8:40].hex()
                        assert after[cfg]["data_hex"][112:114] == f"{obs['flags_after']:02x}"
                        assert r["metadata"]["events"] == 1
                        assert disable_event(logs) == {
                            "disc": DISABLE_DISC, "timestamp": 1234567890,
                            "admin": admin_hex, "bools": obs["event"]["bools"]}, (label, image, step_index)
                        assert obs["payer_paid"] == 5000
                    elif "error_code" in obs:
                        assert r["error"] is not None and obs["error_code"] in r["error"], (label, image, step_index)
                        assert obs["fragment"] in "\n".join(logs), (label, image, step_index)
                        assert r["metadata"]["events"] == 0, (label, image, step_index)
                        assert obs["payer_paid"] == 5000
                        for key, snap_b in before.items():
                            if key == payer:
                                assert snap_b["lamports"] - after[key]["lamports"] == 5000
                            else:
                                assert snap_b == after[key], (label, image, step_index, key)
                        site = (case.get("error_sites") or {}).get(f"{image}:{ctx['step_name']}")
                        assert site and site in "\n".join(logs), (label, image, step_index, site)
                        if ctx["step_name"] == "create_pool":
                            assert after[roles["pool"]] is None
                            assert after[roles["lp_mint"]] is None
                            assert after[roles["userlp"]] is None
                            assert after[roles["vaultbase"]] == before[roles["vaultbase"]]
                            assert after[roles["vaultquote"]] == before[roles["vaultquote"]]
                    elif ctx["step_name"] in ("buy_v2", "sell_v2"):
                        assert r["error"] is None, (label, image, step_index, r["error"])
                        assert r["metadata"]["events"] == 1
                        deltas = {}
                        for name, key in (("userbase", "userbase"), ("userquote", "userquote"),
                                          ("vaultbase", "vaultbase"), ("vaultquote", "vaultquote"),
                                          ("buyback", "buyback")):
                            deltas[name] = amount_at(after[roles[key]]["data_hex"]) - amount_at(before[roles[key]]["data_hex"])
                        assert deltas == obs["deltas"], (label, image, step_index, deltas)
                        assert trade_event_fields(ctx["step_name"], logs) == tuple(obs["event"]), (label, image, step_index)
                        assert pool_deltas(before[roles["pool"]]["data_hex"],
                                           after[roles["pool"]]["data_hex"]) == (-56, 56, 0)
                        assert obs["payer_paid"] == 1849400
                    elif ctx["step_name"] in ("deposit", "withdraw"):
                        assert r["error"] is None, (label, image, step_index, r["error"])
                        assert r["metadata"]["events"] == 1
                        deltas = {}
                        for name in ("userbase", "userquote", "userlp", "vaultbase", "vaultquote"):
                            deltas[name] = amount_at(after[roles[name]]["data_hex"]) - amount_at(before[roles[name]]["data_hex"])
                        assert deltas == obs["deltas"], (label, image, step_index, deltas)
                        assert obs["payer_paid"] == 5000
                    elif ctx["step_name"] == "create_pool":
                        assert r["error"] is None, (label, image, step_index, r["error"])
                        assert r["metadata"]["events"] == 1
                        assert create_event_fields(logs) == {
                            "disc": CREATE_DISC, "base_in": 100, "quote_in": 10200,
                            "pool_base": 100, "pool_quote": 10200, "min_liq": 100,
                            "init_liq": 1009, "lp_out": 909}, (label, image, step_index)
                        assert amount_at(after[roles["userlp"]]["data_hex"]) == 909
                        assert amount_at(after[roles["lp_mint"]]["data_hex"], 36) == 909
                        assert amount_at(after[roles["vaultbase"]]["data_hex"]) == 100
                        assert amount_at(after[roles["vaultquote"]]["data_hex"]) == 10200
                        assert obs["payer_paid"] == 10507640
                    else:
                        raise AssertionError((label, image, step_index, ctx))
        for key, s in obs_seen.items():
            assert len(s) == 1, (label, key, "images must agree", s)
    assert consumed == set(range(111)), "all receipts consumed exactly once"
    print("verify PASS: 26 cases across 3 historical images, 111 signed receipts, all checks passed")


if __name__ == "__main__":
    main()
