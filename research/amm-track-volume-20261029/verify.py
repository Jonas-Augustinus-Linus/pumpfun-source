"""Verify the retained track-volume receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 26 cases x 3 images = 78 receipts, ordered, with contexts
  matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases: the recorded error is None, exactly 1 event whose
  decoded fields match the recorded event (legacy buy 497 bytes /
  buy_exact 512 bytes with track byte @360; tuple events for
  legacy sell 449 bytes, v2 buy 500 / sell 449 / buy_exact 515
  bytes, multi-hop buy 508 / sell 449 bytes with the
  (out, max, quote, lp_bps, lp_fee, protocol_bps, protocol_fee,
  quote_with_lp, user_quote_in) tuple), token deltas recomputed
  from the before/after snapshots via the receipt roles match the
  recorded deltas, the volume accumulator's full 137-byte
  after-state matches the expected seed/fresh/overwrite form
  (discriminator recomputed as sha256("account:
  UserVolumeAccumulator")[:8], seed fields needs=1,
  unclaimed=111, claimed=222, sol=333444, last=999, has=1,
  earned=555 or 1103, cb_claimed=666), the pool protocol /
  creator / virtual-quote deltas match where recorded, and the
  payer delta matches;
- failure cases: the recorded error code appears (in the error
  string or the logs), 0 events, every non-payer watched account
  is byte identical before/after, and the payer delta matches;
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case's observed values.
"""
if not __debug__:
    raise SystemExit("Run without -O")

import ast
import base64
import gzip
import hashlib
import json
import struct
from pathlib import Path

from solders.pubkey import Pubkey
from solders.transaction import Transaction

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IMAGES = ("original", "control", "candidate")
DISC = hashlib.sha256(b"account:UserVolumeAccumulator").digest()[:8]

# Public fixture keys bound by the reviewed builders and signed messages.
KEYS = {'pool': 'GseMAnNDvntR5uFePZ51yZBXzNSn7GdFPkfHwfr6d77J', 'user': 'DXyM8yAHqpMzDtvwz5DXoEUQmPxjJPMKCASCPhLMKpEx', 'global_config': 'ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw', 'base_mint': '7LSsEoJGhLeZzGvDofTdNg7M3JttxQqGWNLo6vWMpump', 'quote_mint': 'So11111111111111111111111111111111111111112', 'user_base_token_account': '5jKh25biPsnrmLWXXuqKNH2Q67j69T4Q7Zew5c8wJKaV', 'user_quote_token_account': '5oEzAP4izB65uRm2yDAEf9oALGwHpWkDfyKb8zBY3euC', 'pool_base_token_account': '5jMpkf4JF4noHftLgNKyPNh6roVfPSGSjuEk3U4eLKRa', 'pool_quote_token_account': '43DVcZR4kQFjh4Xm2i3DcneRxNjZp7HMud8yDrJWrDr8', 'protocol_fee_recipient': '62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV', 'protocol_fee_recipient_token_account': '94qWNrtmfn42h3ZjUZwWvK1MEo9uVmmrBPd2hpNjYDjb', 'base_token_program': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'quote_token_program': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'system_program': '11111111111111111111111111111111', 'associated_token_program': 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', 'event_authority': 'GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR', 'program': 'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA', 'coin_creator_vault_ata': '3E6RtRCxo7Yz64zi8aSmC9DtNKcaMp5rFUcBnJKsc2fg', 'coin_creator_vault_authority': '4LFFCuf82nwijjNjbu8enNmfVa5hqBxBctgnuJ7ZNNMS', 'global_volume_accumulator': 'C2aFPdENg4A2HQsmrd5rTw5TaYBX5Ku887cWjbFKtZpw', 'user_volume_accumulator': '8NyBnxo9mS5MsqY4qoKmrt7MS89d7MNV6rh5fu2YsQPT', 'fee_config': '5PHirr8joyTMp9JMm6nW7hNDVyEYdkzDqazxPD7RaTjx', 'fee_program': 'pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ', 'user_in_token_account': '5oEzAP4izB65uRm2yDAEf9oALGwHpWkDfyKb8zBY3euC', 'user_out_token_account': '5jKh25biPsnrmLWXXuqKNH2Q67j69T4Q7Zew5c8wJKaV', 'buyback_fee_recipient': 'HjQjngTDqoHE6aaGhUqfz9aQ7WZcBRjy5xB8PScLSr8i', 'token_program': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'token_2022_program': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', 'pump_program': '6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P', 'pump_global': '4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf', 'pump_fee_config': '8Wf5TiAheLUqBrKXeYg2JtAFFMWtKdG2BSFgqUcPVwTt', 'pump_event_authority': 'Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1', 'pool_v2': '4Jjna3h73QbgmdqwnV5NJxjCidKWB7Q26jeuj9jtFetC', 'buyback_owner': '5YxQFdt3Tr9zJLvkFccqXVUwhdTWJQc1fFg2YPbxvxeD', 'uvata': 'BEaaJNs1cVZKv29qYcXaaDSgm6Defa5b6kt5pRcUkHWe', 'OUTSIDER_KEY': '5jotNjSnm9ZJRefVfqHato9FC4d9t6CHb2xS1726MTyY'}
ROLE_KEYS = {'fee_payer': 'DXyM8yAHqpMzDtvwz5DXoEUQmPxjJPMKCASCPhLMKpEx', 'pool': 'GseMAnNDvntR5uFePZ51yZBXzNSn7GdFPkfHwfr6d77J', 'global_config': 'ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw', 'userbase': '5jKh25biPsnrmLWXXuqKNH2Q67j69T4Q7Zew5c8wJKaV', 'userquote': '5oEzAP4izB65uRm2yDAEf9oALGwHpWkDfyKb8zBY3euC', 'vaultbase': '5jMpkf4JF4noHftLgNKyPNh6roVfPSGSjuEk3U4eLKRa', 'vaultquote': '43DVcZR4kQFjh4Xm2i3DcneRxNjZp7HMud8yDrJWrDr8', 'protocol_ata': '94qWNrtmfn42h3ZjUZwWvK1MEo9uVmmrBPd2hpNjYDjb', 'creator_ata': '3E6RtRCxo7Yz64zi8aSmC9DtNKcaMp5rFUcBnJKsc2fg', 'buyback': 'HjQjngTDqoHE6aaGhUqfz9aQ7WZcBRjy5xB8PScLSr8i', 'volume': '8NyBnxo9mS5MsqY4qoKmrt7MS89d7MNV6rh5fu2YsQPT'}
IMAGE_SHA256 = {'original': '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7', 'control': '7a300434dced61413bde10788594b427d5649563e0223efcf09e6b214aff7ad3', 'candidate': 'd17a657baf5cc19736a924c41e75424604411ddbe9f6e72cddf41ab72a695007'}
CASES_SHA256 = 'e0abecf294efc79b6e5f33a359a88122ff1b5825c6e6c1894fc38ead5c5c598d'
PRODUCER_SHA256 = '8182f75f82cc39628aa56802f3976d1f23a38dd530f89137f49dca8a9473349f'
IDL_SHA256 = 'b7d8c57a4d9c4dd0109a9ab893052352333252d4eedced10ac091d4d66cab89b'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def declared_inputs():
    """Interpret only finite CASES input literals; never import/eval the producer."""
    source = (HERE / "producer.py").read_bytes()
    assert sha(source) == PRODUCER_SHA256, "retained producer binding"
    tree = ast.parse(source)
    tables = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets)]
    assert len(tables) == 1 and isinstance(tables[0], ast.List), "one declared case table"
    def read(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, bool, type(None))):
            return node.value
        if isinstance(node, ast.Name) and node.id in ("PAYER_KEY", "OUTSIDER_KEY"):
            return KEYS["user"] if node.id == "PAYER_KEY" else KEYS["OUTSIDER_KEY"]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            a, b = read(node.left), read(node.right)
            assert isinstance(a, int) and isinstance(b, int) and 0 <= b <= 64
            return a**b
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name == "dict":
                assert not node.args and all(kw.arg in ("name", "amount", "limit", "track", "overrides", "sell") for kw in node.keywords)
                return {kw.arg: read(kw.value) for kw in node.keywords}
            if name == "vol_seed":
                assert len(node.args) in (1, 2) and not node.keywords
                return {"seed_user": read(node.args[0]), "seed_earned": read(node.args[1]) if len(node.args) == 2 else 555}
            if name == "sell_cash":
                assert len(node.args) == 1 and read(node.args[0]) is True and not node.keywords
                return {"cashback": True}
            if name == "combine":
                assert not node.keywords
                combined = {}
                for arg in node.args:
                    value = read(arg)
                    assert isinstance(value, dict) and not set(value) & set(combined)
                    combined.update(value)
                return combined
        raise ValueError("Unsupported declared input AST: " + ast.dump(node))
    out = []
    for row in tables[0].elts:
        assert isinstance(row, ast.Tuple) and len(row.elts) == 6
        family, kind, instruction, label = [read(node) for node in row.elts[:4]]
        kwargs = read(row.elts[4])
        assert isinstance(kwargs, dict) and kwargs.get("name", instruction) == instruction
        assert 0 <= kwargs["amount"] < 2**64 and 0 <= kwargs["limit"] < 2**64
        out.append({"family": family, "kind": kind, "instruction": instruction, "label": label, "kwargs": kwargs})
    assert len(out) == 26 and len({row["label"] for row in out}) == 26, "declared26case membership"
    return out


def verify_binding(r, declared, idl):
    ctx = r["context"]
    assert all(ctx[name] == declared[name] for name in ("family", "kind", "instruction", "label")), "declared case identity"
    raw = base64.b64decode(r["transaction_base64"], validate=True)
    tx = Transaction.from_bytes(raw)
    assert bytes(tx) == raw and len(tx.signatures) == 1 and all(tx.verify_with_results()), "canonical signed wire"
    m = tx.message
    assert len(m.instructions) == 1
    ix = m.instructions[0]
    assert str(m.account_keys[0]) == KEYS["user"] and str(m.account_keys[ix.program_id_index]) == KEYS["program"], "signed payer/program"
    kwargs, kind = declared["kwargs"], declared["kind"]
    desc = next(row for row in idl["instructions"] if row["name"] == declared["instruction"])
    data = bytes(desc["discriminator"]) + struct.pack("<QQ", kwargs["amount"], kwargs["limit"])
    if kind == "legacy_buy":
        data += kwargs.get("track", b"\0")
    assert bytes(ix.data) == data, "declared signed instruction data"
    keys = dict(KEYS)
    if kind == "mh":
        keys["user_in_token_account"] = KEYS["user_base_token_account"] if kwargs.get("sell") else KEYS["user_quote_token_account"]
        keys["user_out_token_account"] = KEYS["user_quote_token_account"] if kwargs.get("sell") else KEYS["user_base_token_account"]
    metas = [(keys[row["name"]], bool(row.get("signer")), bool(row.get("writable"))) for row in desc["accounts"]]
    override = kwargs.get("overrides", {})
    if kind in ("legacy_buy", "legacy_sell"):
        if override.get("cashback"):
            metas += [(KEYS["uvata"], False, True), (KEYS["user_volume_accumulator"], False, True)]
        metas += [(KEYS["pool_v2"], False, False), (KEYS["buyback_owner"], False, False), (KEYS["buyback_fee_recipient"], False, True)]
    elif kind == "mh":
        metas += [(KEYS[name], False, name in ("pool", "pool_base_token_account", "pool_quote_token_account")) for name in ("base_mint", "quote_mint", "pool", "pool_base_token_account", "pool_quote_token_account")]
    assert len(ix.accounts) == len(metas), "signed account count"
    privileges = {0: (True, True)}
    for index, (key, signer, writable) in zip(ix.accounts, metas):
        assert str(m.account_keys[index]) == key, "signed account position"
        old = privileges.get(index, (False, False))
        privileges[index] = (old[0] or signer, old[1] or writable)
    privileges.setdefault(ix.program_id_index, (False, False))
    assert set(privileges) == set(range(len(m.account_keys))) and len(set(m.account_keys)) == len(m.account_keys), "signed key membership"
    h = m.header
    for index, want in privileges.items():
        signer = index < h.num_required_signatures
        writable = index < h.num_required_signatures - h.num_readonly_signed_accounts if signer else index < len(m.account_keys) - h.num_readonly_unsigned_accounts
        assert (signer, writable) == want, "signed account privileges"
    assert r["roles"] == ROLE_KEYS, "declared role binding"
    excluded = {KEYS[name] for name in ("base_token_program", "quote_token_program", "token_program", "token_2022_program", "system_program", "associated_token_program", "program", "fee_program", "pump_program")}
    watched = {key for key, _, _ in metas} - excluded
    # Plain legacy sell does not pass the volume PDA. Its helper explicitly
    # watches that derived account; no signed instruction binding is claimed.
    watched.add(KEYS["user_volume_accumulator"])
    assert set(r["before"]) == set(r["after"]) == watched, "watched account membership"
    volume = str(Pubkey.find_program_address([b"user_volume_accumulator", bytes(Pubkey.from_string(KEYS["user"]))], Pubkey.from_string(KEYS["program"]))[0])
    assert volume == r["roles"]["volume"], "derived watched volume PDA"
    initial = r["before"][volume]
    if "seed_user" in override:
        assert initial == {"data_hex": seed_bytes(override["seed_user"], override["seed_earned"]), "lamports": 10**9, "owner": KEYS["program"]}, "entire declared before-volume"
    else:
        assert initial is None, "fresh before-volume absent"
    pool = bytes.fromhex(r["before"][KEYS["pool"]]["data_hex"])
    assert pool[244] == int(override.get("cashback", False)), "declared cashback pool"
    events = [line for line in r["metadata"]["logs"] if line.startswith("Program data: ")]
    assert len(events) == r["metadata"]["events"], "event count from logs"
    if events:
        assert len(events) == 1
        event = base64.b64decode(events[0].split(": ", 1)[1], validate=True)
        event_name = "SellEvent" if declared["instruction"] in ("sell", "sell_v2") or kwargs.get("sell") else "BuyEvent"
        assert event[:8] == hashlib.sha256(("event:" + event_name).encode()).digest()[:8], "event discriminator"


def amount_at(data_hex, offset=64):
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
    if len(raw) != (512 if exact else 497):
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


def decode_tuple_event(logs, length, track):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    if len(raw) != length:
        return None
    tup = [struct.unpack_from("<Q", raw, off)[0]
           for off in (16, 24, 64, 72, 80, 88, 96, 104, 112)]
    if track is not None:
        assert raw[360] == track, (raw[360], track)
    return {"tuple": tup, "length": length, "track": track}


def seed_bytes(user_key_str, earned):
    user = bytes(Pubkey.from_string(user_key_str))
    raw = DISC + user + bytes([1]) + struct.pack("<Q", 111) \
        + struct.pack("<Q", 222) + struct.pack("<Q", 333444) \
        + struct.pack("<q", 999) + bytes([1]) + struct.pack("<Q", earned) \
        + struct.pack("<Q", 666)
    return raw.ljust(137, b"\0").hex()


def expected_vol_hex(spec, payer_key_str):
    if spec[0] == "fresh":
        return (DISC + bytes(Pubkey.from_string(payer_key_str)) + bytes(97)).hex()
    if spec[0] == "seed":
        return seed_bytes(spec[1], 555 if spec[2] is None else spec[2])
    if spec[0] == "seed_user_to_payer":
        return seed_bytes(payer_key_str, 555)
    raise AssertionError(spec)


def pool_fields(data_hex):
    raw = bytes.fromhex(data_hex)
    return {"vq": int.from_bytes(raw[245:261], "little", signed=True),
            "proto": struct.unpack_from("<Q", raw, 271)[0],
            "creator": struct.unpack_from("<Q", raw, 279)[0]}


def main():
    paths = list(HERE.rglob("*"))
    assert not any(path.is_symlink() for path in paths), "packet symlink"
    assert all(path.is_file() or path.is_dir() for path in paths), "packet special file"
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
    assert len(report["cases"]) == len({row["case"]["label"] for row in report["cases"]}) == 26, "exact case membership"
    assert sha(canonical(report["cases"])) == CASES_SHA256, "exact case definitions"
    declared = declared_inputs()
    assert all(all(case["case"][name] == spec[name] for name in ("family", "kind", "instruction", "label")) for case, spec in zip(report["cases"], declared)), "declared case membership"
    assert report["mismatches"] == [] and report["divergent_cases"] == []
    assert sha(canonical(report["input_sha256"])) == 'ee66b5951e7c2e9f40f43c062d83ace5ce52bb239b6befc02a2f72e0361be8c4', "exact recorded repository input map"
    for rel, digest in report["input_sha256"].items():
        assert sha((ROOT / rel).read_bytes()) == digest, rel
    assert report["image_sha256"] == IMAGE_SHA256, "historical image declarations"
    for label, path in {"original": "evidence/original/pump_amm/deployed.so", "control": "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz", "candidate": "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz"}.items():
        raw = (ROOT / path).read_bytes()
        raw = gzip.decompress(raw) if path.endswith(".gz") else raw
        assert sha(raw) == IMAGE_SHA256[label], "authenticated historical image"
    idl_raw = (ROOT / "evidence/upstream/pump_amm.json").read_bytes()
    assert sha(idl_raw) == IDL_SHA256, "reviewed IDL binding"
    idl = json.loads(idl_raw)
    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (HERE / part["path"]).read_bytes()
        assert len(data) < 25 * 1024 * 1024, part["path"]
        assert sha(data) == part["sha256"], part["path"]
        chunk = [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l]
        assert len(chunk) == part["receipts"], part["path"]
        receipts.extend(chunk)
    assert len(receipts) == 78, len(receipts)
    assert report["counts"] == {"vms": 78, "transactions": 78, "signature_fields": 78}
    assert [part["path"] for part in report["transaction_receipts"]["parts"]] == [f"runtime/raw-transactions-part{i}.jsonl.gz" for i in range(1, 9)], "exact receipt parts"
    for seq, r in enumerate(receipts):
        assert r["sequence"] == seq and r["vm"] == seq, seq
        assert r["all_signatures_verified"] is True and r["signature_fields"] == 1, seq
        tx = Transaction.from_bytes(base64.b64decode(r["transaction_base64"]))
        assert tx.verify_with_results() and all(tx.verify_with_results()), seq
        assert str(tx.signatures[0]) == r["signatures"][0], seq
        assert r["transaction_sha256"] == sha(base64.b64decode(r["transaction_base64"])), seq
        assert r["payer_delta_lamports"] == r["observed"]["payer_paid"], seq
        ctx = r["context"]
        assert ctx["image"] in IMAGES and 0 <= ctx["index"] < 26, "receipt case/image membership"
        assert ctx["index"] == seq // 3 and ctx["image"] == IMAGES[seq % 3], "ordered receipt membership"
        verify_binding(r, declared[ctx["index"]], idl)
    by_case = {}
    for r in receipts:
        ctx = r["context"]
        by_case.setdefault(ctx["label"], {}).setdefault(ctx["image"], []).append(r)
    assert len(by_case) == 26, len(by_case)
    assert all(set(images) == set(IMAGES) for images in by_case.values()), "exact image roles"
    assert all(len({row["transaction_base64"] for group in images.values() for row in group}) == 1 for images in by_case.values()), "same signed wire across images"
    for case in report["cases"]:
        c = case["case"]
        label, ix_name, kind = c["label"], c["instruction"], c["kind"]
        exp = c["expected"]
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
            vol_a = after.get(roles["volume"])
            vol_after_hex = vol_a["data_hex"] if vol_a else None
            assert vol_after_hex == obs["volume_after_hex"], (label, image)
            assert (vol_a["lamports"] if vol_a else None) == obs["volume_after_lamports"], \
                (label, image)
            if exp["kind"] == "ok":
                assert r["error"] is None, (label, image, r["error"])
                assert r["metadata"]["events"] == 1, (label, image)
                if kind == "legacy_buy":
                    ev = decode_buy_event(logs, ix_name == "buy_exact_quote_in")
                    assert ev == obs["event"], (label, image, ev, obs["event"])
                    want_ev = dict(exp["event"])
                    want_ev["max"] = want_ev.pop("max_")
                    assert obs["event"] == want_ev, (label, image)
                else:
                    ev = decode_tuple_event(logs, exp["event"]["length"],
                                            exp["event"]["track"])
                    assert ev == obs["event"] == exp["event"], (label, image, ev)
                deltas = {}
                for name in obs["deltas"]:
                    key = roles[name]
                    b, a = before.get(key), after.get(key)
                    assert a, (label, image, name)
                    b_amt = amount_at(b["data_hex"]) if b else 0
                    deltas[name] = amount_at(a["data_hex"]) - b_amt
                assert deltas == obs["deltas"] == exp["deltas"], (label, image, deltas)
                want_vol = expected_vol_hex(exp["vol_after"], payer)
                assert vol_after_hex == want_vol, (label, image)
                if exp["vol_after"][0] == "fresh":
                    assert obs["volume_after_lamports"] == 1844400, (label, image)
                else:
                    assert obs["volume_after_lamports"] == 10**9, (label, image)
                assert payer_paid == exp["payer"], (label, image, payer_paid)
                if exp.get("pool_after") is not None:
                    pb = pool_fields(before[roles["pool"]]["data_hex"])
                    pa = pool_fields(after[roles["pool"]]["data_hex"])
                    assert pb == {"vq": -125882, "proto": 2488, "creator": 123394}, "declared initial pool fields"
                    pool_after = {"vq_delta": pa["vq"] - pb["vq"],
                                  "proto_delta": pa["proto"] - pb["proto"],
                                  "creator_delta": pa["creator"] - pb["creator"]}
                    assert pool_after == obs["pool_after"] == \
                        {"vq_delta": exp["pool_after"]["vq"],
                         "proto_delta": exp["pool_after"]["proto"],
                         "creator_delta": exp["pool_after"]["creator"]}, \
                        (label, image, pool_after)
            else:
                assert r["error"] is not None, (label, image)
                assert exp["code"] in r["error"], (label, image, r["error"])
                assert exp["fragment"] in (r["error"] or "") or exp["fragment"] in "\n".join(logs), \
                    (label, image)
                assert r["metadata"]["events"] == 0, (label, image)
                assert obs["rollback"] is True, (label, image)
                assert payer_paid == exp["payer"], (label, image, payer_paid)
                for key, snap_b in before.items():
                    if key == payer:
                        continue
                    assert snap_b == after.get(key), (label, image, key, "no rollback")
        assert len(obs_seen) == 1, (label, "images must agree", obs_seen)
    print("verify PASS: 26 cases x 3 images = 78 receipts, all checks passed")


if __name__ == "__main__":
    main()
