#!/usr/bin/env python3
"""Independent re-verification for amm-reserved-fee-recipients-downstream-20261029.

Checks, from the packet files alone (plus the three program images):
- MANIFEST.json lists every packet file with a matching sha256.
- runtime/report.json.gz: 34 cases, 162 receipts, 17 parts (16x10 + 2),
  part sha256/byte counts match the part files.
- Every receipt transaction parses (solders) and all signatures verify.
- Every receipt's recorded before/after snapshots reproduce the
  report's expected values: payer delta (unique lamport mover rule),
  pool protocol/creator fee fields and virtual quote reserves,
  config writes for set steps (whitelist_pda 353..385,
  reserved_fee_recipient 385..417, reserved_fee_recipients 418..642,
  byte 417 untouched, nothing else changed), event count, and
  decoded event fields (set/buy/buyexact/sell/v2buy/v2sell/mh layouts
  documented in README).
- Failure steps roll back every watched account except the payer
  (fee 5,000) and carry the expected error code plus the recorded
  per-image site line ("thrown in" / "caused by account") in their
  logs. Site lines are checked per image, never compared across
  images, because original and rebuilt sources differ in line
  numbers.
- The observed surface of every case (step, error, event count,
  pool fees/vq, config bytes, all token/lamport deltas, payer delta)
  is identical across the original, control, and candidate images.
- The three program images hash to the values recorded in the
  report.

Usage: python3 verify.py   (run from this packet directory)
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

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
IMAGE_PATHS = {
    "original": REPO / "evidence/original/pump_amm/deployed.so",
    "control": REPO / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz",
    "candidate": REPO / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz",
}
# Reviewed fixture public keys and PDA/account associations, checked against the
# producer's builders and signed messages. They do not attest prior VM loads.
KEYS = {'pool': 'GseMAnNDvntR5uFePZ51yZBXzNSn7GdFPkfHwfr6d77J', 'user': 'DXyM8yAHqpMzDtvwz5DXoEUQmPxjJPMKCASCPhLMKpEx', 'global_config': 'ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw', 'base_mint': '7LSsEoJGhLeZzGvDofTdNg7M3JttxQqGWNLo6vWMpump', 'quote_mint': 'So11111111111111111111111111111111111111112', 'user_base_token_account': '5jKh25biPsnrmLWXXuqKNH2Q67j69T4Q7Zew5c8wJKaV', 'user_quote_token_account': '5oEzAP4izB65uRm2yDAEf9oALGwHpWkDfyKb8zBY3euC', 'pool_base_token_account': '5jMpkf4JF4noHftLgNKyPNh6roVfPSGSjuEk3U4eLKRa', 'pool_quote_token_account': '43DVcZR4kQFjh4Xm2i3DcneRxNjZp7HMud8yDrJWrDr8', 'protocol_fee_recipient': '62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV', 'protocol_fee_recipient_token_account': '94qWNrtmfn42h3ZjUZwWvK1MEo9uVmmrBPd2hpNjYDjb', 'base_token_program': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'quote_token_program': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'system_program': '11111111111111111111111111111111', 'associated_token_program': 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', 'event_authority': 'GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR', 'program': 'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA', 'coin_creator_vault_ata': '3E6RtRCxo7Yz64zi8aSmC9DtNKcaMp5rFUcBnJKsc2fg', 'coin_creator_vault_authority': '4LFFCuf82nwijjNjbu8enNmfVa5hqBxBctgnuJ7ZNNMS', 'global_volume_accumulator': 'C2aFPdENg4A2HQsmrd5rTw5TaYBX5Ku887cWjbFKtZpw', 'user_volume_accumulator': '8NyBnxo9mS5MsqY4qoKmrt7MS89d7MNV6rh5fu2YsQPT', 'fee_config': '5PHirr8joyTMp9JMm6nW7hNDVyEYdkzDqazxPD7RaTjx', 'fee_program': 'pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ', 'user_in_token_account': '5oEzAP4izB65uRm2yDAEf9oALGwHpWkDfyKb8zBY3euC', 'user_out_token_account': '5jKh25biPsnrmLWXXuqKNH2Q67j69T4Q7Zew5c8wJKaV', 'buyback_fee_recipient': 'HjQjngTDqoHE6aaGhUqfz9aQ7WZcBRjy5xB8PScLSr8i', 'token_program': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'token_2022_program': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', 'pump_program': '6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P', 'pump_global': '4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf', 'pump_fee_config': '8Wf5TiAheLUqBrKXeYg2JtAFFMWtKdG2BSFgqUcPVwTt', 'pump_event_authority': 'Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1', 'buyback_owner': '5YxQFdt3Tr9zJLvkFccqXVUwhdTWJQc1fFg2YPbxvxeD', 'pool_v2': '4Jjna3h73QbgmdqwnV5NJxjCidKWB7Q26jeuj9jtFetC', 'RES0': 'GesfTA3X2arioaHp8bbKdjG9vJtskViWACZoYvxp4twS', 'RES0_ATA': 'C93K8DX4YsABYJtHX9awzgZW3LWzBqBVezEbbLJH4yet', 'outside_user': '4XftcvoGV8VPwvj2ZnoxttieKwfoaP6zwnYN7EGQbMX2', 'outside_user_base_token_account': '2v4isFrCDMXRtrViLfBEvcxpwg5Tn1ZtNxtiaJGJtViC', 'outside_user_quote_token_account': '7ogkR5EB1M87jCX99WUpK6esXskuZZfLSnfndcCBZZQR', 'outside_user_volume_accumulator': '59Gk4X16BqTfHZGzHRijeV9HcoMZH8WeCPBPTwoJXdWG'}
WATCH = ['GseMAnNDvntR5uFePZ51yZBXzNSn7GdFPkfHwfr6d77J', '5jKh25biPsnrmLWXXuqKNH2Q67j69T4Q7Zew5c8wJKaV', '5oEzAP4izB65uRm2yDAEf9oALGwHpWkDfyKb8zBY3euC', '5jMpkf4JF4noHftLgNKyPNh6roVfPSGSjuEk3U4eLKRa', '43DVcZR4kQFjh4Xm2i3DcneRxNjZp7HMud8yDrJWrDr8', '94qWNrtmfn42h3ZjUZwWvK1MEo9uVmmrBPd2hpNjYDjb', '3E6RtRCxo7Yz64zi8aSmC9DtNKcaMp5rFUcBnJKsc2fg', 'HjQjngTDqoHE6aaGhUqfz9aQ7WZcBRjy5xB8PScLSr8i', '8NyBnxo9mS5MsqY4qoKmrt7MS89d7MNV6rh5fu2YsQPT', 'ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw', 'DXyM8yAHqpMzDtvwz5DXoEUQmPxjJPMKCASCPhLMKpEx', 'C93K8DX4YsABYJtHX9awzgZW3LWzBqBVezEbbLJH4yet', '2v4isFrCDMXRtrViLfBEvcxpwg5Tn1ZtNxtiaJGJtViC', '7ogkR5EB1M87jCX99WUpK6esXskuZZfLSnfndcCBZZQR', '59Gk4X16BqTfHZGzHRijeV9HcoMZH8WeCPBPTwoJXdWG', '4XftcvoGV8VPwvj2ZnoxttieKwfoaP6zwnYN7EGQbMX2']
CASE_SHAPE = [('s-set-8', 'S', ['set']), ('s-set-9', 'S', ['set']), ('s-set-7', 'S', ['set']), ('s-set-zero', 'S', ['set']), ('s-set-dup', 'S', ['set']), ('s-set-exec', 'S', ['set']), ('s-set-unfunded', 'S', ['set']), ('w-buy-empty', 'W', ['set', 'buy']), ('w-buy-std', 'W', ['set', 'buy']), ('w-buy-trim', 'W', ['set', 'buy']), ('w-buyexact-std', 'W', ['set', 'buyexact']), ('w-buyexact-trim', 'W', ['set', 'buyexact']), ('w-sell-std', 'W', ['set', 'sell']), ('w-sell-empty', 'W', ['set', 'sell']), ('w-sell-trim', 'W', ['set', 'sell']), ('w-v2buy', 'W', ['set', 'v2buy']), ('w-v2sell', 'W', ['set', 'v2sell']), ('w-mhbuy', 'W', ['set', 'mhbuy']), ('w-mhsell', 'W', ['set', 'mhsell']), ('w-nonwl-buy', 'W', ['set', 'buy']), ('w-outsider-buy', 'W', ['set', 'buy']), ('a-v2buy', 'W', ['v2buy']), ('a-v2sell', 'W', ['v2sell']), ('a-mhbuy', 'W', ['mhbuy']), ('a-mhsell', 'W', ['mhsell']), ('m-buy-noset', 'M', ['buy']), ('m-buy-res0', 'M', ['buy']), ('m-buy-res0-replaced', 'M', ['set', 'buy']), ('m-buy-protocol-set', 'M', ['set', 'buy']), ('m-sell-protocol-set', 'M', ['set', 'sell']), ('m-sell-noset', 'M', ['sell']), ('m-wl-buy-trim', 'M', ['set', 'buy']), ('m-wl-buy-std', 'M', ['set', 'buy']), ('m-nonmayhem-reserved', 'M', ['set', 'buy'])]
CASES_SHA256 = '7a0ef6aaf9a21c2ceb36fbc07f0d0cd85f48ba2ff5bd9e0da5c5e17cb5873f7d'
INITIAL_BEFORE_SHA256 = {'s-set-8': 'bb260c13988672be7e2cd0e24e9daf76d0ddbe3b41dc3303273403c8ae5db084', 's-set-9': 'b504dbc81e25ce47e00f1afdb6eb5508f32a343cfbc7ddbfc54e464364f2d531', 's-set-7': '7af4e77b6b5e8aec636ff8421b0bb6999862c391bc6102daf15e179e256442a7', 's-set-zero': 'd622bbd28cd08ca8509dd3c2436e326f784202da7b10b73ac6693bf06088c9f5', 's-set-dup': 'febdbe287d9155b773040c8d8223bbf6f807de6a13a2b07bb220192632ca49f8', 's-set-exec': '713a74ec9aacc977a2c74cd8c971df9158464c06ef5d8e4830c725f9d96698a0', 's-set-unfunded': 'df68636392a35bba932a74250b9e7499d05b6a74235e2b2b68cbb417a09b7ffd', 'w-buy-empty': '23311be175ba26f4ca123357e7385a809ad776f4ebde6d74a652300eb69c23ff', 'w-buy-std': '4e7f182e59af64e655a398904f44873ab4768d8ad5db451c49dfcddb294281dd', 'w-buy-trim': 'a5d1cf1bef68176bea8b4d1ac229d676dd9a6c47f1c68ab3dd3e847b02bd8adc', 'w-buyexact-std': '87c3bd664aca2dfd37759912d5ee8b37e88bb97b8e57503f6570b0c6a537f457', 'w-buyexact-trim': 'e04bed9c5b2639bf353714b86789188174c0d7fd19b6dc684bc4b079af96a9a4', 'w-sell-std': '91dd9e85c6ed30a1a334180564f741acbde1ccdbd59f4d0a28ae273ae42bc00b', 'w-sell-empty': '71715e3284f8079af90084551486d6a8955d54e94c0e0e41d5b6cb8c0903d91f', 'w-sell-trim': '7228dd1ab9e05d7d0ff0c51c04762eb3c56b1e9f31a28a33efaef89975c9d0ce', 'w-v2buy': '04ad9effd918a3eb4279c0b081228eb954ad2a02e1a052785d5f1ff3435bc8ff', 'w-v2sell': '84a5ed4ef2166878df1f2046c2d4134c69ba870ffdb6a69aac8e5470d08f25e2', 'w-mhbuy': 'cab1d3e04d6c66fa4aff94be1fdd1c61f20eba96d57ddf449567b906d385a465', 'w-mhsell': 'd8bc820c2eb538a40917bbf4ce7176f7c065766dc4dcc0fd3ee34a459843ffd2', 'w-nonwl-buy': '3e5e4dd41fbb436a1b4c69f10ce7d6fe8636837cf1093e3e4df554b8bc223a67', 'w-outsider-buy': 'cb9b3ca6ad2342c70f535e4a3f579b587586f7b5d23e64bc9921102e0656638d', 'a-v2buy': 'aa95c439020c175bde2f9c138ef8871e0f45bedf76544625eb160d13899f71fe', 'a-v2sell': '6932d75cd251ee2fce0651db92edec3c61b4517e3412c889fa9f03a4cab0283c', 'a-mhbuy': '4e742e209e3d2a79e3a7accbf60b969eed2cb9c9b693bb2e6c30fa2311835818', 'a-mhsell': '17bfcf21851f8479f2f8ebdacc7f2270ec13befdea5da68fb7a78236c5ee9b03', 'm-buy-noset': '69f7347af5a6c43d15acc1a0c07b2dcf395d79d38c17d80b842cecfcaca5fe68', 'm-buy-res0': '7c1d647bcd77844c258bbd5fbb9f6747cdefab1d71c85fd02aa444c535efcfdb', 'm-buy-res0-replaced': '15b528681aafe6d566b2b5ef2884e663c6b2407aae1e54d16409740e660e8f03', 'm-buy-protocol-set': '7c9b189daa05b0faf4b9049ab19b24fafb4558fc6a6ac22e8a32bc41014ee618', 'm-sell-protocol-set': 'fc77b9ba80791d5a5940d2231b1b037183726ce03346bde4066352ae2945c7fc', 'm-sell-noset': 'b85988f74f58cfe1876fd09a406046c971401e2efe186efa1284190b19337987', 'm-wl-buy-trim': 'ceced0291e5b4fa2c0cf705aa9f4dcc6b235852eebb7036abc2a3763cb987de2', 'm-wl-buy-std': '3c3a8fc38fda7974f705ab2e7adc93bf9d3b346fb01480bd42ed7c2a77aa09c4', 'm-nonmayhem-reserved': '0d3df5756a61062b547daeba88506f85c9bc3a301a7729ff4156b0d62c162f63'}
IMAGE_SHA256 = {'original': '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7', 'control': '7a300434dced61413bde10788594b427d5649563e0223efcf09e6b214aff7ad3', 'candidate': 'd17a657baf5cc19736a924c41e75424604411ddbe9f6e72cddf41ab72a695007'}
IDL_SHA256 = 'b7d8c57a4d9c4dd0109a9ab893052352333252d4eedced10ac091d4d66cab89b'


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(condition, message):
    if not condition:
        fail(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def key_for(name, outside=False):
    names = {"pool": "pool", "userbase": "user_base_token_account",
             "userquote": "user_quote_token_account", "vaultbase": "pool_base_token_account",
             "vaultquote": "pool_quote_token_account", "PROTOCOL_ATA": "protocol_fee_recipient_token_account",
             "CREATOR_ATA": "coin_creator_vault_ata", "volume": "user_volume_accumulator",
             "buyback": "buyback_fee_recipient", "RES0_ATA": "RES0_ATA"}
    account = names[name]
    if outside and name in ("userbase", "userquote", "volume"):
        account = "outside_" + account
    return KEYS[account]


def setter_recipe(label):
    recipients = [str(Pubkey.from_bytes(bytes([0x61 + i]) * 32)) for i in range(8)]
    whitelist = KEYS["user"]
    if label == "w-outsider-buy":
        whitelist = KEYS["outside_user"]
    elif label == "w-nonwl-buy" or (label.startswith("m-") and label not in ("m-wl-buy-trim", "m-wl-buy-std")):
        whitelist = str(Pubkey.from_bytes(bytes([0x73]) * 32))
    if label.startswith("m-"):
        recipients[0] = KEYS["protocol_fee_recipient"]
    if label == "s-set-9":
        recipients.append(str(Pubkey.from_bytes(bytes([0x69]) * 32)))
    elif label == "s-set-7":
        recipients = recipients[:7]
    elif label == "s-set-zero":
        recipients[0] = str(Pubkey.default())
    elif label == "s-set-dup":
        recipients = recipients[:1] * 8
    elif label == "s-set-exec":
        recipients[0] = KEYS["base_token_program"]
    elif label == "s-set-unfunded":
        recipients[0] = str(Pubkey.from_bytes(bytes([0x72]) * 32))
    return whitelist, recipients


def verify_wire(rec, label, step, idl):
    raw = base64.b64decode(rec["transaction_base64"], validate=True)
    tx = Transaction.from_bytes(raw)
    need(bytes(tx) == raw and len(tx.signatures) == 1 and all(tx.verify_with_results()), "canonical single-signature wire")
    message = tx.message
    need(len(message.instructions) == 1, "one signed instruction")
    ix = message.instructions[0]
    keys, header = message.account_keys, message.header
    need(len(set(keys)) == len(keys), "unique signed keys")
    need(str(keys[ix.program_id_index]) == KEYS["program"], "signed program")
    name = {"set": "set_reserved_fee_recipients", "buyexact": "buy_exact_quote_in", "v2buy": "buy_v2", "v2sell": "sell_v2", "mhbuy": "multi_hop_swap", "mhsell": "multi_hop_swap"}.get(step, step)
    desc = next(row for row in idl["instructions"] if row["name"] == name)
    outside = label == "w-outsider-buy" and step != "set"
    payer = KEYS["outside_user"] if outside else KEYS["user"]
    need(str(keys[0]) == rec["payer_key"] == payer, "signed payer")
    expected_keys = dict(KEYS)
    if outside:
        for account in ("user", "user_base_token_account", "user_quote_token_account", "user_volume_accumulator"):
            expected_keys[account] = KEYS["outside_" + account]
    expected_keys["admin"] = KEYS["user"]
    if label in ("m-buy-res0", "m-buy-res0-replaced") and step != "set":
        expected_keys["protocol_fee_recipient"] = KEYS["RES0"]
        expected_keys["protocol_fee_recipient_token_account"] = KEYS["RES0_ATA"]
    if step == "set":
        whitelist, recipients = setter_recipe(label)
        payload = bytes(Pubkey.from_string(whitelist))
        remaining = [(key, False, False) for key in recipients]
    else:
        amount, limit = (10**10, 10**12) if step == "buy" else (10**7, 1) if step == "buyexact" else (10**6, 10**12 if step == "v2buy" else 1) if step.startswith("v2") else (10**9, 1)
        payload = struct.pack("<QQ", amount, limit) + (b"\0" if step in ("buy", "buyexact") else b"")
        if step.startswith("mh"):
            expected_keys["user_in_token_account"] = KEYS["user_base_token_account"] if step == "mhsell" else KEYS["user_quote_token_account"]
            expected_keys["user_out_token_account"] = KEYS["user_quote_token_account"] if step == "mhsell" else KEYS["user_base_token_account"]
            remaining = [(KEYS[account], False, account in ("pool", "pool_base_token_account", "pool_quote_token_account")) for account in ("base_mint", "quote_mint", "pool", "pool_base_token_account", "pool_quote_token_account")]
        elif step.startswith("v2"):
            remaining = []
        else:
            remaining = [(KEYS["buyback_owner"], False, False), (KEYS["buyback_fee_recipient"], False, True)]
            if label.endswith("-empty"):
                remaining = []
            elif label.endswith("-std") or label.startswith("m-") and label not in ("m-wl-buy-trim", "m-sell-noset") or label == "w-nonwl-buy":
                remaining.insert(0, (KEYS["pool_v2"], False, False))
    need(bytes(ix.data) == bytes(desc["discriminator"]) + payload, "signed instruction data")
    metas = [(expected_keys[row["name"]], bool(row.get("signer")), bool(row.get("writable"))) for row in desc["accounts"]] + remaining
    need(len(ix.accounts) == len(metas), "signed account count")
    privileges = {0: (True, True)}
    for index, (key, signer, writable) in zip(ix.accounts, metas):
        need(str(keys[index]) == key, "signed account position")
        old = privileges.get(index, (False, False))
        privileges[index] = (old[0] or signer, old[1] or writable)
    privileges.setdefault(ix.program_id_index, (False, False))
    need(set(privileges) == set(range(len(keys))), "signed key membership")
    for index, want in privileges.items():
        signer = index < header.num_required_signatures
        writable = index < header.num_required_signatures - header.num_readonly_signed_accounts if signer else index < len(keys) - header.num_readonly_unsigned_accounts
        need((signer, writable) == want, "signed account privileges")
    need(set(rec["before"]) == set(rec["after"]) == set(WATCH), "watched account membership")
    need(rec["events"] == [line for line in rec["logs"] if line.startswith("Program data: ")], "events bound to ordered logs")
    return outside


def tok_amount(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) < 72:
        return None
    return struct.unpack_from("<Q", raw, 64)[0]


def tok_delta(before, after):
    return (tok_amount(after) or 0) - (tok_amount(before) or 0)


def lam_delta(before, after):
    return (after["lamports"] if after else 0) - (before["lamports"] if before else 0)


def pool_fees(entry):
    raw = bytes.fromhex(entry["data_hex"])
    return [struct.unpack_from("<Q", raw, 271)[0],
            struct.unpack_from("<Q", raw, 279)[0]]


def pool_vq(entry):
    return int.from_bytes(bytes.fromhex(entry["data_hex"])[245:261], "little", signed=True)


def ev_data(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    return base64.b64decode(lines[0].split("Program data: ", 1)[1].strip(), validate=True)


def u64(raw, off):
    return struct.unpack_from("<Q", raw, off)[0]


def decode_event(kind, rec):
    raw = ev_data(rec["logs"])
    if raw is None:
        return None
    lengths = {"set": 272, "buy": 497, "buyexact": 512, "sell": 449, "v2buy": 500, "v2sell": 449, "mhbuy": 508, "mhsell": 449}
    event = "ReservedFeeRecipientsEvent" if kind == "set" else "SellEvent" if kind in ("sell", "v2sell", "mhsell") else "BuyEvent"
    need(len(raw) == lengths[kind] and raw[:8] == hashlib.sha256(("event:" + event).encode()).digest()[:8], "event discriminator/length")
    if kind in ("buy", "buyexact"):
        bb, bf = (439, 447) if kind == "buyexact" else (424, 432)
        return {"curve": u64(raw, 64), "lp_bps": u64(raw, 72), "lp_fee": u64(raw, 80),
                "proto_bps": u64(raw, 88), "proto_fee": u64(raw, 96),
                "qwlp": u64(raw, 104), "uqin": u64(raw, 112),
                "creator_bps": u64(raw, 344), "creator_fee": u64(raw, 352),
                "buyback_bps": u64(raw, bb), "buyback_fee": u64(raw, bf)}
    if kind == "sell":
        return {"quote": u64(raw, 64), "proto_fee": u64(raw, 96)}
    if kind in ("v2buy", "v2sell"):
        d = {"curve": u64(raw, 64), "quote": u64(raw, 64), "lp_bps": u64(raw, 72),
             "lp_fee": u64(raw, 80), "proto_bps": u64(raw, 88),
             "proto_fee": u64(raw, 96), "qwlp": u64(raw, 104),
             "uqin": u64(raw, 112), "creator_bps": u64(raw, 344),
             "creator_fee": u64(raw, 352)}
        if kind == "v2buy":
            d["buyback_bps"] = u64(raw, 427)
            d["buyback_fee"] = u64(raw, 435)
        else:
            d["buyback_bps"] = u64(raw, 376)
            d["buyback_fee"] = u64(raw, 384)
        return d
    if kind in ("mhbuy", "mhsell"):
        return {"hop": [u64(raw, o) for o in (64, 72, 80, 88, 96, 104, 112)]}
    if kind == "set":
        return {"ts": struct.unpack_from("<q", raw, 8)[0],
                "recip": raw[16:48].hex(),
                "recips": [raw[48 + i * 32:80 + i * 32].hex() for i in range(7)],
                "disc": raw[:8].hex(), "len": len(raw)}
    return None


def main():
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    paths = list(ROOT.rglob("*"))
    need(not any(path.is_symlink() for path in paths), "packet symlink")
    need(all(path.is_file() or path.is_dir() for path in paths), "packet special file")
    need(set(manifest["files"]) == {str(path.relative_to(ROOT)) for path in paths if path.is_file() and path.name != "MANIFEST.json"}, "exact packet inventory")
    for rel, want in manifest["files"].items():
        path = ROOT / rel
        if not path.exists():
            fail(f"manifest file missing: {rel}")
        if sha(path.read_bytes()) != want:
            fail(f"manifest sha mismatch: {rel}")
    with gzip.open(ROOT / "runtime" / "report.json.gz", "rt", encoding="utf-8") as fh:
        report = json.load(fh)
    if report["case_count"] != 34:
        fail(f"case_count {report['case_count']} != 34")
    if report["receipt_count"] != 162:
        fail(f"receipt_count {report['receipt_count']} != 162")
    if report["counts"] != {"cases": 34, "receipts": 162, "parts": 17}:
        fail(f"counts {report['counts']}")
    if report["mismatches"] != []:
        fail(f"mismatches non-empty: {report['mismatches']}")
    need([(case["label"], case["family"], [step["name"] for step in case["steps"]]) for case in report["cases"]] == CASE_SHAPE, "exact case membership")
    need(sha(canonical(report["cases"])) == CASES_SHA256, "exact case expectations/sites")
    need(report["input_sha256"] == report["images"] == IMAGE_SHA256, "historical image declarations")
    for name, want in report["input_sha256"].items():
        raw = IMAGE_PATHS[name].read_bytes()
        if str(IMAGE_PATHS[name]).endswith(".gz"):
            raw = gzip.decompress(raw)
        if sha(raw) != want:
            fail(f"image sha mismatch: {name}")
    idl_raw = (REPO / "evidence/upstream/pump_amm.json").read_bytes()
    need(sha(idl_raw) == IDL_SHA256, "reviewed IDL binding")
    idl = json.loads(idl_raw)
    receipts = []
    for part in report["parts"]:
        path = ROOT / part["file"]
        if sha(path.read_bytes()) != part["sha256"]:
            fail(f"part sha mismatch: {part['file']}")
        if path.stat().st_size != part["bytes"]:
            fail(f"part bytes mismatch: {part['file']}")
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            chunk = [json.loads(line) for line in fh]
        if len(chunk) != part["count"]:
            fail(f"part count mismatch: {part['file']}")
        receipts.extend(chunk)
    if len(receipts) != 162:
        fail(f"total receipts {len(receipts)} != 162")
    if [p["count"] for p in report["parts"]] != [10] * 16 + [2]:
        fail(f"part counts {[p['count'] for p in report['parts']]}")
    need([part["file"] for part in report["parts"]] == [f"runtime/raw-transactions-part{i:02d}.jsonl.gz" for i in range(1, 18)], "exact receipt parts")
    for case in report["cases"]:
        wires = {}
        for image in ("original", "control", "candidate"):
            chain = [row for row in receipts if row["case"] == case["label"] and row["image"] == image]
            need([row["step"] for row in chain] == [step["name"] for step in case["steps"]], "exact chain image/step membership")
            need(sha(canonical(chain[0]["before"])) == INITIAL_BEFORE_SHA256[case["label"]], "reviewed initial watched state")
            for previous, current in zip(chain, chain[1:]):
                need(previous["after"] == current["before"], "complete setter/trade state continuity")
            for row in chain:
                wires.setdefault(row["step"], set()).add(row["transaction_base64"])
        need(all(len(values) == 1 for values in wires.values()), "same wire across image roles")

    expected_order = []
    for case in report["cases"]:
        for image in ("original", "control", "candidate"):
            for step in case["steps"]:
                expected_order.append((case["label"], image, step["name"]))
    got_order = [(r["case"], r["image"], r["step"]) for r in receipts]
    if got_order != expected_order:
        fail("receipt order does not match report cases")

    cases_by_label = {c["label"]: c for c in report["cases"]}
    surfaces = {}
    for (case, image, step_name), rec, exp in zip(
            expected_order, receipts,
            [s for c in report["cases"] for _ in ("original", "control", "candidate") for s in c["steps"]]):
        tag = f"{case}/{image}/{step_name}"
        outside = verify_wire(rec, case, step_name, idl)
        tx = Transaction.from_bytes(base64.b64decode(rec["transaction_base64"]))
        if not all(tx.verify_with_results()):
            fail(f"{tag}: signature verification failed")
        if set(rec["before"]) != set(rec["after"]):
            fail(f"{tag}: before/after key sets differ")
        pool_key = KEYS["pool"]
        pool_before, pool_after = rec["before"][pool_key], rec["after"][pool_key]
        if exp.get("pool_fees") is not None and pool_fees(pool_after) != exp["pool_fees"]:
            fail(f"{tag}: pool_fees {pool_fees(pool_after)} != {exp['pool_fees']}")
        if exp.get("pool_vq") is not None and pool_vq(pool_after) != exp["pool_vq"]:
            fail(f"{tag}: pool_vq {pool_vq(pool_after)} != {exp['pool_vq']}")
        if exp["error"] is None:
            if rec["error"] is not None:
                fail(f"{tag}: unexpected error {rec['error']}")
        else:
            if rec["error"] is None or exp["error"] not in rec["error"]:
                fail(f"{tag}: expected error {exp['error']}, got {rec['error']}")
        if len(rec["events"]) != exp["events"]:
            fail(f"{tag}: events {len(rec['events'])} != {exp['events']}")
        payer_key = rec["payer_key"]
        need(lam_delta(rec["before"][payer_key], rec["after"][payer_key]) == -exp["payer"], "signed payer delta")
        for name, want in exp.get("deltas", {}).items():
            key = key_for(name, outside)
            need(tok_delta(rec["before"][key], rec["after"][key]) == want, "expected token delta: " + name)
        for name, want in exp.get("lam_deltas", {}).items():
            key = key_for(name, outside)
            need(lam_delta(rec["before"][key], rec["after"][key]) == want, "expected lamport delta: " + name)
        if exp.get("rollback"):
            for k in rec["before"]:
                if k == payer_key:
                    continue
                if rec["before"][k] != rec["after"][k]:
                    fail(f"{tag}: rollback violated for {k}")
        if exp.get("site_fragment"):
            blob = "\n".join(rec["logs"])
            if exp["site_fragment"] not in blob:
                fail(f"{tag}: site fragment {exp['site_fragment']} not in logs")
        if exp.get("event") is not None:
            got = decode_event(step_name, rec)
            if got is None:
                fail(f"{tag}: event decode failed")
            for fkey, want in exp["event"].items():
                if got.get(fkey) != want:
                    fail(f"{tag}: event {fkey} {got.get(fkey)} != {want}")
        if step_name == "set" and exp.get("config") is not None:
            cfg_key = KEYS["global_config"]
            before_cfg = bytes.fromhex(rec["before"][cfg_key]["data_hex"])
            after_cfg = bytes.fromhex(rec["after"][cfg_key]["data_hex"])
            wl = bytes(Pubkey.from_string(exp["config"]["wl"]))
            res = [bytes(Pubkey.from_string(x)) for x in exp["config"]["res"]]
            if after_cfg[353:385] != wl:
                fail(f"{tag}: config whitelist_pda mismatch")
            if after_cfg[385:417] != res[0]:
                fail(f"{tag}: config reserved_fee_recipient mismatch")
            if after_cfg[418:642] != b"".join(res[1:8]):
                fail(f"{tag}: config reserved_fee_recipients mismatch")
            if after_cfg[417] != before_cfg[417]:
                fail(f"{tag}: config byte 417 changed")
            masked_before = bytearray(before_cfg)
            masked_after = bytearray(after_cfg)
            for lo, hi in ((353, 385), (385, 417), (418, 642)):
                masked_before[lo:hi] = bytes(hi - lo)
                masked_after[lo:hi] = bytes(hi - lo)
            if bytes(masked_before) != bytes(masked_after):
                fail(f"{tag}: config changed outside the setter ranges")
            need({key: value for key, value in rec["before"][cfg_key].items() if key != "data_hex"} == {key: value for key, value in rec["after"][cfg_key].items() if key != "data_hex"}, "setter config metadata unchanged")
            for key in WATCH:
                if key not in (cfg_key, payer_key):
                    need(rec["before"][key] == rec["after"][key], "setter other watched state unchanged")
            if step_name == "set":
                got = decode_event(step_name, rec)
                if got is None or got["len"] != 272:
                    fail(f"{tag}: set event len != 272")
        site = cases_by_label[case]["error_sites"][image][
            [s["name"] for s in cases_by_label[case]["steps"]].index(step_name)]
        if site is not None and site not in rec["logs"]:
            fail(f"{tag}: recorded site line not in logs")
        cfg_key = KEYS["global_config"]
        surface = {"step": step_name, "error": rec["error"],
                   "events": len(rec["events"]),
                   "pool_fees": pool_fees(pool_after),
                   "pool_vq": pool_vq(pool_after),
                   "config": rec["after"][cfg_key]["data_hex"] if cfg_key else None,
                   "payer": lam_delta(rec["before"][payer_key], rec["after"][payer_key]),
                   "deltas": {k: tok_delta(rec["before"][k], rec["after"][k]) for k in rec["before"]},
                   "lam_deltas": {k: lam_delta(rec["before"][k], rec["after"][k]) for k in rec["before"]}}
        surfaces.setdefault(case, {}).setdefault(image, []).append(surface)
    for case, by_image in surfaces.items():
        base = by_image["original"]
        for image in ("control", "candidate"):
            if by_image[image] != base:
                fail(f"{case}: {image} observed surface differs from original")
    print("PASS: 34 cases, 162 receipts, 17 parts, 3 images agree "
          "(signatures, deltas, events, error codes/sites, rollback)")


if __name__ == "__main__":
    main()
