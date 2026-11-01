#!/usr/bin/env python3
"""Independent re-verification for amm-close-volume-accumulator-chains-20261029.

Checks, from the packet files alone (plus the three program images):
- MANIFEST.json lists every packet file with a matching sha256.
- runtime/report.json.gz: 16 cases, 102 receipts, 11 parts (10x10 + 2),
  part sha256/byte counts match the part files.
- Every receipt transaction parses (solders) and all signatures verify.
- Every receipt's recorded before/after snapshots reproduce the
  report's expected values: fee-payer lamport deltas (per step, so
  harness airdrop accumulation across setups cannot matter), the
  user accumulator state (parsed fields or None when closed), the
  incentive vault and user ATA token amounts, and the decoded event
  fields (close/init/sync/claim layouts documented in README).
- Failure steps roll back every watched account except the fee payer
  (fee 5,000) and carry the expected error code plus the recorded
  per-image site line ("caused by account") in their logs. Site lines
  are checked per image, never compared across images, because
  original and rebuilt sources differ in line numbers.
- The observed surface of every case (step, error, event count,
  payer deltas, accumulator state, vault/user amounts, event fields,
  and snapshots with fee-payer lamports zeroed) is identical across
  the original, control, and candidate images.
- The three program images hash to the values recorded in the report.

Usage: python3 verify.py   (run from this packet directory)
"""
if not __debug__:
    raise SystemExit('Run without -O')
import argparse
import base64
import copy
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.instruction import AccountMeta, Instruction
from solders.message import Message

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
IMAGE_RELATIVE = {
    "original": "evidence/original/pump_amm/deployed.so",
    "control": "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz",
    "candidate": "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz",
}
IMAGE_SHA = {
    "original": "6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7",
    "control": "7a300434dced61413bde10788594b427d5649563e0223efcf09e6b214aff7ad3",
    "candidate": "d17a657baf5cc19736a924c41e75424604411ddbe9f6e72cddf41ab72a695007",
}
TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
MINT = Pubkey.from_bytes(bytes([226]) * 32)
ATA = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
PROGRAM = Pubkey.from_string("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA")
G, _ = Pubkey.find_program_address([b"global_volume_accumulator"], PROGRAM)
GA = Pubkey.find_program_address([bytes(G), bytes(TOKEN), bytes(MINT)], ATA)[0]


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tok_amount(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) < 72:
        return None
    return struct.unpack_from("<Q", raw, 64)[0]


def parse_uva(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) < 90:
        return {"lamports": entry["lamports"], "len": len(raw)}
    v = struct.unpack_from("<BQQQqBQQ", raw, 40)
    return {"lamports": entry["lamports"], "needs": v[0], "unc": v[1],
            "claimed": v[2], "vol": v[3], "last": v[4], "has": v[5],
            "cb": v[6], "cbcl": v[7]}


def lam_delta(before, after):
    b = before["lamports"] if before else 0
    a = after["lamports"] if after else 0
    return a - b


def u64(raw, off):
    return struct.unpack_from("<Q", raw, off)[0]


def i64(raw, off):
    return struct.unpack_from("<q", raw, off)[0]


def ev_data(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    return base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())


def decode_event(kind, rec):
    raw = ev_data(rec["logs"])
    if raw is None:
        return None
    if kind == "close":
        return {"disc": raw[:8].hex(), "user": raw[8:40].hex(), "ts": i64(raw, 40),
                "unc": u64(raw, 48), "claimed": u64(raw, 56), "vol": u64(raw, 64),
                "last": i64(raw, 72), "len": len(raw)}
    if kind == "init":
        return {"disc": raw[:8].hex(), "payer": raw[8:40].hex(), "user": raw[40:72].hex(),
                "ts": i64(raw, 72), "len": len(raw)}
    if kind == "sync":
        return {"disc": raw[:8].hex(), "user": raw[8:40].hex(), "before": u64(raw, 40),
                "after": u64(raw, 48), "ts": i64(raw, 56), "len": len(raw)}
    if kind == "claim":
        return {"disc": raw[:8].hex(), "user": raw[8:40].hex(), "mint": raw[40:72].hex(),
                "amount": u64(raw, 72), "ts": i64(raw, 80), "claimed": u64(raw, 88),
                "vol": u64(raw, 96), "len": len(raw)}
    return None


def strict_bindings(report, receipts, repo):
    """Join retained declarations to reviewed fixture data, wires and state chains."""
    def need(value, message):
        if not value:
            fail(message)
    raw = (ROOT / 'fixture-bindings.json').read_bytes()
    need(sha(raw) == '22ceb729bb373e4a5c57c416856368e9026b118fe1af702f7f2ef9c28b7046e8',
         'reviewed fixture bindings changed')
    b = json.loads(raw)
    need(sha((ROOT / 'producer.py').read_bytes()) == b['producer_sha256'] ==
         '78d8b62965be5e732a3126f97d32613715dfcbedf107c74f3281b5341aa4ff02', 'producer source pin')
    for name, expected in b['reference_data'].items():
        need(sha((repo / name).read_bytes()) == expected, 'reviewed reference data: ' + name)
    need(report['images'] == report['input_sha256'] == IMAGE_SHA,
         'authenticated historical image declarations')
    need([(x['file'], x['count']) for x in report['parts']] ==
         [(f'runtime/raw-transactions-part{i:02d}.jsonl.gz', 10 if i < 11 else 2) for i in range(1, 12)],
         'exact part membership')
    need([dict(label=x['label'], family=x['family'], steps=x['steps']) for x in report['cases']] ==
         [dict(label=x['label'], family=x['family'], steps=x['expect']) for x in b['cases']],
         'exact source-owned case expectations')
    expected_order = [(c['label'], image, s['kind']) for c in b['cases']
                      for image in IMAGE_SHA for s in c['steps']]
    need([(r['case'], r['image'], r['step']) for r in receipts] == expected_order,
         'exact case/image/step membership and every receipt consumed')
    roles = b['roles']; user, payer, uva = (roles[x] for x in ['user', 'payer', 'uva'])
    def uva_state(fields):
        if fields is None:
            return None
        data = bytes.fromhex(b['uva_discriminator']) + bytes(Pubkey.from_string(user))
        data += struct.pack('<BQQQqBQQ', *(fields[k] for k in ['needs','unc','claimed','vol','last','has','cb','cbcl']))
        return dict(lamports=fields['lamports'], owner=roles['program'], data_hex=data.ljust(137, b'\0').hex())
    index = 0
    for case in b['cases']:
        seed = dict(zip(['needs','unc','claimed','vol','last','has','cb','cbcl'], case['seed']), lamports=10**9)
        initial = dict(b['initial'], **{uva: uva_state(seed)})
        for image in IMAGE_SHA:
            previous = None
            for step, exp in zip(case['steps'], case['expect']):
                rec = receipts[index]; index += 1
                tag = f"{case['label']}/{image}/{step['kind']}"
                need(set(rec['before']) == set(rec['after']) == set(initial), tag + ': watched account membership')
                if previous is None:
                    for key, expected in initial.items():
                        got = rec['before'][key]
                        if key in [user, payer]:
                            need(got is not None and {k:v for k,v in got.items() if k != 'lamports'} == expected,
                                 tag + ': source-owned payer account data/owner')
                        else:
                            need(got == expected, tag + ': source-owned initial prestate')
                else:
                    need(rec['before'] == previous, tag + ': chained before/after continuity')
                tx = Transaction.from_bytes(base64.b64decode(rec['transaction_base64'], validate=True))
                instruction = Instruction(PROGRAM, bytes.fromhex(step['data_hex']),
                    [AccountMeta(Pubkey.from_string(m['key']), m['signer'], m['writable']) for m in step['accounts']])
                expected_message = Message.new_with_blockhash([instruction], Pubkey.from_string(step['payer']), tx.message.recent_blockhash)
                need(bytes(tx.message) == bytes(expected_message), tag + ': signed instruction/accounts/privileges')
                events = [line for line in rec['logs'] if line.startswith('Program data: ')]
                need(rec['events'] == events, tag + ': event/log payload join')
                site = next((line for line in rec['logs'] if 'thrown in' in line or 'caused by account' in line), None)
                need(rec['site'] == site, tag + ': recorded error-site/log join')
                if exp['error'] is not None:
                    code = exp['error']
                    need(rec['error'] == f'TransactionErrorInstructionError((0, Tagged(InstructionErrorCustom({code}))))',
                         tag + ': exact instruction error')
                    account = 'user' if code == '3010' else 'user_volume_accumulator'
                    need(site is not None and f'caused by account: {account}. ' in site
                         and f'Error Number: {code}.' in site, tag + ': exact caused-by gate')
                after = copy.deepcopy(rec['before'])
                after[user]['lamports'] += exp['dUSER']; after[payer]['lamports'] += exp['dPAYER']
                after[uva] = uva_state(exp['uva'])
                for role, field in [('vault','vault'), ('user_ata','ua')]:
                    if exp.get(field) is not None:
                        entry = after[roles[role]]
                        data = bytearray.fromhex(entry['data_hex'])
                        struct.pack_into('<Q', data, 64, exp[field]); entry['data_hex'] = data.hex()
                need(rec['after'] == after, tag + ': source-owned full state/delta transition')
                previous = rec['after']
    need(index == len(receipts) == 102, 'unconsumed receipts')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT.parents[1])
    repo = parser.parse_args().repo_root.resolve()
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    names = [entry['path'] for entry in manifest['files']]
    actual = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and p.relative_to(ROOT).as_posix() != 'MANIFEST.json']
    if (len(names) != len(set(names)) or set(names) != set(actual)
            or any(p.is_symlink() for p in ROOT.rglob('*'))
            or any(Path(n).is_absolute() or '..' in Path(n).parts or '\\' in n for n in names)):
        fail('exact regular packet manifest membership')
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if not path.exists():
            fail(f"missing file {entry['path']}")
        if sha(path.read_bytes()) != entry["sha256"] or len(path.read_bytes()) != entry['bytes']:
            fail(f"sha mismatch {entry['path']}")
    with gzip.open(ROOT / "runtime" / "report.json.gz", "rt", encoding="utf-8") as fh:
        report = json.load(fh)
    if report["case_count"] != 16 or report["receipt_count"] != 102:
        fail(f"counts {report['case_count']} cases / {report['receipt_count']} receipts")
    if report["counts"] != {"cases": 16, "receipts": 102, "parts": 11}:
        fail(f"counts block {report['counts']}")
    if report["mismatches"] != []:
        fail(f"mismatches recorded: {report['mismatches']}")
    for name, relative in IMAGE_RELATIVE.items():
        path = repo / relative
        data = path.read_bytes()
        if path.suffix == '.gz':
            data = gzip.decompress(data)
        if sha(data) != IMAGE_SHA[name] or report['images'][name] != IMAGE_SHA[name]:
            fail(f"image hash mismatch {name}")
    receipts = []
    for part in report["parts"]:
        path = ROOT / part["file"]
        data = path.read_bytes()
        if sha(data) != part["sha256"] or len(data) != part["bytes"]:
            fail(f"part hash/size mismatch {part['file']}")
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            chunk = [json.loads(line) for line in fh if line.strip()]
        if len(chunk) != part["count"]:
            fail(f"part count mismatch {part['file']}")
        receipts.extend(chunk)
    if len(receipts) != 102:
        fail(f"receipt total {len(receipts)}")
    strict_bindings(report, receipts, repo)
    # USER pubkey: the close event's user field, identical in every receipt.
    user_hex = None
    for rec in receipts:
        ev = decode_event("close", rec) if rec["step"] == "close" else None
        if ev is not None:
            user_hex = ev["user"]
            break
    if user_hex is None:
        fail("no close event found to recover USER")
    USER = Pubkey.from_bytes(bytes.fromhex(user_hex))
    U, _ = Pubkey.find_program_address([b"user_volume_accumulator", bytes(USER)], PROGRAM)
    UA, _ = Pubkey.find_program_address([bytes(USER), bytes(TOKEN), bytes(MINT)], ATA)
    PAYER_KEY = None
    for rec in receipts:
        ev = decode_event("init", rec) if rec["step"] == "init" else None
        if ev is not None and rec["case"] == "c-close-init-by-payer":
            PAYER_KEY = Pubkey.from_bytes(bytes.fromhex(ev["payer"]))
            break
    if PAYER_KEY is None:
        fail("no init-by-payer event found to recover PAYER")
    by_case = {}
    for rec in receipts:
        by_case.setdefault(rec["case"], {}).setdefault(rec["image"], []).append(rec)
    for case in report["cases"]:
        label = case["label"]
        expect = case["steps"]
        for image in ("original", "control", "candidate"):
            recs = by_case.get(label, {}).get(image)
            if recs is None or len(recs) != len(expect):
                fail(f"{label}/{image}: {0 if recs is None else len(recs)} receipts, expected {len(expect)}")
            for rec, exp in zip(recs, expect):
                tag = f"{label}/{image}/{rec['step']}"
                tx = Transaction.from_bytes(base64.b64decode(rec["transaction_base64"]))
                if not all(tx.verify_with_results()):
                    fail(f"{tag}: signature verification failed")
                if exp["error"] is None:
                    if rec["error"] is not None:
                        fail(f"{tag}: unexpected error {rec['error']}")
                else:
                    if rec["error"] is None or exp["error"] not in rec["error"]:
                        fail(f"{tag}: expected error {exp['error']}, got {rec['error']}")
                if len(rec["events"]) != exp["events"]:
                    fail(f"{tag}: events {len(rec['events'])} != {exp['events']}")
                d_user = lam_delta(rec["before"][str(USER)], rec["after"][str(USER)])
                d_payer = lam_delta(rec["before"][str(PAYER_KEY)], rec["after"][str(PAYER_KEY)])
                if d_user != exp["dUSER"]:
                    fail(f"{tag}: dUSER {d_user} != {exp['dUSER']}")
                if d_payer != exp["dPAYER"]:
                    fail(f"{tag}: dPAYER {d_payer} != {exp['dPAYER']}")
                if parse_uva(rec["after"][str(U)]) != exp["uva"]:
                    fail(f"{tag}: uva {parse_uva(rec['after'][str(U)])} != {exp['uva']}")
                if exp.get("vault") is not None and tok_amount(rec["after"][str(GA)]) != exp["vault"]:
                    fail(f"{tag}: vault {tok_amount(rec['after'][str(GA)])} != {exp['vault']}")
                if exp.get("ua") is not None and tok_amount(rec["after"][str(UA)]) != exp["ua"]:
                    fail(f"{tag}: ua {tok_amount(rec['after'][str(UA)])} != {exp['ua']}")
                if exp.get("rollback"):
                    fee_key = str(PAYER_KEY) if rec["step"] in ("close_other", "close_unsigned") else str(USER)
                    for k, b in rec["before"].items():
                        if k == fee_key:
                            continue
                        if rec["after"][k] != b:
                            fail(f"{tag}: rollback violated for {k}")
                if exp.get("event") is not None:
                    got = decode_event(rec["step"], rec)
                    if got is None:
                        fail(f"{tag}: event decode failed")
                    for fkey, want in exp["event"].items():
                        if got.get(fkey) != want:
                            fail(f"{tag}: event {fkey} {got.get(fkey)} != {want}")
                if exp.get("site_fragment"):
                    blob = "\n".join(rec["logs"])
                    if exp["site_fragment"] not in blob:
                        fail(f"{tag}: site fragment {exp['site_fragment']} not in logs")
        # 3-image surface equality (snapshots with fee-payer lamports zeroed,
        # since absolute balances accumulate airdrops across setups).
        def surface(recs):
            out = []
            for rec in recs:
                def strip(snap):
                    d = dict(snap)
                    for k in (str(USER), str(PAYER_KEY)):
                        if d.get(k) is not None:
                            d[k] = dict(d[k])
                            d[k]["lamports"] = 0
                    return d
                out.append({"step": rec["step"], "error": rec["error"],
                            "events": len(rec["events"]),
                            "before": strip(rec["before"]), "after": strip(rec["after"])})
            return out
        base = surface(by_case[label]["original"])
        for image in ("control", "candidate"):
            if surface(by_case[label][image]) != base:
                fail(f"{label}: {image} surface differs from original")
        # per-image recorded site lines must appear in that image's logs
        for image in ("original", "control", "candidate"):
            sites = case["error_sites"][image]
            recs = by_case[label][image]
            if len(sites) != len(recs):
                fail(f"{label}/{image}: site count mismatch")
            for rec, site in zip(recs, sites):
                if site is not None and site not in "\n".join(rec["logs"]):
                    fail(f"{label}/{image}: recorded site line not in logs: {site}")
    print("PASS: 16 cases, 102 receipts, 11 parts, 3 images agree (signatures, deltas, events, error codes/sites, rollback)")


if __name__ == "__main__":
    main()
