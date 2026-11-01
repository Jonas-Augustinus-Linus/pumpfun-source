"""Verify the retained trade-mode-gate receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (original image, harness scripts, fixture) hash to the
  recorded values; control/candidate are the in-repo #424/#427 artifacts;
- 49 cases x 3 images = 147 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- family A (trade_v2): the pool in each before snapshot has the
  recorded mayhem byte (243) and cashback byte (244); success cases
  move exactly the expected token deltas on all five watched
  accounts, fund the user volume accumulator with exactly
  1,844,400 lamports (137 bytes, payer key at [8:40]), charge
  the payer 1,849,400 lamports, emit exactly 1 event whose
  fixed-offset fields match the recorded values, and leave the
  pool at exactly the recorded post-trade (vq, protocol_fees,
  creator_fees); error cases fail with exactly the recorded
  error code, leave all watched token deltas at 0, charge the
  payer 5,000 only, leave the volume account empty, emit 0
  events, leave the pool bytes unchanged, and carry the
  recorded site line in their logs;
- family B (multi_hop_swap): success cases move exactly the
  expected 9-account deltas, fund the volume accumulator the
  same way, charge 1,849,400, and emit exactly 3 events;
  error cases fail with exactly the recorded error code,
  leave all watched token deltas at 0, charge 5,000 only,
  leave the volume account empty, emit exactly the recorded
  number of prior-hop events (0/1/2), and carry the recorded
  site line in their logs. For DIVERGENT cases (multi-hop
  cashback cells where the original and the rebuilt images
  differ) each image is checked against its OWN recorded
  expectation, not against the other images;
- family C (legacy sell): success cases move exactly the
  expected 7-account deltas, emit exactly 1 SellEvent whose
  fixed-offset fields match (quote @64, lp_fee @80,
  protocol_fee @96 (gross), user_out @112, creator_bps @344,
  creator_fee @352, cashback_bps @360, cashback @368,
  buyback_fee @384), and charge the recorded payer amount;
  cashback cases additionally move the accumulator ATA by
  +548 (pre-created) or land it at 548 tokens / 2,039,828
  lamports (fresh), and set the accumulator's cashback_earned
  (@74..82) to 548; error cases fail with exactly the recorded
  error code, roll back everything except the payer fee,
  emit 0 events, and carry the recorded site line;
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case EXCEPT the recorded
  divergent multi-hop cashback cells.
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
WS = Path.home() / "workspace/slop-verify"
IMAGES = ("original", "control", "candidate")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def amount_at(data_hex, offset=64):
    return struct.unpack_from("<Q", bytes.fromhex(data_hex), offset)[0]


def delta_of(before, after, key):
    if key is None:
        return None
    b, a = before.get(key), after.get(key)
    if b is None or a is None:
        return None
    return amount_at(a["data_hex"]) - amount_at(b["data_hex"])


def pool_flags(data_hex):
    d = bytes.fromhex(data_hex)
    return d[243], d[244]


def pool_state(data_hex):
    d = bytes.fromhex(data_hex)
    return (int.from_bytes(d[245:261], "little", signed=True),
            struct.unpack_from("<Q", d, 271)[0],
            struct.unpack_from("<Q", d, 279)[0])


def v2_event_fields(ix_name, logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    assert len(lines) == 1, lines
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    if ix_name == "buy_v2":
        offs = (64, 72, 80, 88, 96, 104, 112)
    elif ix_name == "sell_v2":
        offs = (64, 72, 80, 88, 96)
    else:
        offs = (16, 24, 64, 72, 80, 88, 96, 104, 112)
    return tuple(struct.unpack_from("<Q", raw, off)[0] for off in offs)


def ls_event_fields(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    assert len(lines) == 1, lines
    raw = base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())
    assert len(raw) == 449, len(raw)
    return {
        "quote": struct.unpack_from("<Q", raw, 64)[0],
        "lp_fee": struct.unpack_from("<Q", raw, 80)[0],
        "protocol_fee": struct.unpack_from("<Q", raw, 96)[0],
        "user_out": struct.unpack_from("<Q", raw, 112)[0],
        "creator_bps": struct.unpack_from("<Q", raw, 344)[0],
        "creator_fee": struct.unpack_from("<Q", raw, 352)[0],
        "cashback_bps": struct.unpack_from("<Q", raw, 360)[0],
        "cashback": struct.unpack_from("<Q", raw, 368)[0],
        "buyback_fee": struct.unpack_from("<Q", raw, 384)[0],
    }


def vol_state(snapshot, key):
    row = snapshot.get(key)
    if row is None:
        return None
    return (row["lamports"], len(bytes.fromhex(row["data_hex"])),
            bytes.fromhex(row["data_hex"])[8:40].hex() if len(bytes.fromhex(row["data_hex"])) >= 40 else "")


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    on_disk = {}
    for p in sorted(HERE.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.json":
            on_disk[str(p.relative_to(HERE))] = sha(p.read_bytes())
    assert set(on_disk) == set(manifest["files"]), \
        (set(on_disk) ^ set(manifest["files"]))
    for name, digest in manifest["files"].items():
        assert on_disk[name] == digest, name
    for name, digest in manifest["repository_inputs"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    report = json.loads(gzip.decompress((HERE / "runtime/report.json.gz").read_bytes()))
    cases = report["cases"]
    assert report["case_count"] == len(cases) == 49, report["case_count"]
    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (HERE / part["path"]).read_bytes()
        assert len(data) < 25 * 1024 * 1024, part["path"]
        assert sha(data) == part["sha256"], part["path"]
        chunk = [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l.strip()]
        assert len(chunk) == part["receipts"], part["path"]
        receipts.extend(chunk)
    assert len(receipts) == 147, len(receipts)

    divergent = set()
    for ci, row in enumerate(cases):
        case = row["case"]
        label = case["label"]
        by_image = case.get("expected_by_image")
        if by_image and len({json.dumps(v, sort_keys=True) for v in by_image.values()}) > 1:
            divergent.add(label)
        for ji, image in enumerate(IMAGES):
            r = receipts[ci * 3 + ji]
            ctx = r["context"]
            assert ctx["index"] == ci and ctx["image"] == image and ctx["label"] == label, ctx
            raw = base64.b64decode(r["transaction_base64"])
            assert sha(raw) == r["transaction_sha256"], (label, image)
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == 1, (label, image, checks)
            assert [str(s) for s in tx.signatures] == r["signatures"], (label, image)
            before, after = r["before"], r["after"]
            roles = r["roles"]
            payer_key = roles["fee_payer"]
            payer_delta = after[payer_key]["lamports"] - before[payer_key]["lamports"]
            logs = r["metadata"]["logs"]
            logtext = "\n".join(logs)
            events = [l for l in logs if l.startswith("Program data: ")]
            assert len(events) == r["observed"].get("event_count", len(events)), (label, image)

            if case["instruction"] in ("buy_v2", "sell_v2", "buy_exact_quote_in_v2"):
                pool_key = roles["pool"]
                assert pool_flags(before[pool_key]["data_hex"]) == (case["mayhem"], case["cashback"]), \
                    (label, image, "before pool flags")
                exp = case["expected"]
                vol = after.get(roles["volume"])
                vol_empty = vol is None or (vol["lamports"] == 0 and vol["data_hex"] == "")
                if exp["kind"] == "ok":
                    assert r["error"] is None, (label, image, r["error"])
                    deltas = {name: delta_of(before, after, roles[k]) for name, k in
                              (("userbase", "userbase"), ("userquote", "userquote"),
                               ("vaultbase", "vaultbase"), ("vaultquote", "vaultquote"),
                               ("buyback", "buyback"))}
                    assert deltas == exp["deltas"], (label, image, deltas, exp["deltas"])
                    assert v2_event_fields(case["instruction"], logs) == tuple(exp["event"]), \
                        (label, image)
                    assert pool_state(after[pool_key]["data_hex"]) == tuple(exp["pool_after"]), \
                        (label, image)
                    assert pool_flags(after[pool_key]["data_hex"]) == (case["mayhem"], case["cashback"]), \
                        (label, image, "after pool flags")
                    assert payer_delta == -1849400, (label, image, payer_delta)
                    vs = vol_state(after, roles["volume"])
                    assert vs is not None and vs[0] == 1844400 and vs[1] == 137, (label, image, vs)
                    assert vs[2] == bytes(Pubkey.from_string(payer_key)).hex(), (label, image, "volume user")
                    assert len(events) == 1, (label, image)
                else:
                    assert r["error"] is not None and str(exp["code"]) in r["error"], \
                        (label, image, r["error"])
                    assert exp["fragment"] in logtext, (label, image)
                    deltas = {name: delta_of(before, after, roles[k]) for name, k in
                              (("userbase", "userbase"), ("userquote", "userquote"),
                               ("vaultbase", "vaultbase"), ("vaultquote", "vaultquote"),
                               ("buyback", "buyback"))}
                    assert deltas == {"userbase": 0, "userquote": 0, "vaultbase": 0,
                                      "vaultquote": 0, "buyback": 0}, (label, image, deltas)
                    assert before[pool_key] == after[pool_key], (label, image, "pool changed")
                    assert payer_delta == -5000, (label, image, payer_delta)
                    assert vol_empty, (label, image, "volume funded on error")
                    assert len(events) == 0, (label, image)
                    site = row.get("error_sites", {}).get(image)
                    assert site and site in logtext, (label, image, "site not in logs")
            elif case["instruction"] == "multi_hop_swap":
                exp = by_image[image]
                vol = after.get(roles["volume"])
                vol_empty = vol is None or (vol["lamports"] == 0 and vol["data_hex"] == "")
                if exp["kind"] == "ok":
                    assert r["error"] is None, (label, image, r["error"])
                    deltas = {name: delta_of(before, after, roles[k]) for name, k in
                              (("userquote", "userquote"), ("u3", "u3"), ("buyback", "buyback"),
                               ("vb1", "vb1"), ("vq1", "vq1"), ("vb2", "vb2"), ("vq2", "vq2"),
                               ("vb3", "vb3"), ("vq3", "vq3"))}
                    assert deltas == exp["deltas"], (label, image, deltas, exp["deltas"])
                    assert payer_delta == -1849400, (label, image, payer_delta)
                    vs = vol_state(after, roles["volume"])
                    assert vs is not None and vs[0] == 1844400 and vs[1] == 137, (label, image, vs)
                    assert vs[2] == bytes(Pubkey.from_string(payer_key)).hex(), (label, image, "volume user")
                    assert len(events) == 3, (label, image)
                else:
                    assert r["error"] is not None and str(exp["code"]) in r["error"], \
                        (label, image, r["error"])
                    assert exp["fragment"] in logtext, (label, image)
                    deltas = {name: delta_of(before, after, roles[k]) for name, k in
                              (("userquote", "userquote"), ("u3", "u3"), ("buyback", "buyback"),
                               ("vb1", "vb1"), ("vq1", "vq1"), ("vb2", "vb2"), ("vq2", "vq2"),
                               ("vb3", "vb3"), ("vq3", "vq3"))}
                    assert all(v == 0 for v in deltas.values()), (label, image, deltas)
                    assert payer_delta == -5000, (label, image, payer_delta)
                    assert vol_empty, (label, image, "volume funded on error")
                    assert len(events) == exp["events"], (label, image, len(events), exp["events"])
                    assert all(before[k] == after[k] for k in before if k != payer_key), \
                        (label, image, "rollback")
                    site = row.get("error_sites", {}).get(image)
                    assert site and site in logtext, (label, image, "site not in logs")
            elif case["instruction"] == "sell":
                exp = case["expected"]
                pool_key = roles.get("pool")
                if exp["kind"] == "ok":
                    assert r["error"] is None, (label, image, r["error"])
                    got = tuple(delta_of(before, after, roles[k]) for k in
                                ("userbase", "userquote", "vaultbase", "vaultquote",
                                 "protocol_ata", "creator_ata", "buyback"))
                    assert list(got) == exp["deltas"], (label, image, got, exp["deltas"])
                    assert ls_event_fields(logs) == exp["event"], (label, image)
                    assert payer_delta == exp["payer"], (label, image, payer_delta, exp["payer"])
                    assert len(events) == 1, (label, image)
                    if "cashback" in label and label != "ls-cashback-std-remaining":
                        uva_after = after.get(roles["uvata"])
                        assert uva_after is not None, (label, image, "uvata missing")
                        vd = bytes.fromhex(after[roles["volume"]]["data_hex"])
                        assert len(vd) == 137, (label, image, "volume len")
                        assert vd[8:40] == bytes(Pubkey.from_string(payer_key)), (label, image, "volume user")
                        assert struct.unpack_from("<Q", vd, 74)[0] == 548, (label, image, "earned")
                        if label == "ls-cashback-present":
                            assert delta_of(before, after, roles["uvata"]) == 548, (label, image)
                            assert uva_after["lamports"] - before[roles["uvata"]]["lamports"] == 548, \
                                (label, image)
                            assert after[roles["volume"]]["lamports"] == 10**9, (label, image)
                        else:
                            assert amount_at(uva_after["data_hex"]) == 548, (label, image)
                            assert uva_after["lamports"] == 2039828, (label, image)
                            assert after[roles["volume"]]["lamports"] == 1844400, (label, image)
                else:
                    assert r["error"] is not None and str(exp["code"]) in r["error"], \
                        (label, image, r["error"])
                    assert exp["fragment"] in logtext, (label, image)
                    assert payer_delta == -5000, (label, image, payer_delta)
                    assert all(before[k] == after[k] for k in before if k != payer_key), \
                        (label, image, "rollback")
                    assert len(events) == 0, (label, image)
                    site = row.get("error_sites", {}).get(image)
                    assert site and site in logtext, (label, image, "site not in logs")
            else:
                raise AssertionError(("unknown instruction", case["instruction"]))
        # cross-image agreement except divergent cells
        if label not in divergent:
            obs = [receipts[ci * 3 + ji]["observed"] for ji in range(3)]
            assert obs[0] == obs[1] == obs[2], (label, "images disagree", obs)
    assert divergent == set(report["divergent_cases"]), (divergent, report["divergent_cases"])
    print(f"verify PASS: {len(cases)} cases x 3 images = {len(receipts)} receipts, all checks passed")
    print(f"divergent cases (original vs rebuilt, pinned per image): {sorted(divergent)}")


if __name__ == "__main__":
    main()
