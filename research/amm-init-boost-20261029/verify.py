"""Verify the retained init_boost receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, IDL, saved migration
  transactions) hash to the recorded values;
- 36 cases x 3 images = 108 receipts, ordered, with contexts matching
  the report, stored as 11 parts (10 x 10 + 8), each under 25MB;
- every transaction verifies (all signatures valid; 2 signature fields
  only for direct-separate-payer, 1 everywhere else);
- all three images agree on every case (identical error and observed
  values), and the recorded error sites match the receipts' logs
  (including "caused by account" sites; MissingAccount and
  IncorrectProgramId have no such line, so their recorded site is
  None);
- direct success cases: a missing vault is created at exactly
  2,039,280 lamports with mint == pool quote, owner == the
  boost_vault PDA for the pool, amount 0, and the creator pays
  exactly 2,039,280 + 5,000 per signature; a pre-existing vault is
  byte-identical afterwards and only the fee is charged; with a
  separate fee payer the creator pays only the 2,039,280 rent and
  the outsider pays 5,000 per signature; pool, vaultbase and
  vaultquote data are byte-identical and no event line is emitted;
- direct error cases: fail with the expected code and log fragment,
  roll back every account except the fee payer's 5,000-per-signature
  fee, create no vault, and emit no event;
- migration cases: the disabled control case defines q, the pool
  quote balance the migration establishes (84,990,359,062 here);
  enabled cases move exactly floor(curvebase * q / 10^15) from the
  pool quote vault into the boost vault (vault lamports =
  2,039,280 + amount, pool virtual_quote_reserves == amount, pool
  quote vault == q - amount) and emit the InitBoostEvent (3 event
  lines), or move nothing (vault 2,039,280 / amount 0, vq 0, quote
  vault == q, 2 event lines) when the amount is 0 or >= q; the
  migration fee payer is charged exactly 2,044,280; the pool base
  vault always receives the full bonding-curve base balance;
- the missing_boost migration shape fails with 6027
  NotEnoughRemainingAccounts, creates no pool, and rolls back
  everything except the 5,000 fee.
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
CONTROL = ROOT / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz"
CANDIDATE = ROOT / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz"
IMAGES = ("original", "control", "candidate")
PROGRAM = Pubkey.from_string("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tok_amount(data_hex):
    return struct.unpack("<Q", bytes.fromhex(data_hex)[64:72])[0]


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
    assert [p["receipts"] for p in parts] == [10] * 10 + [8]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 36
    assert len(receipts) == 108
    assert report["counts"]["vms"] == 108
    assert report["counts"]["transactions"] == 108
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 111
    assert report["mismatches"] == []
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress(CONTROL.read_bytes())),
        "candidate": sha(gzip.decompress(CANDIDATE.read_bytes())),
    }
    for name, digest in report["input_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    q_ref = None
    for index, row in enumerate(report["cases"]):
        case = row["case"]
        kind = case["expected"][0]
        observed_set = set()
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": 0, "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"])
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == rec["signature_fields"]
            assert rec["transaction_sha256"] == sha(raw)
            assert rec["all_signatures_verified"] is True
            assert rec["signatures"] == [str(s) for s in tx.signatures]
            assert rec["error"] == row[image]["error"]
            assert rec["metadata"]["logs"] == row[image]["logs"]
            assert rec["observed"] == row[image]["observed"]
            assert len(rec["metadata"]["events"]) == rec["observed"]["event_count"]
            observed_set.add(json.dumps(rec["observed"], sort_keys=True))
            before, after = rec["before"], rec["after"]
            roles = rec["roles"]
            fee_key = roles["fee_payer"]
            payer_delta = (after[fee_key]["lamports"] if after.get(fee_key) else 0) - \
                          (before[fee_key]["lamports"] if before.get(fee_key) else 0)
            assert payer_delta == rec["payer_delta_lamports"]
            logs = rec["metadata"]["logs"]
            sig = rec["signature_fields"]
            if case["instruction"] == "init_boost":
                pool = before[roles["pool"]]
                pool_after = after[roles["pool"]]
                assert pool_after == pool, "pool changed"
                assert before[roles["vaultbase"]] == after[roles["vaultbase"]]
                assert before[roles["vaultquote"]] == after[roles["vaultquote"]]
                assert rec["observed"]["event_count"] == 0
                vault_before, vault_after = before[roles["vault"]], after[roles["vault"]]
                if kind == "ok-create-vault":
                    assert rec["error"] is None
                    assert vault_before is None
                    assert vault_after is not None
                    assert vault_after["lamports"] == 2039280
                    assert payer_delta == -(2039280 + 5000 * sig)
                    vd = bytes.fromhex(vault_after["data_hex"])
                    assert len(vd) == 165
                    pd = bytes.fromhex(pool["data_hex"])
                    assert vd[0:32] == pd[75:107], "vault mint != pool quote"
                    authority = Pubkey.find_program_address(
                        [b"boost_vault", bytes(Pubkey.from_string(roles["pool"]))], PROGRAM)[0]
                    assert vd[32:64] == bytes(authority), "vault owner != boost PDA"
                    assert tok_amount(vault_after["data_hex"]) == 0
                elif kind == "ok-vault-kept":
                    assert rec["error"] is None
                    assert vault_after == vault_before
                    assert payer_delta == -5000 * sig
                elif kind == "ok-separate":
                    assert rec["error"] is None
                    assert vault_before is None
                    assert vault_after is not None
                    assert vault_after["lamports"] == 2039280
                    assert tok_amount(vault_after["data_hex"]) == 0
                    creator_key = roles["creator"]
                    creator_delta = after[creator_key]["lamports"] - before[creator_key]["lamports"]
                    assert creator_delta == -2039280
                    assert payer_delta == -5000 * sig
                else:
                    _, code, fragment = case["expected"]
                    assert rec["error"] is not None and code in rec["error"]
                    assert fragment in "\n".join(logs)
                    assert payer_delta == -5000 * sig
                    assert all(before[k] == after[k] for k in before if k != fee_key)
                    site = row.get("error_sites", {}).get(image)
                    if code in ("MissingAccount", "IncorrectProgramId"):
                        assert site is None
                    else:
                        assert site is not None and site in logs
                        assert "thrown in" in site or "caused by account" in site
            else:
                pool_after = after[roles["pool"]]
                vault_after = after.get(roles["vault"])
                if kind == "ok-mig":
                    assert rec["error"] is None
                    assert pool_after is not None
                    pd = bytes.fromhex(pool_after["data_hex"])
                    vq = int.from_bytes(pd[245:261], "little", signed=True)
                    assert vq == rec["observed"]["pool_vq_after"]
                    assert before[roles["vault"]] is None
                    assert vault_after is not None
                    vd = bytes.fromhex(vault_after["data_hex"])
                    assert len(vd) == 165
                    assert vd[0:32] == pd[75:107]
                    authority = Pubkey.find_program_address(
                        [b"boost_vault", bytes(Pubkey.from_string(roles["pool"]))], PROGRAM)[0]
                    assert vd[32:64] == bytes(authority)
                    bb = tok_amount(before[roles["curvebase"]]["data_hex"])
                    pb_after = tok_amount(after[roles["poolbase"]]["data_hex"])
                    assert pb_after == bb, "poolbase != curvebase"
                    qa = tok_amount(after[roles["poolquote"]]["data_hex"])
                    va = tok_amount(vault_after["data_hex"])
                    assert qa == rec["observed"]["poolquote_after"]
                    assert va == rec["observed"]["vault_amount_after"]
                    assert payer_delta == -2044280
                    if not case["params"]["boost_enabled"]:
                        assert vq == 0 and va == 0
                        assert vault_after["lamports"] == 2039280
                        assert rec["observed"]["event_count"] == 2
                        if image == "original":
                            q_ref = qa
                    else:
                        assert q_ref is not None
                        amount = (bb * q_ref) // 10**15
                        assert amount == rec["observed"]["amount_formula"]
                        assert q_ref == rec["observed"]["q_ref"]
                        if 0 < amount < q_ref:
                            assert vq == amount and va == amount
                            assert vault_after["lamports"] == 2039280 + amount
                            assert qa == q_ref - amount
                            assert rec["observed"]["event_count"] == 3
                        else:
                            assert vq == 0 and va == 0
                            assert vault_after["lamports"] == 2039280
                            assert qa == q_ref
                            assert rec["observed"]["event_count"] == 2
                else:
                    _, code, fragment = case["expected"]
                    assert rec["error"] is not None and code in rec["error"]
                    assert fragment in "\n".join(logs)
                    assert pool_after is None
                    assert payer_delta == -5000 * sig
                    assert all(before[k] == after[k] for k in before if k != fee_key)
                    site = row.get("error_sites", {}).get(image)
                    assert site is not None and site in logs
        assert len(observed_set) == 1, (case["label"], "images disagree")
    print("verify PASS: 36 cases x 3 images = 108 receipts, all checks passed")


if __name__ == "__main__":
    main()
