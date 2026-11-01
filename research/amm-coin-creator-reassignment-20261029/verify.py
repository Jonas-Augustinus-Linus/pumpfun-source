"""Verify the retained coin-creator reassignment receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs hash to the recorded values;
- 36 cases x 3 images = 108 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- before snapshots: pool owner is the AMM program; pool creator is the
  pool-authority PDA except the noncanonical cases; pool coin_creator
  before is zero for set cases (fixture value for already-set) and the
  fixture value for migrate cases; metadata key is the metadata PDA
  (except set-meta-wrong-pda) owned by the metadata program (except
  set-meta-wrong-owner); bonding-curve key/owner likewise; sharing
  key/owner likewise; pool length 300 except truncated (100) / empty (0);
- success cases set exactly the expected coin_creator (only bytes
  211..243 of the pool change, or nothing for already-set), emit
  exactly the expected event count, and charge the payer exactly
  5,000 lamports;
- error cases fail with the expected code and log fragment, carry the
  expected error site (account/file + error name; line numbers are
  ignored because they differ between images), and roll back every
  account except the payer's 5,000 fee;
- the empty-creators panic case has no error site line;
- all three images agree on every case: error string, pool state
  after, and event logs.
"""
import base64
import gzip
import hashlib
import json
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

sys.path.insert(0, str(ROOT / "scripts"))
import os
os.chdir(ROOT)
from pump_amm_admin_differential import PAYER  # noqa: E402
from pump_amm_liquidity_differential import base as BASE  # noqa: E402
from pump_amm_liquidity_differential import pool as POOLKEY  # noqa: E402
from pump_amm_liquidity_differential import poolraw as POOLRAW  # noqa: E402

PROGRAM = Pubkey.from_string('pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA')
PUMP = Pubkey.from_string('6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P')
META_PROG = Pubkey.from_string('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s')
FEES_PROG = Pubkey.from_string('pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ')
META_PDA, _ = Pubkey.find_program_address([b'metadata', bytes(META_PROG), bytes(BASE)], META_PROG)
BC_PDA, _ = Pubkey.find_program_address([b'bonding-curve', bytes(BASE)], PUMP)
SHARING_PDA, _ = Pubkey.find_program_address([b'sharing-config', bytes(BASE)], FEES_PROG)
POOL_AUTH, _ = Pubkey.find_program_address([b'pool-authority', bytes(BASE)], PUMP)
FIX_CC = bytes(POOLRAW[211:243])
CREATOR0 = bytes([0x11]) * 32
BC_CREATOR = bytes([0x33]) * 32


def sha(data):
    return hashlib.sha256(data).hexdigest()


# (instruction, label, expected) with expected ("ok", cc_hex, events) or
# ("error", err_substr, log_fragment, (site_account, site_error) | None)
EXPECTED = [
    ("set", "set-metaplex-first", ("ok", CREATOR0.hex(), 1)),
    ("set", "set-bonding", ("ok", BC_CREATOR.hex(), 1)),
    ("set", "set-bonding-short", ("ok", BC_CREATOR.hex(), 1)),
    ("set", "set-already-set", ("ok", FIX_CC.hex(), 0)),
    ("set", "set-noncanonical", ("error", "6028", "OnlyCanonicalPumpPoolsCanHaveCoinCreator", ("set_coin_creator.rs", "OnlyCanonicalPumpPoolsCanHaveCoinCreator"))),
    ("set", "set-meta-wrong-pda", ("error", "2006", "ConstraintSeeds", ("metadata", "ConstraintSeeds"))),
    ("set", "set-meta-wrong-owner", ("error", "3007", "AccountOwnedByWrongProgram", ("metadata", "AccountOwnedByWrongProgram"))),
    ("set", "set-bc-wrong-pda", ("error", "2006", "ConstraintSeeds", ("bonding_curve", "ConstraintSeeds"))),
    ("set", "set-bc-wrong-owner", ("error", "3007", "AccountOwnedByWrongProgram", ("bonding_curve", "AccountOwnedByWrongProgram"))),
    ("set", "set-meta-empty", ("error", "BorshIoError", 'BorshIoError("DataTypeMismatch")', ("metadata", "BorshIoError"))),
    ("set", "set-meta-key0", ("error", "BorshIoError", 'BorshIoError("DataTypeMismatch")', ("metadata", "BorshIoError"))),
    ("set", "set-meta-key1", ("error", "BorshIoError", 'BorshIoError("DataTypeMismatch")', ("metadata", "BorshIoError"))),
    ("set", "set-meta-key2", ("error", "BorshIoError", 'BorshIoError("DataTypeMismatch")', ("metadata", "BorshIoError"))),
    ("set", "set-meta-key9", ("error", "BorshIoError", 'BorshIoError("DataTypeMismatch")', ("metadata", "BorshIoError"))),
    ("set", "set-creators-empty", ("error", "ProgramFailedToComplete", "", None)),
    ("set", "set-pool-readonly", ("error", "2000", "ConstraintMut", ("pool", "ConstraintMut"))),
    ("set", "set-pool-disc-flip", ("error", "InvalidAccountData", "Error Number: 17179869184", ("pool", "InvalidAccountData"))),
    ("set", "set-trailing", ("ok", CREATOR0.hex(), 1)),
    ("set", "set-noncanonical-meta-wrong-pda", ("error", "2006", "ConstraintSeeds", ("metadata", "ConstraintSeeds"))),
    ("set", "set-pool-truncated", ("error", "InvalidAccountData", "Error Number: 17179869184", ("pool", "InvalidAccountData"))),
    ("set", "set-pool-empty", ("error", "InvalidAccountData", "Error Number: 17179869184", ("pool", "InvalidAccountData"))),
    ("mig", "mig-ok", ("ok", bytes(SHARING_PDA).hex(), 1)),
    ("mig", "mig-ok-paused", ("ok", bytes(SHARING_PDA).hex(), 1)),
    ("mig", "mig-ok-revoked", ("ok", bytes(SHARING_PDA).hex(), 1)),
    ("mig", "mig-ok-holders", ("ok", bytes(SHARING_PDA).hex(), 1)),
    ("mig", "mig-holder", ("error", "6074", "HolderRewardCreatorImmutable", ("migrate_pool_coin_creator.rs", "HolderRewardCreatorImmutable"))),
    ("mig", "mig-unswept", ("error", "6081", "CreatorFeesNotSwept", ("migrate_pool_coin_creator.rs", "CreatorFeesNotSwept"))),
    ("mig", "mig-bad-mint", ("error", "6045", "InvalidSharingConfigBaseMint", ("sharing_config", "InvalidSharingConfigBaseMint"))),
    ("mig", "mig-bad-admin", ("error", "6046", "InvalidSharingConfigCoinCreator", ("sharing_config", "InvalidSharingConfigCoinCreator"))),
    ("mig", "mig-wrong-pda", ("error", "2006", "ConstraintSeeds", ("sharing_config", "ConstraintSeeds"))),
    ("mig", "mig-wrong-owner", ("error", "3007", "AccountOwnedByWrongProgram", ("sharing_config", "AccountOwnedByWrongProgram"))),
    ("mig", "mig-pool-readonly", ("error", "2000", "ConstraintMut", ("pool", "ConstraintMut"))),
    ("mig", "mig-pool-disc-flip", ("error", "InvalidAccountData", "Error Number: 17179869184", ("pool", "InvalidAccountData"))),
    ("mig", "mig-sharing-disc-only", ("error", "3003", "AccountDidNotDeserialize", ("sharing_config", "AccountDidNotDeserialize"))),
    ("mig", "mig-sharing-empty", ("error", "3001", "AccountDiscriminatorNotFound", ("sharing_config", "AccountDiscriminatorNotFound"))),
    ("mig", "mig-bad-mint-holder", ("error", "6045", "InvalidSharingConfigBaseMint", ("sharing_config", "InvalidSharingConfigBaseMint"))),
]


def main():
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    present = sorted(str(p.relative_to(HERE)) for p in HERE.rglob("*") if p.is_file() and "MANIFEST.json" not in p.name)
    assert sorted(manifest["files"]) == present, (sorted(manifest["files"]), present)
    for name, digest in manifest["files"].items():
        assert sha((HERE / name).read_bytes()) == digest, name
    assert manifest["frozen_repository_inputs"] == {"programs/pump-amm/idls/pump.json": "inputs/pump.json"}
    for rel, digest in manifest["repository_inputs"].items():
        path = HERE / "inputs/pump.json" if rel == "programs/pump-amm/idls/pump.json" else ROOT / rel
        assert sha(path.read_bytes()) == digest, rel

    report = json.loads(gzip.decompress((HERE / "runtime/report.json.gz").read_bytes()))
    for rel, digest in report["input_sha256"].items():
        assert manifest["repository_inputs"][rel] == digest, rel
    assert report["case_count"] == len(EXPECTED) == 36, report["case_count"]
    assert report["counts"] == {"vms": 108, "transactions": 108, "signature_fields": 108}, report["counts"]
    assert report["mismatches"] == []
    assert report["image_sha256"]["original"] == sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes())
    assert report["image_sha256"]["control"] == sha(gzip.decompress(CONTROL.read_bytes()))
    assert report["image_sha256"]["candidate"] == sha(gzip.decompress(CANDIDATE.read_bytes()))

    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (HERE / part["path"]).read_bytes()
        assert len(data) < 25 * 1024 * 1024, part["path"]
        assert sha(data) == part["sha256"], part["path"]
        lines = gzip.decompress(data).decode().strip().split("\n")
        assert len(lines) == part["receipts"], part["path"]
        receipts.extend(json.loads(l) for l in lines)
    assert len(receipts) == 108, len(receipts)
    assert [c["label"] for c in report["cases"]] == [e[1] for e in EXPECTED]

    payer_key = str(PAYER.pubkey())
    for ci, (instruction, label, expected) in enumerate(EXPECTED):
        group = receipts[ci * 3:(ci + 1) * 3]
        errs, pools_after, event_logs = set(), set(), set()
        for ji, image in enumerate(IMAGES):
            r = group[ji]
            assert r["sequence"] == ci * 3 + ji and r["vm"] == ci * 3 + ji
            ctx = r["context"]
            assert (ctx["index"], ctx["image"], ctx["instruction"], ctx["label"]) == (ci, image, instruction, label), ctx
            assert r["all_signatures_verified"] is True and r["signature_fields"] == 1
            raw = base64.b64decode(r["transaction_base64"])
            assert sha(raw) == r["transaction_sha256"]
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks), (label, image)
            assert len(tx.signatures) == 1
            before, after = r["before"], r["after"]
            assert r["payer_fee_lamports"] == 5000
            assert before[payer_key]["lamports"] - after[payer_key]["lamports"] == 5000
            # before-snapshot shape
            pool_before = bytes.fromhex(before[str(POOLKEY)]["data_hex"])
            assert before[str(POOLKEY)]["owner"] == str(PROGRAM)
            if label == "set-pool-truncated":
                assert len(pool_before) == 100
            elif label == "set-pool-empty":
                assert len(pool_before) == 0
            else:
                assert len(pool_before) == 300
                if label in ("set-noncanonical", "set-noncanonical-meta-wrong-pda"):
                    assert pool_before[11:43] != bytes(POOL_AUTH)
                else:
                    assert pool_before[11:43] == bytes(POOL_AUTH)
                if instruction == "set":
                    assert pool_before[211:243] == (FIX_CC if label == "set-already-set" else bytes(32))
                else:
                    assert pool_before[211:243] == FIX_CC
            if instruction == "set":
                if label in ("set-meta-wrong-pda", "set-noncanonical-meta-wrong-pda"):
                    assert str(Pubkey.from_bytes(bytes([0x66]) * 32)) in before
                    assert str(META_PDA) not in before
                else:
                    assert before[str(META_PDA)]["owner"] == (str(Pubkey.default()) if label == "set-meta-wrong-owner" else str(META_PROG))
                if label == "set-bc-wrong-pda":
                    assert str(Pubkey.from_bytes(bytes([0x77]) * 32)) in before
                else:
                    assert before[str(BC_PDA)]["owner"] == (str(Pubkey.default()) if label == "set-bc-wrong-owner" else str(PUMP))
            else:
                if label == "mig-wrong-pda":
                    assert str(Pubkey.from_bytes(bytes([0x66]) * 32)) in before
                else:
                    assert before[str(SHARING_PDA)]["owner"] == (str(Pubkey.default()) if label == "mig-wrong-owner" else str(FEES_PROG))
            logs = r["metadata"]["logs"]
            events = [l for l in logs if l.startswith('Program data: ')]
            pool_after = bytes.fromhex(after[str(POOLKEY)]["data_hex"])
            errs.add(r["error"])
            pools_after.add(after[str(POOLKEY)]["data_hex"])
            event_logs.add(tuple(events))
            if expected[0] == "ok":
                assert r["error"] is None, (label, image, r["error"])
                assert pool_after[211:243].hex() == expected[1], (label, image)
                assert len(events) == expected[2], (label, image)
                if label == "set-already-set":
                    assert pool_after == pool_before
                else:
                    assert pool_after[:211] == pool_before[:211] and pool_after[243:] == pool_before[243:]
                for k in before:
                    if k not in (str(POOLKEY), payer_key):
                        assert before[k] == after[k], (label, image, k)
            else:
                _, err_sub, log_frag, site_subs = expected
                assert r["error"] is not None and err_sub in r["error"], (label, image, r["error"])
                assert log_frag in "\n".join(logs), (label, image)
                site = next((l for l in logs if "thrown in" in l or "caused by account" in l), None)
                if site_subs is None:
                    assert site is None, (label, image, site)
                else:
                    assert site is not None and site_subs[0] in site and site_subs[1] in site, (label, image, site)
                assert r["rollback_except_payer_fee"] is True
                assert all(before[k] == after[k] for k in before if k != payer_key), (label, image)
        assert len(errs) == 1 and len(pools_after) == 1 and len(event_logs) == 1, (label, "images disagree")
    print("PASS: 36 cases x 3 images = 108 receipts, all checks hold")


if __name__ == "__main__":
    main()
