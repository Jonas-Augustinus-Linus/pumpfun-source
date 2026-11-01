"""Verify this packet's retained signed runtime receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, trade fixture, IDL, evidence programs)
  hash to the recorded values;
 - 7 cases x 3 images = 21 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases show the expected config change (flags byte, mayhem
  byte, or admin key bytes 8..40);
- error cases fail with the expected code and log fragment, and roll
  back every account except the payer's 5000 fee;
- the recorded error sites match the receipts' logs;
- receipts are stored as parts, each under 25MB, read in order.
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
IMAGES = ("original", "control", "candidate")

sys.path.insert(0, str(ROOT / "scripts"))
from pump_amm_liquidity_differential import userbase as USERBASE_KEY  # noqa: E402
from pump_amm_liquidity_differential import userquote as USERQUOTE_KEY  # noqa: E402
from pump_amm_liquidity_differential import CONFIG_KEY  # noqa: E402
from pump_amm_liquidity_differential import PAYER as PAYER_KEYPAIR  # noqa: E402
from pump_amm_create_differential import ATA as ATA_PROGRAM  # noqa: E402
from pump_amm_create_differential import TOKEN as TOKEN_PROGRAM  # noqa: E402
from pump_amm_create_differential import PROGRAM  # noqa: E402
from pump_amm_create_differential import base as BASE_MINT  # noqa: E402
from pump_amm_create_differential import quote as QUOTE_MINT  # noqa: E402

_POOL = Pubkey.find_program_address(
    [b"pool", struct.pack("<H", 0), bytes(PAYER_KEYPAIR.pubkey()), bytes(BASE_MINT), bytes(QUOTE_MINT)],
    PROGRAM)[0]
VAULTBASE_KEY = str(Pubkey.find_program_address(
    [bytes(_POOL), bytes(TOKEN_PROGRAM), bytes(BASE_MINT)], ATA_PROGRAM)[0])
VAULTQUOTE_KEY = str(Pubkey.find_program_address(
    [bytes(_POOL), bytes(TOKEN_PROGRAM), bytes(QUOTE_MINT)], ATA_PROGRAM)[0])


def sha(data):
    return hashlib.sha256(data).hexdigest()


def amount_at(data_hex, offset):
    return struct.unpack_from("<Q", bytes.fromhex(data_hex), offset)[0]


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
    assert [p["receipts"] for p in parts] == [10, 10, 1]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 7
    assert len(receipts) == 21
    assert report["counts"] == {"vms": 21, "transactions": 21, "signature_fields": 21}
    assert report["mismatches"] == []
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress((ROOT / "research/amm-multi-hop-group-slice-recovery"
                                        "/artifacts/candidate.so.gz").read_bytes())),
        "candidate": sha(gzip.decompress((ROOT / "research/amm-transfer-fee-diagnostic-recovery"
                                          "/artifacts/candidate.so.gz").read_bytes())),
    }
    for name, digest in report["input_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    for index, row in enumerate(report["cases"]):
        case = row["case"]
        kind = case["expected"][0]
        pairs = set()
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": 0, "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"], validate=True)
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == 1
            assert rec["all_signatures_verified"] and rec["signature_fields"] == 1
            assert sha(raw) == rec["transaction_sha256"]
            assert [str(s) for s in tx.signatures] == rec["signatures"]
            assert rec["loaded_programs"][next(
                k for k in rec["loaded_programs"] if k.startswith("pAMM"))]["sha256"] == \
                report["image_sha256"][image]
            value = row[image]
            assert value["error"] == rec["error"] and value["logs"] == rec["metadata"]["logs"]
            payer = str(tx.message.account_keys[0])
            assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == \
                rec["payer_fee_lamports"]
            if kind == "ok":
                assert rec["error"] is None
                cfg_after = bytes.fromhex(rec["after"][str(CONFIG_KEY)]["data_hex"]) \
                    if str(CONFIG_KEY) in rec["after"] else b""
                check = case["expected"][1]
                if check[0] == "vaults":
                    vb = bytes.fromhex(rec["after"][VAULTBASE_KEY]["data_hex"])
                    vq = bytes.fromhex(rec["after"][VAULTQUOTE_KEY]["data_hex"])
                    got = (struct.unpack_from("<Q", vb, 64)[0],
                           struct.unpack_from("<Q", vq, 64)[0])
                else:
                    got = cfg_after[8:40].hex()
                assert got == (tuple(check[1]) if isinstance(check[1], list) else check[1]), (case, image, got)
                assert rec["observed"] == {check[0]: check[1]}
                assert value["observed"] == rec["observed"]
                pairs.add((got,) if isinstance(got, int) else (got,))
                assert value["observed"] == rec["observed"]
            else:
                assert rec["error"] is not None and case["expected"][1] in rec["error"]
                assert case["expected"][2] in "\n".join(rec["metadata"]["logs"])
                assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == 5000
                assert all(rec["before"][k] == rec["after"][k]
                           for k in rec["before"] if k != payer)
                assert rec["rollback_except_payer_fee"] is True
                site = next((l for l in rec["metadata"]["logs"]
                             if "thrown in" in l or "caused by account" in l), None)
                assert row["error_sites"][image] == site, (case, image)
        if kind == "ok":
            assert len(pairs) == 1, (case, "images must agree on amounts")
    print("PASS: 7 cases, 21 signed receipts, "
          "create pool validation pinned, "
          "same-mint, zero amounts, duplicate pool, "
          "all images agree")


if __name__ == "__main__":
    main()
