#!/usr/bin/env python3
"""Verify integrity of this deep disassembly packet."""
import hashlib, json, os, sys

PACKET = os.path.dirname(os.path.abspath(__file__))

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    manifest = json.load(open(os.path.join(PACKET, "manifest.json")))
    errors = 0
    for name, expected in manifest.items():
        path = os.path.join(PACKET, name)
        if not os.path.exists(path):
            print(f"FAIL: {name} missing"); errors += 1; continue
        actual = sha256_file(path)
        if actual != expected:
            print(f"FAIL: {name} hash mismatch"); errors += 1
        else:
            print(f"  OK: {name}")
    s = json.load(open(os.path.join(PACKET, "summary.json")))
    w = json.load(open(os.path.join(PACKET, "windows-deep.json")))
    if s["total_windows"] != len(w):
        print(f"FAIL: window count mismatch"); errors += 1
    else:
        print(f"  OK: windows consistent ({len(w)})")
    if errors:
        print(f"\n{errors} error(s)"); return 1
    print("\nAll checks passed."); return 0

if __name__ == "__main__":
    sys.exit(main())
