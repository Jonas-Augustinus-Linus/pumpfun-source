#!/usr/bin/env python3
import hashlib, json, os, sys
PACKET = os.path.dirname(os.path.abspath(__file__))
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""): h.update(c)
    return h.hexdigest()
def main():
    m = json.load(open(os.path.join(PACKET, "manifest.json")))
    e = 0
    for n, x in m.items():
        p = os.path.join(PACKET, n)
        if not os.path.exists(p): print(f"FAIL: {n} missing"); e += 1; continue
        if sha256_file(p) != x: print(f"FAIL: {n} hash mismatch"); e += 1
        else: print(f"  OK: {n}")
    for layer in range(1, 6):
        f = f"layer{layer}-{'data-layout' if layer==1 else 'relocation-map' if layer==2 else 'cross-section' if layer==3 else 'anchor-idl' if layer==4 else 'math-analysis'}.json"
        if not os.path.exists(os.path.join(PACKET, f)):
            print(f"FAIL: {f} missing"); e += 1
        else: print(f"  OK: layer {layer} present")
    if e: print(f"\n{e} error(s)"); return 1
    print("\nAll checks passed."); return 0
if __name__ == "__main__": sys.exit(main())
