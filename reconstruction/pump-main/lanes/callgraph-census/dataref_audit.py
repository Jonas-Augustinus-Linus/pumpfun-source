#!/usr/bin/env python3
"""Hidden data-reference audit: normalized matches whose lddw constants point at different data.

  dataref_audit.py [--cand unstripped.so] [--json out.json] [--width 16]

score.py masks lddw values that point into an ELF section, so a normalized match can load a
different string, panic Location, vtable or function pointer than the original. For every
normalized-matched window (best candidate = first bisimilar one from callid_audit's relation is not
needed: all normalized candidates are tried, a window is clean if any candidate is clean):
  * lddw -> .text: the two targets must be the same function by normalized body;
  * lddw -> data: compare `width` bytes at both targets, masking 8-byte words that are section
    pointers in both images (relocated pointers). Mismatches are reported with both byte strings.
Reading past the end of a short object can give false positives (neighbouring data differs by
layout); reported rows show the bytes so they can be judged. Diagnostic only.
"""
import argparse, hashlib, json, struct, sys, tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import census as C  # noqa: E402
from original_input import resolve_original  # noqa: E402
from score_admission import report_destination  # noqa: E402
from score import _window_rows  # noqa: E402
from compare_scores import publish_report  # noqa: E402


def lddws(raw, start):
    i = 0
    while i < len(raw):
        op = raw[i]
        if op == 0x18:
            v = struct.unpack_from('<I', raw, i + 4)[0] | struct.unpack_from('<I', raw, i + 12)[0] << 32
            ln = None
            for k in range(i + 16, min(i + 16 + 4 * 8, len(raw)), 8):
                if raw[k] & 7 in (5, 6):  # jump, call or exit: a later scalar is unrelated
                    break
                if raw[k] == 0xb7:  # mov64 dst, imm: likely the &str length
                    imm = struct.unpack_from('<i', raw, k + 4)[0]
                    if 0 < imm < 4096:
                        ln = imm
                    break
            yield i, v, ln
            i += 16
        else:
            i += 8


def sec_of(secs, v):
    for n, s in secs.items():
        if s['addr'] > 0 and s['addr'] <= v < s['addr'] + s['size']:
            return n
    return None


def read(img, v, n):
    s = img.secs[sec_of(img.secs, v)]
    o = v - s['addr'] + s['offset']
    end = min(o + n, s['offset'] + s['size'])
    return img.blob[o:end]


def ptr_words(img, b, base):
    """8-byte aligned words that are relocated pointers. sBPF keeps a data relocation's target as a
    u32 in the word's upper half (R_BPF_64_RELATIVE, offset+4); plain u64 addresses are accepted too."""
    out = {}
    for k in range(0, len(b) - 7):
        if (base + k) % 8:
            continue
        w = struct.unpack_from('<Q', b, k)[0]
        for v in ((w >> 32) if (w & 0xffffffff) == 0 else None, w):
            if v and sec_of(img.secs, v):
                out[k] = v
                break
    return out


def masked(img, b, base):
    out = bytearray(b)
    for k in ptr_words(img, b, base):
        out[k:k + 8] = b'PPPPPPPP'
    return bytes(out)


def audit(candidate_path, original_path, original_blob, inventory_text, width):
    wins = [dict(zip(('start', 'bytes', 'raw', 'norm'), row))
            for row in _window_rows(original_blob, inventory_text)]
    O = C.Image(original_path, {w['start']: (w['bytes'], []) for w in wins})
    cf = {}
    for s, n, nm in C.candidate_functions(candidate_path):
        cf.setdefault(s, (n, []))[1].append(nm)
    K = C.Image(candidate_path, cf)

    def nh(img, s):
        return (img.funcs[s][0], hashlib.sha256(C.normalize(img.raw(s), s, img.secs)).digest())
    by = defaultdict(set)
    for s in cf:
        by[nh(K, s)].add(s)
    rows = []
    clean = 0
    for o in sorted(O.funcs):
        cands = sorted(by.get(nh(O, o), ()))
        if not cands:
            continue
        per = []
        for c in cands:
            bad = []
            for (i, vo, ln), (j, vc, _) in zip(lddws(O.raw(o), o), lddws(K.raw(c), c)):
                so, sc = sec_of(O.secs, vo), sec_of(K.secs, vc)
                if not so:
                    continue
                if so == '.text':
                    ok = vo in O.funcs and vc in cf and nh(O, vo) == nh(K, vc)
                    if not ok:
                        bad.append({'off': hex(i), 'kind': 'fnptr', 'orig': hex(vo), 'ours': hex(vc),
                                    'our_name': C.short(cf[vc][1][0]) if vc in cf else None})
                    continue
                w = min(width, ln) if (so == '.rodata' and ln) else width
                bo, bc = read(O, vo, w + 8), read(K, vc, w + 8)
                mo, mc = masked(O, bo, vo), masked(K, bc, vc)
                n = min(len(mo), len(mc), w)
                po, pc = ptr_words(O, bo, vo), ptr_words(K, bc, vc)
                for k in sorted(set(po) & set(pc)):
                    if k < n and sec_of(O.secs, po[k]) == '.text':
                        x, y = po[k], pc[k]
                        if not (x in O.funcs and y in cf and nh(O, x) == nh(K, y)):
                            bad.append({'off': hex(i), 'kind': 'data-fnptr', 'orig': hex(x), 'ours': hex(y),
                                        'our_name': C.short(cf[y][1][0]) if y in cf else None})
                bo, bc = bo[:w], bc[:w]
                if mo[:w] != mc[:w]:
                    bad.append({'off': hex(i), 'kind': 'data', 'sec': so, 'orig': hex(vo), 'ours': hex(vc),
                                'orig_bytes': bo.hex(), 'our_bytes': bc.hex(),
                                'orig_txt': bo.decode('latin1').encode('unicode_escape').decode()[:40],
                                'our_txt': bc.decode('latin1').encode('unicode_escape').decode()[:40]})
            per.append({'cand': hex(c), 'name': C.short(cf[c][1][0]), 'bad': bad})
        if any(not p['bad'] for p in per):
            clean += 1
        else:
            rows.append({'window': hex(o), 'bytes': O.funcs[o][0], 'candidates': per[:2]})
    res = {'width': width, 'clean': clean, 'flagged': len(rows), 'rows': rows}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cand', type=Path, required=True)
    ap.add_argument('--json', type=Path)
    ap.add_argument('--width', type=int, default=16)
    a = ap.parse_args()
    if a.width <= 0:
        ap.error('--width must be positive')
    if a.json:
        # Reject lexical and physical aliases before reading any inputs.
        # Publication repeats this check, then exclusively admits a complete
        # staged report, so late collisions cannot replace prior bytes.
        try:
            report_destination(a.json, [a.cand, C.BASE / 'original.so',
                                        resolve_original(C.BASE / 'original.so'),
                                        C.BASE / 'functions.tsv'])
        except ValueError as error:
            ap.error(str(error))
    # Every analysis read uses one admitted byte cohort, including symbols and
    # original window boundaries. Replacing public paths cannot mix images.
    original_blob = C.ORIG_PATH.read_bytes()
    candidate_blob = a.cand.read_bytes()
    inventory_blob = (C.BASE / 'functions.tsv').read_bytes()
    with tempfile.TemporaryDirectory(prefix='pump-dataref-inputs-') as temporary:
        directory = Path(temporary)
        original_path, candidate_path = directory / 'original.so', directory / 'candidate.so'
        original_path.write_bytes(original_blob)
        candidate_path.write_bytes(candidate_blob)
        original_path.chmod(0o400)
        candidate_path.chmod(0o400)
        res = audit(candidate_path, original_path, original_blob, inventory_blob.decode('utf-8'), a.width)
    res = {'candidate': str(a.cand),
           'candidate_sha256': hashlib.sha256(candidate_blob).hexdigest(),
           'original_sha256': hashlib.sha256(original_blob).hexdigest(),
           'window_inventory_sha256': hashlib.sha256(inventory_blob).hexdigest(), **res}
    if a.json:
        try:
            report_destination(a.json, [a.cand, C.BASE / 'original.so', C.ORIG_PATH,
                                        C.BASE / 'functions.tsv'])
            publish_report(a.json, json.dumps(res, indent=1) + '\n')
        except (OSError, ValueError) as error:
            ap.error(str(error))
    print(json.dumps({key: res[key] for key in ('width', 'clean', 'flagged')}))
    for r in res['rows']:
        p = r['candidates'][0]
        print(r['window'], p['name'][:60], len(p['bad']), [(b['kind'], b.get('orig_txt', b.get('our_name')), b.get('our_txt')) for b in p['bad'][:2]])


if __name__ == '__main__':
    main()
