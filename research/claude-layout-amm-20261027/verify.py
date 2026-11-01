#!/usr/bin/env python3
"""Recompute every claimed count of this packet from saved artifacts (read-only).

Runs no compiler, linker, VM or network. For every frontier and layout in
claims.json it checks:
  1. packet inventory (manifest.json) and artifact / map SHA-256 values;
  2. the repository AMM window measurement (same reader, key and raw test as
     repro/pump_amm/focused-diagnostics-20261026/measure.py) of the frontier's
     own artifacts and of the layout, the claimed counts, no lost normalized or
     raw window, the exact gained set, and equality with the saved measurement
     JSON rows;
  3. the linker script: identical to the captured SDK script outside the
     `.text` / `.rodata` / `.data.rel.ro` selector lists; every selector line is
     `*FILE("SECTION")` (or `*(".rodata.cstN")` for merged constant pools) and
     names exactly one input section of that output section in the default map;
     every default input section is named exactly once; the SDK catch-all ends
     each list; no other statement is present;
  4. regeneration of the script byte-for-byte by tools/plan.py / tools/dataplan.py;
  5. a byte-level translation proof (tools/translation.py) for both the stripped
     and the symbol ELF: every byte of the layout ELF follows from the frontier
     ELF and the two maps by moving input sections, recomputing direct-call
     immediates, translating relocated immediates/pointers/symbol values and
     zero padding — no supplied or patched bytes;
  6. the multiplicity deficit (normalized windows whose equal body is already
     placed elsewhere), data-immediate offsets, native relink receipts against
     the packet's link-kit inputs, repeat-build records, and runtime summaries
     plus per-case digests (25 suites, 17,462 cases, zero negative verdicts).
"""
import argparse, collections, gzip, hashlib, json, re, sys, tempfile
from pathlib import Path

if not __debug__:
    raise RuntimeError('verification requires assertions; do not use Python -O')
sys.dont_write_bytecode = True

P = Path(__file__).resolve().parent


def find_root(argv):
    if '--repository-root' in argv:
        return Path(argv[argv.index('--repository-root') + 1]).resolve()
    for p in [P, *P.parents]:
        if (p / 'evidence/original/pump_amm/deployed.so').is_file():
            return p
    raise SystemExit('repository root not found; pass --repository-root')


ROOT = find_root(sys.argv)
sys.path.insert(0, str(ROOT / 'repro/pump_amm/claim-self-transfer-v144/static-tool'))
sys.path.insert(0, str(P / 'tools'))
from elf_reader import Elf  # noqa: E402
import plan as planmod  # noqa: E402
import dataplan  # noqa: E402
import translation  # noqa: E402
import runtime_digest  # noqa: E402

planmod.ROOT = ROOT
sha = lambda b: hashlib.sha256(b).hexdigest()
ORIGINAL = ROOT / 'evidence/original/pump_amm/deployed.so'
FILE = r'\*[A-Za-z0-9_.+-]+(?::[A-Za-z0-9_.+-]+)?'
SECTION = {'.text': r'\.text\.[A-Za-z0-9_.$]+', '.rodata': r'\.rodata\.[A-Za-z0-9_.$]+',
           '.data.rel.ro': r'\.data\.rel\.ro\.[A-Za-z0-9_.$]+'}
BLOCKS = [('.text', '  .text : { *(.text*) } :text', '\n    *(.text*)\n  } :text'),
          ('.rodata', '  .rodata : { *(.rodata*) } :rodata', '\n    *(.rodata*)\n  } :rodata'),
          ('.data.rel.ro', '  .data.rel.ro : { *(.data.rel.ro*) } :rodata', '\n    *(.data.rel.ro*)\n  } :rodata')]


def check_inventory():
    paths = list(P.rglob('*'))
    assert not any(f.is_symlink() for f in paths), 'packet includes a symlink'
    assert all(f.is_file() or f.is_dir() for f in paths), 'packet includes a special file'
    actual = {f.relative_to(P).as_posix(): sha(f.read_bytes()) for f in paths if f.is_file() and f != P / 'manifest.json'}
    assert actual == json.loads((P / 'manifest.json').read_text()), 'packet file inventory differs'


def measure(candidate, symbols):
    """Exact replica of focused-diagnostics measure.py row logic (no file output)."""
    original = Elf(ORIGINAL)
    c, s = Elf(Path(candidate)), Elf(Path(symbols))
    assert c.b[c.lo:c.hi] == s.b[s.lo:s.hi]
    index = collections.defaultdict(list)
    for f in s.funcs:
        st, size = f['start'], f['size']
        key = (size, sha(c.normalized[st:st + size]), json.dumps(c.pattern(st, size), sort_keys=True))
        index[key].append({'start': st, 'raw_sha256': sha(c.b[st:st + size])})
    entries = sorted(set(original.entries) | {original.lo})
    rows = []
    for st, en in zip(entries, entries[1:] + [original.hi]):
        m = index[(en - st, sha(original.normalized[st:en]), json.dumps(original.pattern(st, en - st), sort_keys=True))]
        raw = sha(original.b[st:en])
        rows.append({'start': st, 'size': en - st, 'normalized': bool(m), 'raw': any(x['raw_sha256'] == raw for x in m),
                     'matches': sorted(x['start'] for x in m)})
    return rows


def counts(rows):
    return {'windows': len(rows), 'normalized_matches': sum(r['normalized'] for r in rows),
            'raw_matches': sum(r['raw'] for r in rows), 'unmatched': sum(not r['normalized'] for r in rows),
            'raw_matched_original_bytes': sum(r['size'] for r in rows if r['raw']),
            'normalized_matched_original_bytes': sum(r['size'] for r in rows if r['normalized'])}


def check_saved_measurement(path, rows, candidate_sha256):
    saved = json.loads(gzip.decompress((P / path).read_bytes()))
    assert saved['candidate_sha256'] == candidate_sha256, ('saved measurement binds another candidate', path)
    got = [(r['start'], r['start'] + r['size'], r['raw'], r['matches']) for r in rows]
    want = [(r['start'], r['end'], r['raw_match'], sorted(m['start'] for m in r['matches'])) for r in saved['rows']]
    assert got == want, ('saved measurement rows differ from recomputation', path)
    assert (saved['raw_matches'], saved['normalized_matches'], saved['unmatched']) == (
        sum(r['raw'] for r in rows), sum(r['normalized'] for r in rows), sum(not r['normalized'] for r in rows)), path


def unpack(path, expect, tmp):
    data = gzip.decompress((P / path).read_bytes())
    assert sha(data) == expect, (path, sha(data), expect)
    out = Path(tmp) / Path(path).name.replace('.gz', '')
    out.write_bytes(data)
    return out


def input_sections(mapfile):
    keys = collections.Counter()
    for r in dataplan.parse_data_map(mapfile) + [dict(x, out='.text') for x in planmod.parse_map(mapfile)]:
        owner = '<internal>' if r['owner'] == '<internal>' else planmod.selector_owner(r['owner'])[1:]
        keys[(r['out'], owner, r['section'])] += 1
    assert all(v == 1 for v in keys.values()), 'map input sections are not uniquely qualified'
    return set(keys)


def check_script(default, script, data_order, default_sections):
    """Strict structure: SDK text outside the selector lists, selector-only lists."""
    rest = script
    named = set()
    for i, (out, line, end) in enumerate(BLOCKS):
        if i == 0:
            head = default.split(line)[0]
            assert rest.startswith(head), 'script prefix differs from SDK script'
            rest = rest[len(head):]
        if i > 0 and not data_order:
            assert rest.startswith(line), 'data block differs from SDK script'
            rest = rest[len(line):]
        else:
            start = '  %s : {\n' % out
            assert rest.startswith(start), 'block header differs'
            stop = rest.index(end)
            for sel in rest[len(start):stop].split('\n'):
                m = re.fullmatch(r'    (%s)\("(%s)"\)' % (FILE, SECTION[out]), sel)
                pool = re.fullmatch(r'    \*\("(\.rodata\.cst(?:4|8|16|32))"\)', sel)
                assert m or (pool and out == '.rodata'), ('selector is not a qualified input-section name', sel[:100])
                key = (out, m.group(1)[1:], m.group(2)) if m else (out, '<internal>', pool.group(1))
                assert key in default_sections, ('selector names no default input section', sel[:100])
                assert key not in named, ('selector repeated', sel[:100])
                named.add(key)
            rest = rest[stop + len(end):]
        nxt = BLOCKS[i + 1][1] if i + 1 < len(BLOCKS) else None
        between = default.split(line)[1].split(nxt)[0] if nxt else default.split(line)[1]
        assert rest.startswith(between), 'text between blocks differs from SDK script'
        rest = rest[len(between):]
    assert rest == '', 'trailing statements after the SDK script'
    for out in ([o for o, _, _ in BLOCKS] if data_order else ['.text']):
        assert {k for k in default_sections if k[0] == out} == {k for k in named if k[0] == out}, ('not every input section named', out)


def data_reference_offsets(pl, symbols, mapfile):
    """lddw immediates into .rodata/.data.rel.ro inside normalized-equal placed pairs
    that land at the original section-relative offset in this artifact."""
    e = Elf(Path(symbols))
    placed = {(planmod.selector_owner(r['owner']), r['section']): r['vma'] for r in planmod.parse_map(mapfile)}
    ob = {n: dataplan.bounds(pl.o, n) for n in dataplan.DATA}
    cb = {n: dataplan.bounds(e, n) for n in dataplan.DATA}
    total = equal = 0
    for w, c in pl.A.items():
        if pl.wkey[w] != pl.ckey[c]:
            continue
        r = pl.sections[c]
        at = placed[(planmod.selector_owner(r['owner']), r['section'])]
        st, en = pl.W[w]
        wo, wc = dataplan.lddw_values(pl.o, st, en - st), dataplan.lddw_values(e, at, r['size'])
        for off, vo in wo.items():
            so = next((n for n, (lo, hi) in ob.items() if lo <= vo < hi), None)
            if so is None:
                continue
            total += 1
            vc = wc.get(off)
            equal += vc is not None and cb[so][0] <= vc < cb[so][1] and vo - ob[so][0] == vc - cb[so][0]
    return {'data_references': total, 'at_original_section_offset': equal}


def check_runtime(rec, candidate_sha256):
    summ = json.loads((P / rec['runtime']).read_text())
    assert summ['candidate_sha256'] == candidate_sha256 and summ['mismatches'] == [], 'runtime summary binding'
    assert summ['cases'] == 17462 and summ['suites'] == 25 and summ['transactions'] == 35074, 'runtime summary counts'
    suites = json.loads((P / rec['runtime_suites']).read_text())
    cases = json.loads(gzip.decompress((P / rec['runtime_cases']).read_bytes()))
    assert cases['candidate_sha256'] == candidate_sha256 == summ['candidate_sha256'], 'runtime case digest binding'
    assert len(suites) == 25 and {s['suite'] for s in suites} == set(cases['suites']), 'runtime suite set'
    assert sum(s['case_count'] for s in suites) == summ['cases'], 'runtime case sum'
    assert sum(s['transactions'] for s in suites) == summ['transactions'], 'runtime transaction sum'
    assert sum(s['signatures'] for s in suites) == summ['signatures'], 'runtime signature sum'
    for s in suites:
        c = cases['suites'][s['suite']]
        assert s['returncode'] == 0 and not s['mismatches'] and c['mismatches'] == 0, s['suite']
        assert c['case_count'] == s['case_count'] == len(c['cases']) and c['receipt_sha256'] == s['receipt_sha256'], s['suite']
        assert all(v is True for _, v in c['cases']), ('negative case verdict', s['suite'])
        assert runtime_digest.suite_digest(c['cases']) == c['suite_digest'], ('suite digest', s['suite'])
    return summ['cases']


def check_relink(receipt, kit, symbols_sha256, candidate_sha256, script_path):
    r = json.loads((P / receipt).read_text())
    assert r['symbols_sha256'] == symbols_sha256 and r['candidate_sha256'] == candidate_sha256, ('relink receipt', receipt)
    assert r['script_sha256'] == sha((P / script_path).read_bytes()), ('relink receipt script', receipt)
    assert r['effective_args_sha256'] == sha((P / kit / 'effective-args.txt').read_bytes()), 'relink receipt arguments'
    held = {f.name[:-3]: sha(gzip.decompress(f.read_bytes())) for f in (P / kit).glob('*.gz')}
    assert held == r['transient_inputs'], ('link-kit inputs differ from receipt', receipt)
    args = (P / kit / 'effective-args.txt').read_text().split('\n')
    assert {a for a in args if a.endswith('.rlib')} == set(r['dependency_rlibs']), 'receipt rlib set'


def check_frontier(fname, fr, tmp, regenerate, report):
    packet = ROOT / fr['packet'] / 'results/build'
    base_c, base_s = packet / 'candidate.so', packet / 'unstripped.so'
    assert sha(base_c.read_bytes()) == fr['baseline']['candidate_sha256'], fname
    assert sha(base_s.read_bytes()) == fr['baseline']['symbols_sha256'], fname
    base_rows = measure(base_c, base_s)
    rep = report[fname] = {'baseline': counts(base_rows)}
    assert rep['baseline'] == fr['baseline']['counts'], (fname, rep['baseline'])
    check_saved_measurement(fr['baseline']['measurement'], base_rows, fr['baseline']['candidate_sha256'])
    default_script = (P / fr['sdk_script']).read_text()
    default_map = Path(tmp) / (fname + '-default.map')
    default_map.write_bytes(gzip.decompress((P / fr['default_map']).read_bytes()))
    assert sha(default_map.read_bytes()) == fr['default_map_sha256'], 'default map hash'
    default_sections = input_sections(default_map)
    pl0 = planmod.Plan(ORIGINAL, base_s, default_map)
    pl0.assign()
    deficit = sorted(hex(pl0.W[w][0]) for w in range(len(pl0.W)) if pl0.C[w] and w not in pl0.A)
    assert deficit == fr['multiplicity_deficit'], ('multiplicity deficit', deficit)
    rep['placed_with_equal_body'] = sum(1 for w, c in pl0.A.items() if pl0.wkey[w] == pl0.ckey[c])
    assert rep['placed_with_equal_body'] == rep['baseline']['normalized_matches'] - len(deficit)
    assert data_reference_offsets(pl0, base_s, default_map) == fr['baseline']['data_references'], fname
    check_relink(fr['default_receipt'], fr['kit'], fr['baseline']['symbols_sha256'], fr['baseline']['candidate_sha256'], fr['sdk_script'])
    for name, rec in fr['layouts'].items():
        c = unpack(rec['candidate'], rec['candidate_sha256'], tmp)
        s = unpack(rec['symbols'], rec['symbols_sha256'], tmp)
        rows = measure(c, s)
        got = counts(rows)
        assert got == rec['counts'], ('claimed counts differ', name, got, rec['counts'])
        check_saved_measurement(rec['measurement'], rows, rec['candidate_sha256'])
        lost_norm = [hex(x['start']) for x, y in zip(base_rows, rows) if x['normalized'] and not y['normalized']]
        lost_raw = [hex(x['start']) for x, y in zip(base_rows, rows) if x['raw'] and not y['raw']]
        gained_raw = [hex(x['start']) for x, y in zip(base_rows, rows) if y['raw'] and not x['raw']]
        assert not lost_norm and not lost_raw, (name, lost_norm, lost_raw)
        assert gained_raw == rec['gained_raw_windows'], name
        script = (P / rec['script']).read_text()
        check_script(default_script, script, rec.get('data_order', False), default_sections)
        omap = Path(tmp) / (name + '.map')
        omap.write_bytes(gzip.decompress((P / rec['map']).read_bytes()))
        assert sha(omap.read_bytes()) == rec['map_sha256'], ('layout map hash', name)
        assert input_sections(omap) == default_sections, name
        if regenerate:
            pl = planmod.Plan(ORIGINAL, base_s, default_map)
            pl.assign()
            seq, tl = pl.order()
            regen = pl.script(default_script, seq, tl)
            if rec.get('data_order'):
                dp = dataplan.DataPlan(pl, default_map)
                dp.place()
                regen = dp.script(regen)
            assert regen == script, name + ': regenerated script differs'
        proofs = {}
        for kind, before, after in (('stripped', base_c, c), ('symbols', base_s, s)):
            res = translation.prove(before, after, default_map, omap)
            proofs[kind] = {k: v for k, v in res.items() if k not in ('before_sha256', 'after_sha256')}
        assert proofs == rec['translation'], ('translation statistics', name)
        got_d = data_reference_offsets(pl0, s, omap)
        assert got_d == rec['data_references'], (name, got_d)
        check_relink(rec['relink_receipt'], fr['kit'], rec['symbols_sha256'], rec['candidate_sha256'], rec['script'])
        for path in rec['linux_builds']:
            rb = json.loads((P / path).read_text())
            assert rb['candidate_sha256'] == rec['candidate_sha256'] and rb['unstripped_sha256'] == rec['symbols_sha256'], path
            assert rb['ordered_sha256'] == sha(script.encode()) and rb['dependency_artifacts_unchanged'], path
        cases = check_runtime(rec, rec['candidate_sha256'])
        rep[name] = dict(got, gained_raw=len(gained_raw), lost_raw=0, lost_normalized=0, data_references=got_d,
                         linux_builds=len(rec['linux_builds']), runtime_cases=cases,
                         translated_direct_calls=proofs['symbols']['direct_calls'])


def main():
    check_inventory()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--skip-regenerate', action='store_true', help='skip regenerating ordered scripts with tools/')
    ap.add_argument('--repository-root', type=Path, help='repository holding evidence/ and the frontier packets')
    ap.add_argument('--frontier', help='check only this frontier (default: all)')
    a = ap.parse_args()
    claims = json.loads((P / 'claims.json').read_text())
    report = {}
    with tempfile.TemporaryDirectory() as tmp:
        for fname, fr in claims['frontiers'].items():
            if a.frontier in (None, fname):
                check_frontier(fname, fr, tmp, not a.skip_regenerate, report)
    assert report, 'no frontier checked'
    print(json.dumps(report, indent=2))
    print('verified')


if __name__ == '__main__':
    main()
