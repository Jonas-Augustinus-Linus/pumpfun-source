#!/usr/bin/env python3
"""Recompute this packet's recorded claims from saved artifacts; compiles and links nothing.

For each round directory (roundNN/ with claims.json) the verifier checks:
  1. every packet file matches MANIFEST.json (no symlinks or special files);
  2. the published round ELF is the baseline: its sha256 equals the round's
     CHECKPOINT and its recomputed window inventory has the published
     normalized/raw/unmatched counts and matched/raw text bytes;
  3. derive_layout.py, re-run on that ELF and the saved baseline lld map,
     regenerates the saved ordered.ld byte for byte; the script is the SDK
     default plus a literal qualified `.text` input list only;
  4. the saved ordered ELF's inventory reproduces every recorded count (incl.
     matched and raw text bytes), with no normalized or raw window lost and
     exactly the recorded raw gains;
  5. the translation proof (all recorded statistics), the residual classes,
     data-operand/Location breakdown, top call-only blockers, blocker pricing
     (unlock) and correspondence disclosure figures recompute to the recorded
     values;
  6. the saved stripped candidate has the claimed sha256 and carries exactly
     the unstripped ELF's allocated sections and program headers (pure Python);
  7. build records (or, for relink-only rounds, the relink record) bind the
     saved script and artifacts, and each recorded build compiled exactly the
     round's archived primary source;
  8. when a round records runtime evidence: every per-suite result and loader
     receipt hash, per-suite case counts, the absence of any recorded mismatch,
     loader invariants, and the diagnostic audit (log-bearing cases,
     mismatches) via scripts/pump_diagnostic_audit.py;
  9. when a round records policy controls, every control script is regenerated
     from its policy and has the recorded sha256;
 10. for rounds the integration session published with this generator composed
     in (roundNN-composed.json), the text order regenerates byte for byte from
     the round's recorded default-layout baseline, and both ELFs re-measure to
     the recorded counts and gains.
Window measurement uses the repository's scripts/pump_compare_function_bytes.py
and pump_quote_control_function_match.sections; candidate function symbols are
listed by tools/measure.py. Archive identification (needs dependency rlibs)
and relinked control ELFs are recorded observations, not re-derived here.
"""
import argparse
import gzip
import hashlib
import json
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise RuntimeError('verification requires assertions; do not use Python -O')
sys.dont_write_bytecode = True

P = Path(__file__).resolve().parent
sys.path.insert(0, str(P / 'tools'))
import classify  # noqa: E402
import derive_layout  # noqa: E402
import disclose  # noqa: E402
import layout_script  # noqa: E402
import measure  # noqa: E402
import translation  # noqa: E402
import unlock  # noqa: E402

ROOT = measure.ROOT
sha = lambda b: hashlib.sha256(b).hexdigest()


def read(p):
    b = Path(p).read_bytes()
    return json.loads(gzip.decompress(b) if b[:2] == b'\x1f\x8b' else b)


def unpacked(p, tmp):
    p = Path(p)
    if p.suffix != '.gz':
        return p
    out = Path(tmp) / '-'.join(p.relative_to(P).parts)[:-3]  # unique per packet path
    out.write_bytes(gzip.decompress(p.read_bytes()))
    return out


def strip_check(unstripped, stripped):
    """The stripped file carries exactly the unstripped file's loadable image."""
    A, B = translation.Elf(unstripped), translation.Elf(stripped)
    assert A.entry == B.entry and A.phnum == B.phnum
    assert A.b[A.phoff:A.phoff + A.phnum * A.phentsize] == B.b[B.phoff:B.phoff + B.phnum * B.phentsize]
    alloc = [s for s in A.section_list if s['flags'] & 2]
    balloc = [s for s in B.section_list if s['flags'] & 2]
    assert [(s['name'], s['type'], s['flags'], s['addr'], s['size']) for s in alloc] == \
           [(s['name'], s['type'], s['flags'], s['addr'], s['size']) for s in balloc]
    for s in alloc:
        if s['type'] != 8:  # SHT_NOBITS has no file bytes
            assert A.data(s['name']) == B.data(s['name']), s['name']
    extra = {s['name'] for s in B.section_list if not s['flags'] & 2} - {'', '.shstrtab'}
    assert not extra, extra
    return {'allocated_sections_equal': len(alloc)}


def runtime_check(d, claims):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from pump_diagnostic_audit import audit
    rt = claims['runtime']
    summary = read(d / rt['summary'])
    cand, orig = claims['ordered']['candidate_sha256'], sha((ROOT / 'evidence/original/pump/deployed.so').read_bytes())
    assert summary['candidate_sha256'] == cand and summary['original_sha256'] == orig

    def has(x, digest):
        if isinstance(x, str):
            return x == digest
        if isinstance(x, dict):
            return any(has(v, digest) for v in x.values())
        if isinstance(x, list):
            return any(has(v, digest) for v in x)
        return False

    def clean(x, where):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ('mismatches', 'different_fields', 'differences', 'failures'):
                    assert not v, (where, k)
                else:
                    clean(v, where)
        elif isinstance(x, list):
            for v in x:
                clean(v, where)

    suites, cases = {}, 0
    for row in summary['suites']:
        name = row['suite']
        f = d / 'runtime/suites' / (name + '.json.gz')
        assert sha(f.read_bytes()) == row['result_sha256'], name
        r = read(f)
        assert has(r, cand) and has(r, orig), (name, 'artifact binding')
        assert r['case_count'] == row['cases'], name
        clean(r, name)
        loads = read(d / 'runtime/suites' / (name + '.loader.json.gz'))['loads']
        assert len(loads) == row['loader_loads'] and {x['elf_sha256'] for x in loads} == {cand, orig}, name
        assert all(x['program_owner'] == 'BPFLoaderUpgradeab1e11111111111111111111111' and x['program_bytes'] == 36
                   and x['programdata_bytes'] == 10485760 and x['elf_prefix_unchanged'] and x['zero_allocation_tail']
                   for x in loads), name
        suites[name] = r
        cases += r['case_count']
    a = audit(suites)
    assert len(suites) == summary['suite_count'] == rt['suite_count'] and cases == summary['case_count'] == rt['case_count']
    assert a['log_bearing_cases'] == summary['diagnostic_log_cases'] == rt['diagnostic_log_cases']
    assert len(a['mismatches']) == summary['diagnostic_mismatches'] == rt['diagnostic_mismatches'] == 0
    return {'suites': len(suites), 'cases': cases, 'log_bearing_cases': a['log_bearing_cases'], 'diagnostic_mismatches': 0}


def verify_round(d, tmp):
    claims = read(d / 'claims.json')
    frontier = ROOT / claims['frontier_packet']
    cp = read(frontier / 'CHECKPOINT.json')
    base_elf = frontier / 'unstripped.so'
    assert sha(base_elf.read_bytes()) == cp['unstripped_sha256'] == claims['baseline']['unstripped_sha256']
    assert cp['candidate_sha256'] == claims['baseline']['candidate_sha256']
    base_map = unpacked(d / 'baseline/link.map.gz', tmp)
    windows = [{'start': w['start'], 'bytes': w['bytes']} for w in read(frontier / 'inventory.json.gz')['windows']]
    base = measure.inventory(base_elf, windows)
    keys = ('normalized', 'raw', 'unmatched', 'matched_text_bytes', 'raw_text_bytes')
    assert {k: base['counts'][k] for k in keys} == {k: claims['baseline'][k] for k in keys}
    assert (base['counts']['normalized'], base['counts']['raw'], base['counts']['matched_text_bytes']) == \
           (cp['normalized_windows'], cp['raw_windows'], cp['matched_text_bytes'])
    # 3. regenerate the script
    ordered, counts = derive_layout.plan(ROOT / 'evidence/original/pump/deployed.so', windows, base_elf, base_map)
    default = (P / 'tools/default.ld').read_text()
    script = layout_script.render(default, [layout_script.selector(x['owner'], x['section']) for x in ordered])
    saved = (d / 'ordered.ld').read_text()
    assert script == saved, 'ordered.ld is not the generator output'
    assert layout_script.check_script(default, saved) == len(ordered)
    # 4. ordered inventory
    ord_elf = unpacked(d / 'ordered/unstripped.so.gz', tmp)
    assert sha(ord_elf.read_bytes()) == claims['ordered']['unstripped_sha256']
    new = measure.inventory(ord_elf, windows)
    assert {k: new['counts'][k] for k in keys} == {k: claims['ordered'][k] for k in keys}
    norm = lambda inv: {w['start'] for w in inv['windows'] if w['normalized_matches']}
    raw = lambda inv: {w['start'] for w in inv['windows'] if w['raw_match']}
    assert norm(base) <= norm(new) and raw(base) <= raw(new), 'a match was lost'
    assert sorted(raw(new) - raw(base)) == claims['raw_gained_windows'] and not claims['raw_lost_windows']
    assert norm(new) == norm(base) and not claims['normalized_lost_windows']
    # 5. translation, residuals, blockers, pricing, disclosure
    omap = unpacked(d / 'ordered/link.map.gz', tmp)
    t = translation.check(base_elf, base_map, ord_elf, omap)
    assert t == claims['translation'], 'translation statistics differ'
    plan = {'sections': ordered}
    res = classify.classify(new, plan, ROOT / 'evidence/original/pump/deployed.so', ord_elf, omap)
    assert res['counts'] == claims['residual_classes'] and res['data_operands'] == claims['residual_data_operands']
    assert res['call_only_blockers'][:12] == claims['call_only_blockers_top12']
    u = unlock.compute(plan, windows, base_elf)
    assert u['call_only_raw_now'] == claims['unlock']['call_only_raw_now'] == new['counts']['raw']
    assert u['call_only_raw_if_all_neutral'] == claims['unlock']['raw_if_all_size_changing_windows_neutral']
    assert [{k: r[k] for k in ['region', 'bytes', 'raw_if_neutral', 'gain']} | {'windows': len(r['windows'])}
            for r in u['regions']] == claims['unlock']['regions']
    assert disclose.disclose(ordered, base) == claims['correspondence']
    # 6. stripped candidate (pure Python)
    stripped = unpacked(d / 'ordered/candidate.so.gz', tmp)
    assert sha(stripped.read_bytes()) == claims['ordered']['candidate_sha256']
    strip = strip_check(ord_elf, stripped)
    # 7. build or relink records
    if not claims['ordered_builds']:
        rl = read(d / 'ordered/relink.json')
        assert rl['unstripped_sha256'] == claims['ordered']['unstripped_sha256']
        assert rl['candidate_sha256'] == claims['ordered']['candidate_sha256'] and rl['script_sha256'] == sha(saved.encode())
    bb = read(d / 'baseline/build.json')
    assert bb['returncode'] == 0 and bb['source_unchanged'] and bb['linker_script_sha256'] is None
    assert bb['unstripped_sha256'] == cp['unstripped_sha256'] and bb['candidate_sha256'] == cp['candidate_sha256']
    primary = cp['primary_source_sha256']
    for record in [bb] + [read(d / 'ordered' / n) for n in claims['ordered_builds']]:
        assert all(record['primary_source_sha256'].get(k) == v for k, v in primary.items()), 'build did not compile the round source'
        assert set(record['primary_source_sha256']) - set(primary) <= {'README.md', 'recovered/README.md'}
    for n in claims['ordered_builds']:
        b = read(d / 'ordered' / n)
        assert b['returncode'] == 0 and b['source_unchanged'] and b['linker_script_sha256'] == sha(saved.encode())
        assert b['unstripped_sha256'] == claims['ordered']['unstripped_sha256'] and b['candidate_sha256'] == claims['ordered']['candidate_sha256']
    out = {'round': d.name, 'baseline_raw': base['counts']['raw'], 'ordered_raw': new['counts']['raw'],
           'normalized': new['counts']['normalized'], 'raw_gained': [hex(x) for x in sorted(raw(new) - raw(base))],
           'selectors': len(ordered), 'translation_sections': t['sections'], 'strip_check': strip,
           'evidence': ('builds: ' + ', '.join(claims['ordered_builds'])) if claims['ordered_builds'] else 'relink record'}
    # 8. runtime
    out['runtime'] = runtime_check(d, claims) if 'runtime' in claims else 'not recorded for this round'
    # 9. policy controls
    pc = d / 'policy-controls.json'
    if pc.is_file():
        controls = read(pc)
        assert controls['frontier_packet'] == claims['frontier_packet']
        for name, row in controls['controls'].items():
            o2, _ = derive_layout.plan(ROOT / 'evidence/original/pump/deployed.so', windows, base_elf, base_map, row['policy'])
            s2 = layout_script.render(default, [layout_script.selector(x['owner'], x['section']) for x in o2])
            assert sha(s2.encode()) == row['script_sha256'], name
            assert disclose.disclose(o2, base) == row['disclosure'], name
        adopted = controls['controls']['adopted']
        assert adopted['script_sha256'] == sha(saved.encode()) and adopted['unstripped_sha256'] == claims['ordered']['unstripped_sha256']
        assert adopted['raw'] == claims['ordered']['raw']
        out['policy_controls_regenerated'] = len(controls['controls'])
    return out


def verify_composed(rec_path):
    """A round published by the integration session with this generator's text order composed in."""
    rec = read(rec_path)
    R = ROOT / rec['frontier_packet']
    cp = read(R / 'CHECKPOINT.json')
    assert sha((R / rec['baseline_elf']).read_bytes()) == rec['baseline_elf_sha256']
    assert sha((R / 'unstripped.so').read_bytes()) == cp['unstripped_sha256'] == rec['published_unstripped_sha256']
    windows = [{'start': w['start'], 'bytes': w['bytes']} for w in read(R / 'inventory.json.gz')['windows']]
    ordered, _ = derive_layout.plan(ROOT / 'evidence/original/pump/deployed.so', windows, R / rec['baseline_elf'], R / rec['baseline_map'])
    script = layout_script.render((P / 'tools/default.ld').read_text(), [layout_script.selector(x['owner'], x['section']) for x in ordered])
    assert sha(script.encode()) == rec['text_order_sha256'] == sha((R / rec['text_order_script']).read_bytes()), 'text order not regenerated'
    base, pub = measure.inventory(R / rec['baseline_elf'], windows), measure.inventory(R / 'unstripped.so', windows)
    keys = ('normalized', 'raw', 'unmatched', 'matched_text_bytes', 'raw_text_bytes')
    assert {k: base['counts'][k] for k in keys} == rec['baseline'] and {k: pub['counts'][k] for k in keys} == rec['published']
    assert (pub['counts']['normalized'], pub['counts']['raw']) == (cp['normalized_windows'], cp['raw_windows'])
    rb = {w['start'] for w in base['windows'] if w['raw_match']}
    rp = {w['start']: w for w in pub['windows'] if w['raw_match']}
    assert sorted(set(rp) - rb) == rec['raw_gained_windows'] and sorted(rb - set(rp)) == rec['raw_lost_windows'] == []
    assert sorted(a for a, w in rp.items() if any(o['kind'] == 'elf-pointer' for o in w['original_operands'])) == \
           rec['published_raw_windows_with_data_operands']
    return {'composed_round': rec['frontier_packet'], 'baseline_raw': base['counts']['raw'], 'published_raw': pub['counts']['raw'],
            'normalized': pub['counts']['normalized'], 'text_order_regenerated': True}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--round', action='append', help='verify only these round directories (default: all)')
    a = ap.parse_args()
    manifest = read(P / 'MANIFEST.json')
    paths = list(P.rglob('*'))
    assert not any(f.is_symlink() for f in paths), 'packet includes a symlink'
    assert all(f.is_file() or f.is_dir() for f in paths), 'packet includes a special file'
    files = {f.relative_to(P).as_posix() for f in paths if f.is_file()}
    assert files == set(manifest) | {'MANIFEST.json'}, 'packet file inventory differs'
    for name, digest in manifest.items():
        assert sha((P / name).read_bytes()) == digest, name
    results = []
    with tempfile.TemporaryDirectory(prefix='layout-pump-verify-') as tmp:
        for d in sorted(P.glob('round*/')):
            if (d / 'claims.json').is_file() and (not a.round or d.name in a.round):
                results.append(verify_round(d, tmp))
        if not a.round:
            for rec in sorted(P.glob('round*-composed.json')):
                results.append(verify_composed(rec))
    assert results, 'no round verified'
    print(json.dumps({'verified': True, 'rounds': results}, indent=1))


if __name__ == '__main__':
    main()
