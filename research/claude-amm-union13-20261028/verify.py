#!/usr/bin/env python3
"""Audit this AMM union packet with the standard library only (no rebuild, no execution).

python3 -I -B research/<this packet>/verify.py
Checks exact packet membership and hashes, the source archive against the recorded staged inputs, source.patch
against the parent packet's archive, the two Linux builds (identical), the window measurement (recomputed from the
saved symbols for this candidate and for the parent packet's candidate against evidence/original/pump_amm/deployed.so),
and the bound reported runtime summaries, plus the five incentive error-order controls for both images (all equal).
The layout layer must keep every raw window of the parent packet's layout layer; its raw differences against this
packet's source-only image are recomputed and must equal the recorded lists."""
import difflib, gzip, hashlib, io, json, os, subprocess, sys, tarfile, tempfile, types
from pathlib import Path
P = Path(__file__).resolve().parent; ROOT = P.parents[1]
sha = lambda b: hashlib.sha256(b).hexdigest()
def j(rel): return json.loads((P / rel).read_text())
def fail(msg): raise SystemExit('FAIL: ' + msg)
def check(cond, msg):
    if not cond: fail(msg)
# 1. exact membership + hashes
actual = set()
for f in P.rglob('*'):
    if f.is_symlink() or not (f.is_file() or f.is_dir()): fail('special file ' + str(f))
    if f.is_file(): actual.add(f.relative_to(P).as_posix())
man = j('MANIFEST.json')['files']
check(actual == set(man) | {'MANIFEST.json'}, 'membership differs: %s' % sorted(actual ^ (set(man) | {'MANIFEST.json'})))
for rel, h in man.items(): check(sha((P / rel).read_bytes()) == h, 'hash ' + rel)
PINFO = j('measurement.json')['parent']; PARENT = ROOT / PINFO['packet']
# 2. source archive == recorded staged inputs (the tree the builds mounted)
recipe = j('builds/recipe.json'); staged = recipe['staged_inputs']
def members(path):
    t = tarfile.open(fileobj=io.BytesIO(Path(path).read_bytes()))
    out = {}
    for m in t.getmembers():
        check(m.isfile() and not m.name.startswith('/') and '..' not in m.name.split('/'), 'archive member ' + m.name)
        out[m.name] = t.extractfile(m).read()
    return out
cand = members(P / 'sources/candidate.tar.gz')
check({k: sha(v) for k, v in cand.items()} == staged, 'candidate archive != staged inputs')
# 3. source.patch == diff(parent packet archive -> candidate archive)
par = members(PARENT / PINFO['sources'])
out = []
for rel in sorted(set(par) | set(cand)):
    a, b = par.get(rel), cand.get(rel)
    if a == b: continue
    al = a.decode().splitlines(keepends=True) if a is not None else []
    bl = b.decode().splitlines(keepends=True) if b is not None else []
    for line in difflib.unified_diff(al, bl, 'a/' + rel if a is not None else '/dev/null', 'b/' + rel if b is not None else '/dev/null', n=3):
        out.append(line if line.endswith('\n') else line + '\n\\ No newline at end of file\n')
check(''.join(out) == (P / 'source.patch').read_text(), 'source.patch does not reproduce')
ch = j('source-changes.json')
check(ch['modified'] == sorted(r for r in cand if r in par and par[r] != cand[r]) and ch['added'] == sorted(set(cand) - set(par)) and ch['removed'] == sorted(set(par) - set(cand)), 'source-changes.json')
# 4. builds a/b identical, recorded hashes
blobs = {}
for name in 'ab':
    r = j('builds/%s/result.json' % name)
    s = gzip.decompress((P / ('builds/%s/symbols.so.gz' % name)).read_bytes()); c = gzip.decompress((P / ('builds/%s/candidate.so.gz' % name)).read_bytes())
    check(sha(s) == r['symbols_sha256'] and sha(c) == r['candidate_sha256'], 'build %s hashes' % name)
    check(r['root_invocations'] == 1 and set(r['compiled']) == {'native-transfer-fee v0.1.0', 'pump-amm-recovered v0.1.0'}, 'build %s compiled set' % name)
    blobs[name] = (s, c)
check(blobs['a'] == blobs['b'], 'builds a and b differ')
# 5. measurement recomputed for candidate and parent
m = types.ModuleType('measure'); mp = P / 'tools/measure.py'; m.__file__ = str(mp); exec(compile(mp.read_bytes(), str(mp), 'exec'), m.__dict__)
orig = ROOT / 'evidence/original/pump_amm/deployed.so'
meas = j('measurement.json'); check(sha(orig.read_bytes()) == meas['original_sha256'], 'original hash')
with tempfile.TemporaryDirectory() as td:
    cs = Path(td) / 'candidate.so'; cs.write_bytes(blobs['a'][0])
    ps = Path(td) / 'parent.so'; ps.write_bytes(gzip.decompress((PARENT / PINFO['symbols']).read_bytes()))
    rc = m.measure(orig, cs); rp = m.measure(orig, ps)
    psha = sha(ps.read_bytes())
k = lambda x: int(x, 16)
cn = {r['original'] for r in rc if r['match']}; cr = {r['original'] for r in rc if r['raw']}
pn = {r['original'] for r in rp if r['match']}; pr = {r['original'] for r in rp if r['raw']}
check(meas['parent']['symbols_sha256'] == psha and meas['parent']['normalized'] == len(pn) and meas['parent']['raw'] == len(pr), 'parent measurement')
check(meas['candidate']['normalized'] == len(cn) and meas['candidate']['raw'] == len(cr) and meas['windows'] == len(rc), 'candidate measurement')
check(meas['normalized_gains'] == sorted(cn - pn, key=k) and meas['normalized_losses'] == sorted(pn - cn, key=k) == [], 'normalized gains/losses')
check(meas['raw_gains'] == sorted(cr - pr, key=k) and meas['raw_losses'] == sorted(pr - cr, key=k) == [], 'raw gains/losses')
check(meas['windows_detail'] == [[r['original'], r['bytes'], r['match'], r['raw']] for r in rc], 'per-window detail')
# 6. runtime summary bound to builds/a and the repository harness
s = j('runtime/summary.json'); rows = j('runtime/suites.json'); inp = j('runtime/inputs.json')
check(s['candidate_sha256'] == sha(blobs['a'][1]) == inp['candidate_sha256'], 'runtime candidate binding')
check(s['original_sha256'] == meas['original_sha256'], 'runtime original binding')
check(s['suites'] == len(rows) == 25 and s['cases'] == sum(r['case_count'] for r in rows) == 17462 and s['mismatches'] == [], 'runtime totals')
check(all(r['returncode'] == 0 and not r['mismatches'] for r in rows), 'runtime suite failures')
check(s['transactions'] == sum(r['transactions'] for r in rows) and s['signatures'] == sum(r['signatures'] for r in rows), 'runtime tx totals')
check(s['replay_driver_sha256'] == sha((P / 'runtime/replay_parallel.py').read_bytes()), 'replay driver hash')
check(s['observer_sha256'] == sha((ROOT / 'repro/pump_amm/owner6048-v144/runtime/observe_suite.py').read_bytes()), 'observer hash')
for name, h in s['harness_sha256'].items(): check(sha((ROOT / name).read_bytes()) == h, 'harness ' + name)
# 7. optional layout layer (generated linker order): identical builds, same normalized set, regenerated ordered.ld, runtime
lay_out = {}
if 'layout' in meas:
    L = meas['layout']
    lb = {}
    for name in 'ab':
        r = j('layout/builds/%s/result.json' % name)
        s2 = gzip.decompress((P / ('layout/builds/%s/symbols.so.gz' % name)).read_bytes()); c2 = gzip.decompress((P / ('layout/builds/%s/candidate.so.gz' % name)).read_bytes())
        check(sha(s2) == r['symbols_sha256'] and sha(c2) == r['candidate_sha256'] and r['root_invocations'] == 1, 'layout build %s' % name)
        lb[name] = (s2, c2)
    check(lb['a'] == lb['b'], 'layout builds differ')
    with tempfile.TemporaryDirectory() as td:
        ls_ = Path(td) / 'layout.so'; ls_.write_bytes(lb['a'][0])
        rl = m.measure(orig, ls_)
        mp = Path(td) / 'link.map'; mp.write_bytes(gzip.decompress((P / 'layout/link-map.txt.gz').read_bytes()))
        so = Path(td) / 'source.so'; so.write_bytes(blobs['a'][0])
        ld = Path(td) / 'ordered.ld'
        r = subprocess.run([sys.executable, '-I', '-B', str(P / 'tools/lay.py'), str(so), str(mp), '--ld', str(ld), '--mode', 'order'], capture_output=True, text=True)
        check(r.returncode == 0, 'lay.py failed: ' + r.stderr[-300:])
        check(ld.read_bytes() == (P / 'layout/ordered.ld').read_bytes(), 'ordered.ld does not regenerate from the source-only build + link map')
    ln = {x['original'] for x in rl if x['match']}; lr = {x['original'] for x in rl if x['raw']}
    check(ln == cn and L['normalized_equal_to_source_only'] is True and L['normalized'] == len(ln), 'layout normalized set')
    check(L['raw'] == len(lr) and L['raw_gains_vs_source_only'] == sorted(lr - cr, key=k) and L['raw_losses_vs_source_only'] == sorted(cr - lr, key=k), 'layout raw')
    # the layout layer must keep every raw window of the parent packet's own layout layer (losses against this packet's
    # source-only image are recorded exactly above and listed in the README)
    with tempfile.TemporaryDirectory() as td:
        pl = Path(td) / 'parent-layout.so'; pl.write_bytes(gzip.decompress((PARENT / L['parent_layout']['symbols']).read_bytes()))
        plsha = sha(pl.read_bytes()); plr = {x['original'] for x in m.measure(orig, pl) if x['raw']}
    check(L['parent_layout']['symbols_sha256'] == plsha and L['parent_layout']['raw'] == len(plr) and L['raw_gains_vs_parent_layout'] == sorted(lr - plr, key=k)
          and L['raw_losses_vs_parent_layout'] == sorted(plr - lr, key=k) == [], 'layout raw vs parent layout layer')
    s3 = j('layout/runtime/summary.json'); rows3 = j('layout/runtime/suites.json')
    check(s3['candidate_sha256'] == sha(lb['a'][1]) and s3['suites'] == len(rows3) == 25 and s3['cases'] == 17462 and s3['mismatches'] == [], 'layout runtime')
    check(all(x['returncode'] == 0 and not x['mismatches'] for x in rows3), 'layout runtime suites')
    for name, h in s3['harness_sha256'].items(): check(sha((ROOT / name).read_bytes()) == h, 'layout harness ' + name)
    lay_out = {'layout_normalized': len(ln), 'layout_raw': len(lr), 'layout_candidate_sha256': sha(lb['a'][1]), 'layout_reported_runtime_cases': s3['cases'],
               'layout_raw_losses_vs_source_only': L['raw_losses_vs_source_only'], 'parent_layout_raw': len(plr), 'layout_raw_losses_vs_parent_layout': []}
negmod = types.ModuleType('negative_verify'); negpath = P / 'negative/verify.py'; negmod.__file__ = str(negpath); exec(compile(negpath.read_bytes(), str(negpath), 'exec'), negmod.__dict__)
negative = negmod.verify(P,validate_packet=False)
check(negative['cases'] == 10 and negative['mismatches'] == 0 and all(x['mismatches'] == 0 for x in negative['images'].values()), 'error-order controls for both current images')
print(json.dumps({'status': 'PASS', 'qualification': 'static_research', 'eligible_for_maintained_promotion': False, 'packet': P.name, 'normalized': len(cn), 'raw': len(cr), 'windows': len(rc),
                  'parent_normalized': len(pn), 'parent_raw': len(pr), 'gains': len(cn - pn), 'raw_gains': len(cr - pr), 'losses': 0,
                  'candidate_sha256': sha(blobs['a'][1]), 'symbols_sha256': sha(blobs['a'][0]),
                  'reported_runtime_cases': s['cases'], 'reported_runtime_mismatches': 0, 'independently_verified_reported_runtime': False, 'negative_controls': negative, **lay_out}))
