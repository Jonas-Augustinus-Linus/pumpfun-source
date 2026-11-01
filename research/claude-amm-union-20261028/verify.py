#!/usr/bin/env python3
"""Audit research/claude-amm-union-20261028 with the standard library only (no rebuild, no execution).

python3 -I -B research/claude-amm-union-20261028/verify.py
Checks exact packet membership and hashes, the source archive against the recorded staged inputs, source.patch
against the parent packet's archive, the two Linux builds (identical), the window measurement (recomputed from the
saved symbols for this candidate and for the parent packet's candidate against evidence/original/pump_amm/deployed.so),
and the bound 25-suite runtime summary."""
import difflib, gzip, hashlib, io, json, os, tarfile, tempfile, types
from pathlib import Path
P = Path(__file__).resolve().parent; ROOT = P.parents[1]
PARENT = ROOT / 'research/amm-fee-value-call-recovery'
sha = lambda b: hashlib.sha256(b).hexdigest()
def j(rel): return json.loads((P / rel).read_text())
def fail(msg): raise SystemExit('FAIL: ' + msg)
def check(cond, msg):
    if not cond: fail(msg)
# 1. exact membership + hashes
man = j('MANIFEST.json')['files']
actual = set()
for f in P.rglob('*'):
    if f.is_symlink() or not (f.is_file() or f.is_dir()): fail('special file ' + str(f))
    if f.is_file(): actual.add(f.relative_to(P).as_posix())
check(actual == set(man) | {'MANIFEST.json'}, 'membership differs: %s' % sorted(actual ^ (set(man) | {'MANIFEST.json'})))
for rel, h in man.items(): check(sha((P / rel).read_bytes()) == h, 'hash ' + rel)
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
par = members(PARENT / 'sources/candidate.tar.gz')
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
    ps = Path(td) / 'parent.so'; ps.write_bytes(gzip.decompress((PARENT / 'builds/candidate/symbols.so.gz').read_bytes()))
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
print(json.dumps({'status': 'PASS', 'packet': P.name, 'normalized': len(cn), 'raw': len(cr), 'windows': len(rc),
                  'parent_normalized': len(pn), 'parent_raw': len(pr), 'gains': len(cn - pn), 'raw_gains': len(cr - pr), 'losses': 0,
                  'candidate_sha256': sha(blobs['a'][1]), 'symbols_sha256': sha(blobs['a'][0]),
                  'runtime_cases': s['cases'], 'runtime_mismatches': 0}))
