#!/usr/bin/env python3
"""Standard-library verifier for the fees-final Mayhem O0073 packet.

    HOME=$(mktemp -d) python3 -B research/claude-fees-final-mayhem-o0073/verify.py

Reads nothing outside this packet directory; touches no toolchain and no HOME. Checks:
  1. SHA256SUMS.txt lists exactly the files present (itself excluded) and every hash matches.
  2. The parent `fee_recipients.rs` equals the canonical 432 source
     (research/mayhem-quotes-current-recovery-20261027/source-inputs.json digest), and the
     shipped `fee_recipients.rs` differs from it ONLY inside validate_sweep (lines 46-64),
     with the file's total line count unchanged. source.patch is exactly that unified diff.
  3. The gzipped ELFs decompress to the digests recorded in build-result.json; the build
     exited 0 with sources/tools/target-libs unchanged and no "exceeded max offset" warning.
  4. measure-vs-parent432.json: O0073 is the only gain, there are no losses of any kind, and
     the normalized count went 432 -> 433; its candidate digest is the shipped symbols ELF.
  5. The mbcp2 composition measurement also gains O0073 with no losses (call-site robustness).
  6. Runtime receipts, all bound by digest to the shipped stripped ELF and the deployed original:
     a. stock sweep suite (692 cases): state/errors/events/CPIs/return data recomputed equal;
     b. the same suite on the 432 parent: the shipped ELF behaves exactly like the parent on every
        case (logs modulo compute units included), so the 58 log-only differences from the original
        (sweep-handler diagnostic origins, none in validate_sweep) pre-exist and none are new;
     c. targeted rate-limit differential (856 cases, the committed driver): every branch of the
        changed body (pass+write, SweepFeeRateLimit at :61, add-overflow panic at :58:32) equal to
        the original, logs included, and identical to the parent;
     d. trade summary (14 families, 6,636 cases): 0 mismatches, 0 non-compute log differences.
  7. composition-cp4/: the same source.patch on the current frontier (mayhem-b cp4-q04-o0075,
     433/441, merged in PR #390): cp4 reproduced bit-for-bit, the composed build gains only O0073
     (433 -> 434, no losses), equals the original on every stock and rate-limit case including
     logs, behaves exactly like cp4 everywhere, and its trade suites show 0 mismatches.
"""
import gzip, hashlib, json, re, sys
from pathlib import Path

if not __debug__:
    raise SystemExit('run with assertions enabled')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CANON_PARENT_FEE_RECIPIENTS = 'b9b5e5008f4d22240130791516d7c001cb07740f651149b43ded11e1fd6f3aab'
CAND = 'c8fb565e5becdb7b153f631d797545d8cf7642bb404fe272dc280de0b2222d03'
SYMS = '63a501e0180b50ae6e255471f13fd8721a183fbadfccfa045568d9f98c8b16da'
sha = lambda b: hashlib.sha256(b).hexdigest()
raw = lambda p: gzip.decompress(p.read_bytes()) if p.suffix == '.gz' else p.read_bytes()
ok = []


def check(cond, msg):
    assert cond, 'FAIL: ' + msg
    ok.append(msg)


# 1. manifest
sums = {}
for line in (HERE / 'SHA256SUMS.txt').read_text().splitlines():
    if line.strip():
        h, name = line.split(None, 1)
        sums[name.strip()] = h
present = {str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file() and p.name != 'SHA256SUMS.txt'}
check(present == set(sums), f'manifest lists exactly the files present ({len(present)})')
for name, h in sums.items():
    check(sha((HERE / name).read_bytes()) == h, f'sha256 {name}')

# 2. source
parent = (HERE / 'sources/fee_recipients.parent.rs').read_bytes()
final = (HERE / 'sources/fee_recipients.rs').read_bytes()
check(sha(parent) == CANON_PARENT_FEE_RECIPIENTS, 'parent fee_recipients.rs == canonical 432 digest')
pl, fl = parent.decode().split('\n'), final.decode().split('\n')
check(len(pl) == len(fl), f'line count unchanged ({len(pl)})')
changed = [i + 1 for i, (a, b) in enumerate(zip(pl, fl)) if a != b]
check(changed and all(46 <= n <= 64 for n in changed), f'changes confined to validate_sweep body lines 46-64: {changed}')


def apply_unified(src_lines, patch_text):
    """Apply a single-file unified diff (space/-/+ hunk lines) to src_lines -> new lines."""
    out, i, lines = [], 0, patch_text.splitlines()
    k = 0
    while k < len(lines) and not lines[k].startswith('@@'):
        k += 1
    for j in range(k, len(lines)):
        ln = lines[j]
        if ln.startswith('@@'):
            m = re.match(r'@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@', ln)
            start = int(m.group(1)) - 1
            out += src_lines[i:start]; i = start
        elif ln.startswith(' '):
            assert src_lines[i] == ln[1:], (i, src_lines[i], ln[1:]); out.append(src_lines[i]); i += 1
        elif ln.startswith('-'):
            assert src_lines[i] == ln[1:], (i, src_lines[i], ln[1:]); i += 1
        elif ln.startswith('+'):
            out.append(ln[1:])
    out += src_lines[i:]
    return out


applied = apply_unified(pl, (HERE / 'source.patch').read_text())
check(applied == fl, 'source.patch applied to the parent reproduces the shipped file')

# 3. ELFs + build
br = json.loads((HERE / 'builds/build-result.json').read_text())
check(sha(raw(HERE / 'builds/candidate.so.gz')) == CAND == br['candidate_sha256'], 'candidate.so.gz == recorded stripped digest')
check(sha(raw(HERE / 'builds/symbols.so.gz')) == SYMS == br['symbols_sha256'], 'symbols.so.gz == recorded symbols digest')
check(br['returncode'] == 0 and br['source_unchanged'] and br['tools_unchanged'] and br['target_libraries_unchanged'],
      'build exited 0 with inputs unchanged')
stderr = raw(HERE / 'builds/build-stderr.gz').decode('utf-8', 'replace')
check('exceeded max offset' not in stderr, 'no stack-offset-exceeded warning')

# 4. measurement vs parent-432
m = json.loads((HERE / 'measurement/measure-vs-parent432.json').read_text())
check(m['gains'] == ['O0073'], 'O0073 is the only normalized gain')
check(m['no_losses'] and not m['raw_losses'], 'no losses of any kind (body/raw/edge/source/profile)')
check(m['counts']['matched_before'] == 432 and m['counts']['matched_after'] == 433, '432 -> 433 normalized windows')
check(m['candidate_symbols_sha256'] == SYMS, 'measurement is bound to the shipped symbols ELF')

# 5. composition on mayhem-b cp2 tree
mc = json.loads((HERE / 'measurement/measure-mbcp2-composition.json').read_text())
check(mc['gains'] == ['O0073'] and mc['no_losses'], 'mbcp2 composition also gains O0073 with no losses')

# 6. runtime
CU = re.compile(r'consumed \d+ of \d+ compute units')
ORIGINAL = 'a87fa9f866272514e6acb852b668c4a08aeb173d56c883039991d114d1199bdb'  # evidence/original/mayhem/deployed.so


PARENT_CAND = '73dff97e65535ce7d2552ba6f29f94fe0e08ebd414a51871a81c6cba2d7d6168'  # 432 parent, stripped
FIELDS = ['error', 'accounts', 'events', 'inner', 'return_data']  # the harness's own equality


def state(r):
    return {k: r[k] for k in FIELDS}


def logs(r):
    return [CU.sub('consumed <cu>', x) for x in r['logs']]


# 6a. stock sweep suite (scripts/mayhem_validate_sweeps.py): shipped ELF vs the deployed original
sw = json.loads(raw(HERE / 'runtime/sweeps-differential.json.gz'))
check(sw['candidate_sha256'] == CAND and sw['original_sha256'] == ORIGINAL,
      'stock sweep receipt: shipped stripped ELF vs the deployed Mayhem original')
check(sw['case_count'] == len(sw['cases']) == 692 and sw['mismatches'] == [], 'stock sweep: 692 cases, 0 recorded mismatches')
check(all(state(c['original']) == state(c['candidate']) and c['equal'] for c in sw['cases']),
      'stock sweep recomputed here: state, errors, events, CPIs, return data equal on all 692')
log_diffs = [i for i, c in enumerate(sw['cases']) if logs(c['original']) != logs(c['candidate'])]

# 6b. the same suite on the 432 parent: the log-only differences pre-exist and this patch changes nothing
pw = json.loads(raw(HERE / 'runtime/sweeps-parent432.json.gz'))
check(pw['candidate_sha256'] == PARENT_CAND and pw['original_sha256'] == ORIGINAL, 'parent sweep receipt: 432 parent ELF vs the same original')
check([c['case'] for c in pw['cases']] == [c['case'] for c in sw['cases']], 'parent and shipped runs use the identical 692 cases')
check(all(state(a['original']) == state(b['original']) and logs(a['original']) == logs(b['original'])
          for a, b in zip(sw['cases'], pw['cases'])), 'original side identical across the two runs')
check(all(state(a['candidate']) == state(b['candidate']) and logs(a['candidate']) == logs(b['candidate'])
          for a, b in zip(sw['cases'], pw['cases'])), 'shipped ELF behaves exactly like the 432 parent on all 692 (incl. logs mod CU)')
parent_log_diffs = [i for i, c in enumerate(pw['cases']) if logs(c['original']) != logs(c['candidate'])]
check(log_diffs == parent_log_diffs and len(log_diffs) == 58,
      'the 58 log-only differences (sweep-handler diagnostic origins) are identical in the parent: none introduced')
check(not any(re.search(r'fee_recipients\.rs:(47|58|61)\b', x) for i in log_diffs
              for x in sw['cases'][i]['original']['logs'] + sw['cases'][i]['candidate']['logs']),
      'no log-only difference involves validate_sweep (fee_recipients.rs:47/58/61)')

# 6c. targeted rate-limit differential (the stock suite never runs validate_sweep's body)
rl = json.loads(raw(HERE / 'runtime/ratelimit-differential.json.gz'))
check(rl['candidate_sha256'] == CAND and rl['original_sha256'] == ORIGINAL and rl['parent_sha256'] == PARENT_CAND,
      'rate-limit receipt: shipped ELF and parent vs the deployed original')
check(rl['harness_sha256']['driver'] == sha((HERE / 'tools/o73_ratelimit_differential.py').read_bytes()),
      'rate-limit receipt produced by the committed driver')
check(rl['case_count'] == len(rl['cases']) == 856 and rl['mismatches'] == [] and rl['log_differences_modulo_cu'] == []
      and rl['candidate_vs_parent_differences'] == [], 'rate-limit: 856 cases, 0 mismatches, 0 log diffs, 0 differences from parent')
check(all(state(c['original']) == state(c['candidate']) and logs(c['original']) == logs(c['candidate']) for c in rl['cases']),
      'rate-limit recomputed here: every case equal incl. logs mod CU')
oc = rl['original_outcomes']
check(oc.get('ok', 0) > 0 and oc.get('AnchorError fee_recipients.rs:61', 0) > 0 and oc.get('panic fee_recipients.rs:58:32', 0) > 0,
      f'rate-limit cases reach every branch of the changed body: {oc}')
t = json.loads((HERE / 'runtime/trades-summary.json').read_text())
check(t['candidate_sha256'] == CAND, 'trade summary bound to the shipped stripped ELF')
runs = t['runs']
check(len(runs) == 14 and all(r['returncode'] == 0 and r['cases'] == r['expected_cases'] and r['mismatches'] == 0
                                and r['noncompute_log_diffs'] == 0 for r in runs), 'trade suites: 14 families exit 0, full case counts, 0 mismatches')
check(sum(r['cases'] for r in runs) == t['total_cases'] == 6636 and t['total_mismatches'] == 0
      and t['total_noncompute_log_diffs'] == 0 and t['all_ok'], 'trade suites: 6636 cases, 0 mismatches, 0 non-compute log diffs')

# 7. composition onto the current Mayhem frontier: mayhem-b cp4-q04-o0075 (433/441, merged as PR #390)
K = HERE / 'composition-cp4'
CP4_FEE_RECIPIENTS = 'aa37caaae36f21fadf48b033866ff1a7529b4fb5f123c8ea7f40c73a2b650172'  # cp4 source-inputs.json
CP4_CAND = 'c1f25d01e61fcfb93f9068ef9a61566a9fd31b61eb37a8d745ca7e49948f5b31'  # cp4 ELF-SHA256.txt
CP4_SYMS = '73c28d5e51d16b21868ed975993aaca51ce49ef024ca9f3afbafeaa3c0306e2e'
COMP_CAND = 'e0d0d0c34e2db5463b5bb85b30a5240fec0ed3fcf46c8f9b395ae86d2e6cc37f'
COMP_SYMS = '828751f913dc547b8e6b2474852b37832d0718595f0f69be8eca8dfcfa091b1d'
cp4 = (K / 'fee_recipients.cp4.rs').read_bytes()
comp = (K / 'fee_recipients.rs').read_bytes()
check(sha(cp4) == CP4_FEE_RECIPIENTS, 'cp4 fee_recipients.rs == its canonical source-inputs digest')
c4l, cpl = cp4.decode().split('\n'), comp.decode().split('\n')
check(len(c4l) == len(cpl) and all(46 <= i + 1 <= 64 for i, (a, b) in enumerate(zip(c4l, cpl)) if a != b),
      'composition changes only validate_sweep (46-64) of the cp4 file, line count unchanged')
check(apply_unified(c4l, (HERE / 'source.patch').read_text()) == cpl, 'the same source.patch applies to cp4 and yields the composed file')
cb = json.loads((K / 'build-result.json').read_text())
check(sha(raw(K / 'candidate.so.gz')) == COMP_CAND == cb['candidate_sha256'] and sha(raw(K / 'symbols.so.gz')) == COMP_SYMS == cb['symbols_sha256'],
      'composed ELFs == recorded build digests')
check(cb['returncode'] == 0 and cb['source_unchanged'] and cb['tools_unchanged'] and cb['target_libraries_unchanged']
      and 'exceeded max offset' not in raw(K / 'build-stderr.gz').decode('utf-8', 'replace'), 'composed build exit 0, inputs unchanged, no stack warning')
rb = json.loads((K / 'cp4-repro-build-result.json').read_text())
check(rb['candidate_sha256'] == CP4_CAND and rb['symbols_sha256'] == CP4_SYMS, 'cp4 base reproduced bit-for-bit in this environment')
m4 = json.loads((K / 'measure-vs-cp4.json').read_text())
check(m4['gains'] == ['O0073'] and m4['no_losses'] and not m4['raw_losses'] and m4['candidate_symbols_sha256'] == COMP_SYMS
      and (m4['counts']['matched_before'], m4['counts']['matched_after']) == (433, 434), 'vs cp4: O0073 only gain, no losses, 433 -> 434')
m2 = json.loads((K / 'measure-vs-parent432.json').read_text())
check(sorted(m2['gains']) == ['O0073', 'O0075'] and m2['no_losses'] and (m2['counts']['matched_before'], m2['counts']['matched_after']) == (432, 434),
      'vs the 432 parent: O0073 + O0075, no losses, 432 -> 434')
cs = json.loads(raw(K / 'sweeps-differential.json.gz'))
bs = json.loads(raw(K / 'sweeps-cp4.json.gz'))
check(cs['candidate_sha256'] == COMP_CAND and bs['candidate_sha256'] == CP4_CAND and cs['original_sha256'] == bs['original_sha256'] == ORIGINAL,
      'composition and cp4 sweep receipts bound to their ELFs and the original')
check([c['case'] for c in cs['cases']] == [c['case'] for c in bs['cases']] and cs['case_count'] == 692 and cs['mismatches'] == [] == bs['mismatches'],
      'composition stock sweep: same 692 cases as cp4, 0 mismatches')
check(all(state(c['original']) == state(c['candidate']) and logs(c['original']) == logs(c['candidate']) for c in cs['cases']),
      'composition equals the original on all 692 stock cases, logs included (mod CU)')
check(all(state(a['candidate']) == state(b['candidate']) and logs(a['candidate']) == logs(b['candidate'])
          for a, b in zip(cs['cases'], bs['cases'])), 'composition behaves exactly like cp4 on all 692')
cr = json.loads(raw(K / 'ratelimit-differential.json.gz'))
check(cr['candidate_sha256'] == COMP_CAND and cr['parent_sha256'] == CP4_CAND and cr['original_sha256'] == ORIGINAL
      and cr['harness_sha256']['driver'] == sha((HERE / 'tools/o73_ratelimit_differential.py').read_bytes()), 'composition rate-limit receipt bound')
check(cr['case_count'] == len(cr['cases']) == 856 and cr['mismatches'] == [] == cr['log_differences_modulo_cu'] == cr['candidate_vs_parent_differences']
      and all(state(c['original']) == state(c['candidate']) and logs(c['original']) == logs(c['candidate']) for c in cr['cases']),
      'composition rate-limit: 856 cases equal to the original incl. logs, identical to cp4')
t = json.loads((K / 'trades-summary.json').read_text())
check(t['candidate_sha256'] == COMP_CAND and t['all_ok'] and t['total_mismatches'] == 0 and t['total_noncompute_log_diffs'] == 0
      and len(t['runs']) == 14 and all(r['returncode'] == 0 and r['cases'] == r['expected_cases'] and r['mismatches'] == 0
                                       and r['noncompute_log_diffs'] == 0 for r in t['runs'])
      and sum(r['cases'] for r in t['runs']) == t['total_cases'] == 6636,
      'composition trade suites: 14 families, 6636 cases, 0 mismatches, 0 non-compute log diffs')

print('\n'.join('  OK  ' + m for m in ok))
print(f'\nPASS — {len(ok)} checks')
