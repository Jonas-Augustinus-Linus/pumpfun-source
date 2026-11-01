#!/usr/bin/env python3
"""Standard-library verifier for the Mayhem 436/441 packet (O0081 + O0082 closures).

    HOME=$(mktemp -d) python3 -B research/claude-mayhem-436-20261027/verify.py

Reads only this packet directory, plus (when present, i.e. in a checkout of the repo) the two
main-branch files that define the parent-434 tree. Touches no toolchain and no HOME. Checks:
  1. SHA256SUMS.txt lists exactly the files present (itself excluded) and every hash matches.
  2. Parent tree: sources/source-inputs.parent434.json is the tree shipped on main by PR #397
     (cp4-q04-o0075 source-inputs.json with fee_recipients.rs replaced by the O0073
     composition-cp4 file); every sources/parent/* file matches it. source.patch applied to the
     parent files reproduces sources/shipped/*, the shipped files match
     sources/source-inputs.json, and the two inventories differ in exactly the six patched files.
     Line counts are preserved everywhere except pump_interface.rs, which only loses the
     now-unused trailing `legacy_price_check` helper (all earlier lines keep their line:column).
  3. The gzipped ELFs decompress to the digests recorded in build-result.json; two clean builds
     (fresh target dirs, anchor re-cleaned) produced identical stripped and symbols ELFs; both
     exited 0 with sources/tools/target libraries unchanged and no stack-offset warning.
  4. measure-vs-parent434.json: gains exactly [O0081, O0082], no losses of any kind, 434 -> 436,
     the five remaining unmatched windows are O0076 O0077 O0079 O0083 O0084, bound to the
     shipped symbols ELF. measure-vs-parent433.json: gains [O0073, O0081, O0082], no losses.
  5. Runtime receipts bound to the shipped stripped ELF and the deployed original:
     a. stock sweep suite (692 cases): state/errors/events/CPIs/return data and logs (mod compute
        units) recomputed equal to the original on every case;
     b. trade suites (14 families, 6,636 cases): exit 0, full case counts, 0 mismatches,
        0 non-compute log differences.
"""
import gzip, hashlib, json, re, sys
from pathlib import Path

if not __debug__:
    raise SystemExit('run with assertions enabled')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CAND = 'e93b60f1001c5bc65d4c24b3b3e727d52fb887b9a671c1bd5f7863e27c65ef93'
SYMS = '49d70dc773147690f6b0995c0b1f2c0620741262c2809b34337e3314b6b30f38'
PARENT434_SYMS = '828751f913dc547b8e6b2474852b37832d0718595f0f69be8eca8dfcfa091b1d'
ORIGINAL = 'a87fa9f866272514e6acb852b668c4a08aeb173d56c883039991d114d1199bdb'  # evidence/original/mayhem/deployed.so
CP4_INPUTS = 'research/claude-mayhem-b-20261027/checkpoints/cp4-q04-o0075/source-inputs.json'
O73_FEE = 'research/claude-fees-final-mayhem-o0073/composition-cp4/fee_recipients.rs'
O73_FEE_SHA = '53fe2d86'  # prefix recorded in the parent-434 provenance note
PATCHED = ['src/instructions/buy_pump_swap.rs', 'src/instructions/buy_v2.rs', 'src/instructions/pump_interface.rs',
           'src/instructions/pump_interface_v2.rs', 'src/instructions/sell_pump_swap.rs', 'src/state.rs']
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
present = {p.relative_to(HERE).as_posix() for p in HERE.rglob('*') if p.is_file() and p.name != 'SHA256SUMS.txt'}
check(present == set(sums), f'manifest lists exactly the files present ({len(present)})')
for name, h in sorted(sums.items()):
    check(sha((HERE / name).read_bytes()) == h, f'sha256 {name}')

# 2. sources
pinv = json.loads((HERE / 'sources/source-inputs.parent434.json').read_text())
sinv = json.loads((HERE / 'sources/source-inputs.json').read_text())
check(len(pinv) == len(sinv) == 67, 'parent and shipped inventories list the 67 crate inputs')
check(sorted(k for k in pinv if pinv[k] != sinv.get(k)) == sorted(PATCHED) and set(pinv) == set(sinv),
      'the 436 tree differs from parent-434 in exactly the six patched files')
check(pinv['src/instructions/fee_recipients.rs'].startswith(O73_FEE_SHA), 'parent-434 carries the O0073 fee_recipients.rs (53fe2d86...)')
if (REPO / CP4_INPUTS).is_file() and (REPO / O73_FEE).is_file():
    main_tree = json.loads((REPO / CP4_INPUTS).read_text())
    main_tree['src/instructions/fee_recipients.rs'] = sha((REPO / O73_FEE).read_bytes())
    check(main_tree == pinv, 'parent-434 inventory == main tree (cp4 source-inputs + #397 composition fee_recipients.rs)')
else:
    print('  note: repo files for the main parent-434 cross-check not found; skipped')


def apply_unified(src_lines, hunks):
    out, i = [], 0
    for ln in hunks:
        if ln.startswith('@@'):
            start = int(re.match(r'@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@', ln).group(1)) - 1
            out += src_lines[i:start]; i = start
        elif ln.startswith(' ') or ln == '':
            body = ln[1:] if ln else ''
            assert src_lines[i] == body, (i, src_lines[i], body); out.append(src_lines[i]); i += 1
        elif ln.startswith('-'):
            assert src_lines[i] == ln[1:], (i, src_lines[i], ln[1:]); i += 1
        elif ln.startswith('+'):
            out.append(ln[1:])
        elif ln.startswith('\\'):
            pass
    return out + src_lines[i:]


patch = (HERE / 'source.patch').read_text().split('\n')
per_file, cur = {}, None
for ln in patch:
    if ln.startswith('diff '):
        cur = None
    elif ln.startswith('--- a/programs/mayhem/'):
        continue
    elif ln.startswith('+++ b/programs/mayhem/'):
        cur = ln[len('+++ b/programs/mayhem/'):]; per_file[cur] = []
    elif cur is not None:
        per_file[cur].append(ln)
check(sorted(per_file) == sorted(PATCHED), 'source.patch touches exactly the six patched files')
for rel in PATCHED:
    short = rel[len('src/'):]
    pb, sb = (HERE / 'sources/parent' / short).read_bytes(), (HERE / 'sources/shipped' / short).read_bytes()
    check(sha(pb) == pinv[rel], f'sources/parent/{short} == parent-434 digest')
    check(sha(sb) == sinv[rel], f'sources/shipped/{short} == shipped digest')
    hunks = per_file[rel]
    while hunks and hunks[-1] == '':
        hunks = hunks[:-1]
    check(apply_unified(pb.decode().split('\n'), hunks) == sb.decode().split('\n'), f'source.patch reproduces {short}')
    pl, sl = pb.decode().split('\n'), sb.decode().split('\n')
    if short == 'instructions/pump_interface.rs':
        tail = '\n'.join(pl[len(sl) - 1:])
        check(len(pl) - len(sl) == 12 and 'fn legacy_price_check' in tail and 'fn legacy_price_check' not in sb.decode(),
              'pump_interface.rs only drops the trailing 12-line legacy_price_check helper')
    else:
        check(len(pl) == len(sl), f'{short}: line count preserved ({len(pl)})')

# 3. ELFs + builds
br = json.loads((HERE / 'builds/build-result.json').read_text())
rr = json.loads((HERE / 'builds/repeat-build-result.json').read_text())
check(sha(raw(HERE / 'builds/candidate.so.gz')) == CAND == br['candidate_sha256'], 'candidate.so.gz == recorded stripped digest e93b60f1')
check(sha(raw(HERE / 'builds/symbols.so.gz')) == SYMS == br['symbols_sha256'], 'symbols.so.gz == recorded symbols digest 49d70dc7')
check(rr['candidate_sha256'] == CAND and rr['symbols_sha256'] == SYMS, 'second clean build reproduced both ELFs bit-for-bit')
for name, r in [('build-result', br), ('repeat-build-result', rr)]:
    check(r['returncode'] == 0 and r['source_unchanged'] and r['tools_unchanged'] and r['target_libraries_unchanged'],
          f'{name}: exit 0, inputs unchanged')
la, lb = (json.loads((HERE / f'builds/{n}.json').read_text()) for n in ('launch', 'repeat-launch'))
check(la['clean_anchor'] and lb['clean_anchor'] and la['environment_overrides']['CARGO_TARGET_DIR'] != lb['environment_overrides']['CARGO_TARGET_DIR'],
      'the two builds used distinct fresh target dirs with anchor re-cleaned')
check(la['source_inputs'] == lb['source_inputs'] == sinv,
      'both builds compiled exactly the shipped 67-file tree')
stderr = raw(HERE / 'builds/build-stderr.gz').decode('utf-8', 'replace')
check('exceeded max offset' not in stderr and 'Stack offset' not in stderr, 'no stack-offset warning')

# 4. measurement
m = json.loads((HERE / 'measurement/measure-vs-parent434.json').read_text())
check(m['candidate_symbols_sha256'] == SYMS, 'measurement bound to the shipped symbols ELF')
check(m['gains'] == ['O0081', 'O0082'], 'vs parent-434: gains are exactly O0081 and O0082')
check(m['no_losses'] and not any(m[k] for k in ('body_losses', 'raw_losses', 'profile_losses', 'edge_losses', 'source_losses')),
      'vs parent-434: no losses of any kind (body/raw/profile/edge/source)')
c = m['counts']
check((c['matched_before'], c['matched_after']) == (434, 436) and c['raw_after'] >= c['raw_before'] and c['edges_after'] >= c['edges_before']
      and c['source_after'] >= c['source_before'], f'434 -> 436 normalized windows; raw {c["raw_before"]}->{c["raw_after"]}, '
      f'edges {c["edges_before"]}->{c["edges_after"]}, source {c["source_before"]}->{c["source_after"]}')
check(m['unmatched_ids'] == ['O0076', 'O0077', 'O0079', 'O0083', 'O0084'], 'remaining unmatched: O0076 O0077 O0079 O0083 O0084')
m3 = json.loads((HERE / 'measurement/measure-vs-parent433.json').read_text())
check(m3['candidate_symbols_sha256'] == SYMS and m3['gains'] == ['O0073', 'O0081', 'O0082'] and m3['no_losses']
      and (m3['counts']['matched_before'], m3['counts']['matched_after']) == (433, 436), 'vs parent-433 (cp4): O0073 O0081 O0082, no losses')

# 5. runtime
CU = re.compile(r'consumed \d+ of \d+ compute units')
FIELDS = ['error', 'accounts', 'events', 'inner', 'return_data']
state = lambda r: {k: r[k] for k in FIELDS}
logs = lambda r: [CU.sub('consumed <cu>', x) for x in r['logs']]
sw = json.loads(raw(HERE / 'runtime/sweeps-differential.json.gz'))
check(sw['candidate_sha256'] == CAND and sw['original_sha256'] == ORIGINAL, 'sweep receipt: shipped stripped ELF vs the deployed original')
check(sw['case_count'] == len(sw['cases']) == 692 and sw['mismatches'] == [], 'stock sweep: 692 cases, 0 recorded mismatches')
check(all(c['equal'] and state(c['original']) == state(c['candidate']) and logs(c['original']) == logs(c['candidate']) for c in sw['cases']),
      'stock sweep recomputed here: state, errors, events, CPIs, return data and logs (mod CU) equal on all 692')
t = json.loads((HERE / 'runtime/trades-summary.json').read_text())
check(t['candidate_sha256'] == CAND, 'trade summary bound to the shipped stripped ELF')
runs = t['runs']
check(len(runs) == 14 and len({r['family'] for r in runs}) == 14 and all(
    r['returncode'] == 0 and r['cases'] == r['expected_cases'] and r['mismatches'] == 0 and r['noncompute_log_diffs'] == 0 for r in runs),
    'trade suites: 14 families exit 0, full case counts, 0 mismatches, 0 non-compute log diffs')
check(sum(r['cases'] for r in runs) == t['total_cases'] == 6636 and t['total_mismatches'] == 0 and t['total_noncompute_log_diffs'] == 0
      and t['all_ok'], 'trade suites: 6636 cases total, 0 mismatches')

print('\n'.join('  OK  ' + x for x in ok))
print(f'\nPASS - {len(ok)} checks')
