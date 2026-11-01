#!/usr/bin/env python3
"""Verify the claude-mayhem-439 packet from saved evidence; no compiler or VM runs.

Requires a repository checkout with the hash-pinned original image, the Codex qualified438 packet
(research/mayhem-current438-composition-20261028: parent inventory, source archive, build recipe and images)
and the existing reader (research/mayhem-current-macro-call-closure-20261027). Recomputes the full 441-window
census and the O0077 body match from ELF bytes, and every runtime count from the saved per-case outputs.
"""
import gzip, hashlib, importlib.util, io, json, lzma, re, sys, tarfile
from pathlib import Path, PurePosixPath

if not __debug__:
    raise SystemExit('run with assertions enabled')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = next(p for p in HERE.parents if (p / 'evidence/original/mayhem/deployed.so').is_file())
CAND = 'e899e096d903ffe0b6e475bc00d6015dc38f1caed13a85952e4cf83e229f6b08'
SYMS = '5d18b89a1c76fbc85a90ae46dde2d06a7d0157b94e4bb41050f68b48ff1963f4'
PARENT = 'b69ee99d83cb1eaaa999082dc707560e95e1540174f27b5e6a8e1438cc4c34fc'  # Codex qualified438 stripped
PARENT_SYMS = 'a4e4768d99d31f078ef876b71faca42acd774db00c53f75e888bc1b1c119aa4a'
ORIGINAL = 'a87fa9f866272514e6acb852b668c4a08aeb173d56c883039991d114d1199bdb'  # evidence/original/mayhem/deployed.so
Q438 = 'research/mayhem-current438-composition-20261028'
PATCHED = ['src/instructions/buy_pump_swap.rs', 'src/instructions/pump_amm_interface.rs']
MAY = 'MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e'
sha = lambda b: hashlib.sha256(b).hexdigest()
raw = lambda p: gzip.decompress(p.read_bytes()) if p.suffix == '.gz' else lzma.decompress(p.read_bytes()) if p.suffix == '.xz' else p.read_bytes()
load = lambda p: json.loads(raw(p))
ok = []


def check(cond, msg):
    assert cond, 'FAIL: ' + msg
    ok.append(msg)


# 1. manifest
sums = {}
for line in (HERE / 'SHA256SUMS.txt').read_text().splitlines():
    if line.strip():
        h, name = line.split(None, 1)
        name = name.strip(); n = PurePosixPath(name)
        check(str(n) == name and not n.is_absolute() and '..' not in n.parts and name not in sums,
              'manifest path is canonical, relative and unique: ' + name)
        sums[name] = h
paths = list(HERE.rglob('*'))
check(not any(p.is_symlink() for p in paths), 'manifest rejects symlinks')
check(all(p.is_file() or p.is_dir() for p in paths), 'manifest rejects special files')
present = {p.relative_to(HERE).as_posix() for p in paths if p.is_file() and p != HERE / 'SHA256SUMS.txt'}
check(present == set(sums), f'manifest lists exactly the files present ({len(present)})')
for name, h in sorted(sums.items()):
    check(sha((HERE / name).read_bytes()) == h, f'sha256 {name}')

# 2. sources: parent = Codex qualified438 (67 files), shipped differs only in the two O0077 files
pinv = json.loads((HERE / 'sources/source-inputs.parent438.json').read_text())
sinv = json.loads((HERE / 'sources/source-inputs.json').read_text())
check(len(pinv) == len(sinv) == 67 and set(pinv) == set(sinv), 'parent and shipped inventories list the same 67 crate inputs')
check(sorted(k for k in pinv if pinv[k] != sinv[k]) == PATCHED, 'the 439 tree differs from qualified438 only in buy_pump_swap.rs and pump_amm_interface.rs')
check(json.loads((REPO / Q438 / 'composed-inputs.json').read_text()) == pinv, 'parent inventory == qualified438 composed-inputs.json on main')
with tarfile.open(fileobj=io.BytesIO((REPO / Q438 / 'source.tar.gz').read_bytes())) as t:
    members = {m.name.removeprefix('./'): t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
check({k: sha(v) for k, v in members.items()} == pinv, 'qualified438 source.tar.gz on main holds exactly the parent inventory (67 files)')
for f in PATCHED:
    check((HERE / 'sources/parent/instructions' / Path(f).name).read_bytes() == members[f], f'sources/parent/{Path(f).name} == qualified438 archive copy')
    check(sha((HERE / 'sources/shipped/instructions' / Path(f).name).read_bytes()) == sinv[f], f'sources/shipped/{Path(f).name} matches the shipped inventory')


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
    return out + src_lines[i:]


patch = (HERE / 'source.patch').read_text().split('\n')
heads = [i for i, ln in enumerate(patch) if ln.startswith('--- ')]
check([patch[i] for i in heads] == ['--- a/programs/mayhem/' + f for f in PATCHED]
      and [patch[i + 1] for i in heads] == ['+++ b/programs/mayhem/' + f for f in PATCHED]
      and sum(ln.startswith('+++ ') for ln in patch) == 2, 'source.patch touches only the two O0077 files')
for n, f in enumerate(PATCHED):
    hunks = patch[heads[n] + 2:heads[n + 1] if n + 1 < len(heads) else len(patch)]
    while hunks and hunks[-1] == '':
        hunks = hunks[:-1]
    pb = (HERE / 'sources/parent/instructions' / Path(f).name).read_bytes()
    sb = (HERE / 'sources/shipped/instructions' / Path(f).name).read_bytes()
    check(apply_unified(pb.decode().split('\n'), hunks) == sb.decode().split('\n'), f'source.patch reproduces shipped {Path(f).name}')
check([(HERE / 'sources/shipped/instructions' / Path(f).name).read_bytes().count(b'\n') for f in PATCHED] == [130, 598],
      'shipped line counts: buy_pump_swap.rs 129 -> 130, pump_amm_interface.rs 598 -> 598')

# 3. ELFs + builds (Codex qualified438 root recipe, paths only differ)
br = json.loads((HERE / 'builds/build-result.json').read_text())
rr = json.loads((HERE / 'builds/repeat-build-result.json').read_text())
check(sha(raw(HERE / 'builds/candidate.so.gz')) == CAND == br['candidate_sha256'] == rr['candidate_sha256'], 'candidate.so.gz == both builds\' stripped digest e899e096')
check(sha(raw(HERE / 'builds/symbols.so.gz')) == SYMS == br['symbols_sha256'] == rr['symbols_sha256'], 'symbols.so.gz == both builds\' symbols digest 5d18b89a')
for name, r in [('build-result', br), ('repeat-build-result', rr)]:
    check(r['returncode'] == 0 and r['source_unchanged'] and r['archives_unchanged'] and r['tools_unchanged'] and r['stack_offset_warnings'] == 0,
          f'{name}: exit 0, sources/dependency archives/tools unchanged, no stack-offset warning')
la, lb = (json.loads((HERE / f'builds/{n}.json').read_text()) for n in ('launch', 'repeat-launch'))
check(la['source_inputs'] == lb['source_inputs'] == sinv, 'both builds compiled exactly the shipped 67-file tree')
dep = lambda l: [x for x in l['command'] if x.startswith('dependency=') and 'sbpf-solana-solana' in x]
check(la['cwd'] != lb['cwd'] and set(dep(la)).isdisjoint(dep(lb)), 'clean build: separate source copy and separate dependency-cache clone')
check(la['controller_sha256'] == sha((HERE / 'builds/crecipe.py').read_bytes()), 'clean build controller == builds/crecipe.py')
q = REPO / Q438 / 'builds/first'
check(la['packet_launch_sha256'] == lb['packet_launch_sha256'] == sha((q / 'launch.json').read_bytes())
      and la['packet_linker_sha256'] == sha((q / 'linker.py').read_bytes()), 'recipe source: qualified438 builds/first launch.json and linker.py on main')
for n in ('ordered.ld', 'default.ld'):
    check(sorted(h for p, h in la['tools'].items() if p.endswith('/' + n)) == [sha((q / n).read_bytes())], f'linker input {n} == qualified438 builds/first/{n}')
P_RE = re.compile(r'/\S*/(fast-amm-qualified434-20261027|historical-native-macro-a|layout-lane-linux-target2-sysroot)(?=/|$)')
O_RE = re.compile(r'/\S*/(root-out|link\.map|linker\.py)$')
norm = lambda x: O_RE.sub(r'<out>/\1', P_RE.sub(r'<\1>', x))
codex = json.loads((q / 'launch.json').read_bytes())
check([norm(x) for x in la['command']] == [norm(x) for x in lb['command']] == [norm(x) for x in codex['command']],
      f'rustc command == qualified438 builds/first command modulo paths ({len(codex["command"])} args)')
env = lambda l: {k: (v if k.startswith('CARGO_PKG') else 'path') for k, v in l['environment'].items()}
check(env(la) == env(lb) == env(codex), 'build environment keys and package values == qualified438 builds/first')
for n in ('build-stderr.gz', 'repeat-build-stderr.gz'):
    stderr = raw(HERE / 'builds' / n).decode('utf-8', 'replace')
    check('exceeded max offset' not in stderr and 'Stack offset' not in stderr, f'{n}: no stack-offset warning')

# 4. measurement
m = json.loads((HERE / 'measurement/measure-vs-codex438.json').read_text())
check(m['candidate_symbols_sha256'] == SYMS, 'measurement bound to the shipped symbols ELF')
check(m['gains'] == ['O0077'] and not m['raw_gains'], 'vs qualified438: gains are exactly O0077, no raw gains')
check(m['no_losses'] and not any(m[k] for k in ('body_losses', 'raw_losses', 'profile_losses', 'edge_losses', 'source_losses')),
      'vs qualified438: no losses of any kind (body/raw/profile/edge/source)')
c = m['counts']
check((c['matched_before'], c['matched_after'], c['raw_before'], c['raw_after'], c['edges_before'], c['edges_after'], c['source_before'], c['source_after'])
      == (438, 439, 141, 141, 4573, 4670, 502, 505), '438 -> 439 normalized windows; raw 141 -> 141, edges 4573 -> 4670, Source 502 -> 505')
check(m['unmatched_ids'] == ['O0083', 'O0084'] and m['unmatched_window_bytes'] == 36744, 'remaining unmatched: O0083 O0084 (36,744 bytes)')
spec = importlib.util.spec_from_file_location('claude439_elf_check', HERE / 'elf_check.py')
elf_check = importlib.util.module_from_spec(spec); spec.loader.exec_module(elf_check)
actual = elf_check.inspect(REPO, HERE)
check(actual == json.loads((HERE / 'measurement/recomputed-elf.json').read_text()),
      'actual ELF: full 441-window census, O0077 normalized body, calls and Source profiles')
pa, ca = actual['parent'], actual['candidate']
check((sum(pa['counts'].values()) - pa['counts']['unmatched'], sum(ca['counts'].values()) - ca['counts']['unmatched']) == (c['matched_before'], c['matched_after'])
      and (pa['counts']['raw'], ca['counts']['raw'], pa['positive_edges'], ca['positive_edges'], pa['positive_Source'], ca['positive_Source'])
      == (c['raw_before'], c['raw_after'], c['edges_before'], c['edges_after'], c['source_before'], c['source_after']),
      'saved measurement totals agree with recomputed ELF totals')
check(sha(gzip.decompress((REPO / Q438 / 'builds/first/candidate.so.gz').read_bytes())) == PARENT
      and sha(gzip.decompress((REPO / Q438 / 'builds/first/symbols.so.gz').read_bytes())) == PARENT_SYMS, 'parent images: qualified438 b69ee99d / a4e4768d')
we = actual['whole_elf']
check(we['candidate_sha256'] == CAND and we['original_sha256'] == ORIGINAL and not we['equal'] and (we['candidate_bytes'], we['original_bytes']) == (765856, 777408),
      'whole ELF remains unequal to the original (765,856 vs 777,408 bytes)')

# 5. runtime: every count recomputed from the saved per-case outputs
CU = re.compile(r'Program \S+ consumed \d+ of \d+ compute units')
ev = lambda r: [x for x in r['metadata']['logs'] if x.startswith('Program data: ')]
nl = lambda r: [CU.sub('Program <p> consumed <cu>', x) for x in r['metadata']['logs']]
slogs = lambda r: [x for x in r['logs'] if not CU.fullmatch(x)]


def tdiff(case):
    o, n = case['original'], case['candidate']
    bad = [ph for ph in ('before', 'after') if {k: v for k, v in o[ph].items() if k != MAY} != {k: v for k, v in n[ph].items() if k != MAY}]
    bad += ['error'] * (o['error'] != n['error']) + [f for f in ('inner_instructions', 'return_data') if o['metadata'][f] != n['metadata'][f]]
    return bad + ['events'] * (ev(o) != ev(n)) + ['logs'] * (nl(o) != nl(n))


R = HERE / 'runtime'
summary = dict(trades={}, sweeps={}, initializer={}, target_rates={})
cmds = load(R / 'trades/commands.json'); tl = load(R / 'trades/launch.json'); tpl = load(R / 'controllers/trade-template.json')
check(cmds['candidate_sha256'] == tl['candidate_sha256'] == CAND and len(cmds['runs']) == 14 and [r['family'] for r in cmds['runs']] == [r['family'] for r in tpl['runs']],
      'trade commands: 14 template families run on the shipped ELF')
check(tl['template_sha256'] == sha((R / 'controllers/trade-template.json').read_bytes()) and tl['controller_sha256'] == cmds['controller_sha256'] == sha((R / 'controllers/run_trades.py').read_bytes()),
      'trade launch bound to the shipped controller and template')
for run, row in zip(cmds['runs'], tpl['runs']):
    f = run['family']; d = load(R / 'trades' / (f + '.json.xz'))
    bad = [i for i, x in enumerate(d['cases']) if x['different_fields'] or x['normalized_log_difference'] or tdiff(x)]
    check(d['candidate_sha256'] == CAND and d['original_sha256'] == ORIGINAL and run['returncode'] == 0 and d['case_count'] == len(d['cases']) == run['cases'] == row['cases']
          and d['mismatches'] == [] and d['normalized_log_differences'] == [] and not bad and d['signed_transactions'] == 2 * d['case_count']
          and all(x['original']['signature_verified'] and x['candidate']['signature_verified'] for x in d['cases']),
          f'trade {f}: {d["case_count"]} signed original/candidate pairs, state/error/CPI/return/events/logs (mod CU) equal')
    summary['trades'][f] = dict(cases=d['case_count'], listed=len(d['cases']), mismatches=len(d['mismatches']), log_diffs=len(d['normalized_log_differences']),
                                recomputed_bad=len(bad), signed_transactions=d['signed_transactions'], candidate_sha256=d['candidate_sha256'])
ex = load(R / 'sweeps/execution.json')
check(ex['candidate_sha256'] == CAND and ex['control_sha256'] == PARENT and ex['signature_verification'] and ex['blockhash_check'],
      'sweep execution: shipped ELF vs qualified438 control, signature and blockhash checks on')
for suite, count in (('sweeps', 692), ('rates', 150)):
    d = load(R / 'sweeps' / (suite + '.json.gz')); bad = ctrl = 0
    for row in d['cases']:
        a, b, x = (row['results'][s] for s in ('original', 'control', 'candidate'))
        bad += any(not (a[k] == b[k] == x[k]) for k in ('error', 'accounts', 'events', 'inner', 'return_data')) or slogs(a) != slogs(x)
        ctrl += slogs(a) != slogs(b)
    check(d['count'] == len(d['cases']) == count and bad == 0 and d['binaries'] == dict(original=ORIGINAL, control=PARENT, candidate=CAND)
          and all(set(r['receipts']) == {'original', 'control', 'candidate'} for r in d['cases']),
          f'{suite}: {count} cases x 3 signed binaries, state/error/events/CPI/return equal, logs (mod CU) original == candidate')
    summary['sweeps'][suite] = dict(cases=d['count'], listed=len(d['cases']), mismatches=bad, control_log_diffs=ctrl,
                                    signed_records=sum(len(r['receipts']) for r in d['cases']), binaries=d['binaries'])
for k, count in (('rejections', 53), ('pump-cpi', 16)):
    d = load(R / 'initializer' / (k + '.json.gz'))
    initializer_fields = ('before', 'after', 'error', 'events', 'inner', 'return')
    if k == 'rejections':
        initializer_fields += ('anchor_errors', 'signed_transaction_base64')
    initializer_bad = [i for i, x in enumerate(d['cases']) if x['differences']
                       or any(f not in x['original'] or f not in x['candidate']
                              or x['original'][f] != x['candidate'][f] for f in initializer_fields)
                       or slogs(x['original']) != slogs(x['candidate'])]
    check(d['candidate_sha256'] == CAND and d['original_sha256'] == ORIGINAL and d['case_count'] == len(d['cases']) == count and d['mismatches'] == []
          and not initializer_bad, f'initializer {k}: {count} signed original/candidate pairs, no differences')
    summary['initializer'][k] = dict(cases=d['case_count'], listed=len(d['cases']), mismatches=len(d['mismatches']),
                                     recomputed_bad=sum(bool(x['differences']) for x in d['cases']), candidate_sha256=d['candidate_sha256'],
                                     signed_records=sum(len(x['original_executions']) + len(x['candidate_executions']) for x in d['cases']))
il = load(R / 'initializer/launch.json'); ir = load(R / 'initializer/result.json')
check(il['candidate_sha256'] == CAND and ir['returncode'] == 0 and ir['inputs_unchanged'] and il['controller_sha256'] == sha((R / 'controllers/run_initializer.py').read_bytes()),
      'initializer launch bound to the shipped ELF and controller, exit 0')
d = load(R / 'target-rates/differential.json.gz'); a = load(R / 'target-rates/attested.json.gz')
check(d['candidate_sha256'] == a['candidate_sha256'] == CAND and d['parent_sha256'] == a['control_sha256'] == PARENT and d['original_sha256'] == a['original_sha256'] == ORIGINAL
      and d['case_count'] == len(d['cases']) == 856 and d['mismatches'] == [] and d['log_differences_modulo_cu'] == [] and d['candidate_vs_parent_differences'] == []
      and all(x['equal'] and x['logs_equal_modulo_cu']
              and all(f in x['original'] and f in x['candidate'] and x['original'][f] == x['candidate'][f]
                      for f in ('error', 'accounts', 'events', 'inner', 'return_data'))
              and slogs(x['original']) == slogs(x['candidate']) for x in d['cases'])
      and len(a['records']) == 3 and all(len(v) == 856 for v in a['records'].values()),
      'target rates: 856 cases, equal to original and parent, 3 x 856 attested signed records')
summary['target_rates'] = dict(cases=d['case_count'], listed=len(d['cases']), mismatches=len(d['mismatches']), log_diffs=len(d['log_differences_modulo_cu']),
                               candidate_vs_parent=len(d['candidate_vs_parent_differences']), recomputed_bad=sum(not (x['equal'] and x['logs_equal_modulo_cu']) for x in d['cases']),
                               attested_records=sum(map(len, a['records'].values())), attested_binaries=len(a['records']), original_outcomes=d['original_outcomes'])
t = summary['trades']
summary['totals'] = dict(trade_families=len(t), trade_cases=sum(v['cases'] for v in t.values()),
                         trade_mismatches=sum(v['mismatches'] + v['log_diffs'] + v['recomputed_bad'] for v in t.values()),
                         trade_signed_transactions=sum(v['signed_transactions'] for v in t.values()),
                         sweep_cases=summary['sweeps']['sweeps']['cases'], rate_cases=summary['sweeps']['rates']['cases'],
                         sweep_mismatches=summary['sweeps']['sweeps']['mismatches'] + summary['sweeps']['rates']['mismatches'],
                         initializer_cases=sum(v['cases'] for v in summary['initializer'].values()),
                         initializer_mismatches=sum(v['mismatches'] + v['recomputed_bad'] for v in summary['initializer'].values()),
                         target_rate_cases=summary['target_rates']['cases'],
                         target_rate_mismatches=summary['target_rates']['mismatches'] + summary['target_rates']['log_diffs'] + summary['target_rates']['recomputed_bad'])
check(summary == load(R / 'summary.json'), 'runtime summary.json == counts recomputed from the saved outputs')
T = summary['totals']
check((T['trade_cases'], T['trade_signed_transactions'], T['sweep_cases'], T['rate_cases'], T['initializer_cases'], T['target_rate_cases']) == (6636, 13272, 692, 150, 69, 856)
      and not (T['trade_mismatches'] or T['sweep_mismatches'] or T['initializer_mismatches'] or T['target_rate_mismatches']),
      'runtime totals: 6,636 trade pairs, 692 sweeps, 150 rates, 69 initializer, 856 target rates; 0 mismatches')

print('\n'.join('  OK  ' + x for x in ok))
print(f'\nPASS - {len(ok)} checks')
print('Not checked here: whole-ELF identity (unequal), fresh dependency builds (the recipe reuses the qualified434 rlibs), '
      'signature re-verification of saved transactions (needs solders), arbitrary data/indirect-call equivalence.')
