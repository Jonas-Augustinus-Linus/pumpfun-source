#!/usr/bin/env python3
"""Verify the claude-mayhem-441-20261028 packet from saved evidence; no compiler or VM runs.

Requires a repository checkout with the hash-pinned original image, the parent packet (claude-mayhem-439 (PR #423)),
the Codex qualified438 packet (research/mayhem-current438-composition-20261028: source archive and build recipe)
and the existing reader (research/mayhem-current-macro-call-closure-20261027). Recomputes the full 441-window
census and the gained bodies from ELF bytes, and every runtime count from the saved per-case outputs.
"""
import gzip, hashlib, importlib.util, io, json, lzma, re, sys, tarfile
from pathlib import Path, PurePosixPath

if not __debug__:
    raise SystemExit('run with assertions enabled')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = next(p for p in HERE.parents if (p / 'evidence/original/mayhem/deployed.so').is_file())
ORIGINAL = 'a87fa9f866272514e6acb852b668c4a08aeb173d56c883039991d114d1199bdb'  # evidence/original/mayhem/deployed.so
Q438 = 'research/mayhem-current438-composition-20261028'
MAY = 'MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e'
# ---- claims (generated) ----
CAND = "380157fa6a63e717bd1630c6c4a86a4b66b596caedab6769d4497c8fa2b8d2a9"
SYMS = "5fda674541c8a39caf95d304d4cfb14fe5b0493a0c57e16a4dd78447b7169448"
PARENT = "e899e096d903ffe0b6e475bc00d6015dc38f1caed13a85952e4cf83e229f6b08"
PARENT_SYMS = "5d18b89a1c76fbc85a90ae46dde2d06a7d0157b94e4bb41050f68b48ff1963f4"
PARENT_IMAGES = {"candidate": "research/claude-mayhem-439-20261028/builds/candidate.so.gz", "symbols": "research/claude-mayhem-439-20261028/builds/symbols.so.gz"}
PARENT_INVENTORY = "research/claude-mayhem-439-20261028/sources/source-inputs.json"
PARENT_TREE = [["tar", "research/mayhem-current438-composition-20261028/source.tar.gz"], ["overlay", "research/claude-mayhem-439-20261028/sources/shipped/instructions", "src/instructions"]]
PATCHED = ["src/instructions/burn.rs", "src/instructions/buy_v2.rs", "src/instructions/extend_account.rs", "src/instructions/pump_interface_v2.rs", "src/lib.rs", "src/state.rs"]
LINES = {"src/instructions/burn.rs": [118, 118], "src/instructions/buy_v2.rs": [119, 119], "src/instructions/extend_account.rs": [153, 153], "src/instructions/pump_interface_v2.rs": [605, 600], "src/lib.rs": [488, 488], "src/state.rs": [630, 635]}
GAINS = ["O0083", "O0084"]
RAW_GAINS = ["O0000", "O0001", "O0002", "O0003", "O0004", "O0005", "O0006", "O0007", "O0008", "O0009", "O0010", "O0011", "O0012", "O0013", "O0014", "O0015", "O0016", "O0017", "O0018", "O0019", "O0020", "O0021", "O0022", "O0023", "O0024", "O0025", "O0026", "O0027", "O0028", "O0029", "O0030", "O0031", "O0032", "O0033", "O0034", "O0035", "O0036", "O0037", "O0039", "O0040", "O0041", "O0043", "O0044", "O0046", "O0047", "O0048", "O0049", "O0051", "O0052", "O0053", "O0054", "O0055", "O0056", "O0057", "O0058", "O0059", "O0060", "O0061", "O0062", "O0063", "O0064", "O0065", "O0066", "O0067", "O0068", "O0069", "O0070", "O0071", "O0072", "O0073", "O0074", "O0075", "O0076", "O0077", "O0078", "O0079", "O0080", "O0081", "O0082", "O0083", "O0084", "O0085", "O0086", "O0087", "O0088", "O0089", "O0090", "O0091", "O0092", "O0093", "O0094", "O0095", "O0096", "O0097", "O0098", "O0099", "O0100", "O0101", "O0102", "O0103", "O0104", "O0105", "O0106", "O0107", "O0108", "O0109", "O0110", "O0111", "O0112", "O0113", "O0114", "O0115", "O0116", "O0117", "O0118", "O0119", "O0120", "O0121", "O0122", "O0123", "O0124", "O0125", "O0126", "O0127", "O0128", "O0129", "O0130", "O0131", "O0132", "O0133", "O0134", "O0135", "O0136", "O0137", "O0138", "O0139", "O0140", "O0141", "O0142", "O0143", "O0144", "O0145", "O0146", "O0147", "O0148", "O0149", "O0150", "O0151", "O0152", "O0153", "O0154", "O0155", "O0156", "O0157", "O0158", "O0159", "O0160", "O0161", "O0162", "O0163", "O0164", "O0165", "O0167", "O0168", "O0169", "O0170", "O0171", "O0172", "O0173", "O0174", "O0175", "O0176", "O0177", "O0178", "O0179", "O0180", "O0181", "O0182", "O0183", "O0184", "O0185", "O0186", "O0187", "O0188", "O0189", "O0190", "O0191", "O0192", "O0193", "O0202", "O0203", "O0205", "O0206", "O0210", "O0211", "O0212", "O0213", "O0214", "O0215", "O0216", "O0218", "O0220", "O0221", "O0226", "O0231", "O0232", "O0238", "O0239", "O0240", "O0241", "O0242", "O0243", "O0244", "O0247", "O0248", "O0249", "O0250", "O0251", "O0257", "O0260", "O0264", "O0266", "O0267", "O0270", "O0276", "O0277", "O0284", "O0285", "O0286", "O0290", "O0291", "O0292", "O0293", "O0294", "O0302", "O0303", "O0304", "O0305", "O0306", "O0307", "O0310", "O0311", "O0314", "O0317", "O0318", "O0320", "O0323", "O0325", "O0328", "O0329", "O0340", "O0342", "O0345", "O0349", "O0351", "O0353", "O0355", "O0356", "O0357", "O0364", "O0367", "O0368", "O0369", "O0370", "O0371", "O0374", "O0375", "O0376", "O0377", "O0378", "O0379", "O0380", "O0381", "O0382", "O0389", "O0391", "O0392", "O0400", "O0401", "O0402", "O0403", "O0404", "O0405", "O0406", "O0407", "O0408", "O0409", "O0410", "O0411", "O0412", "O0413", "O0414", "O0417", "O0419", "O0422", "O0423", "O0424", "O0425", "O0433", "O0440"]
COUNTS = (439, 441, 141, 441, 4670, 4768, 505, 519)
UNMATCHED = []
UNMATCHED_BYTES = 0
WHOLE_EQUAL = False
WHOLE_BYTES = (775416, 777408)
ORDERED_FROM_PACKET = True
WHOLE_DETAIL = (30, True, True, {'.dynsym': 1, '.dynstr': 20, '.rel.dyn': 9})
# ----------------------------
sha = lambda b: hashlib.sha256(b).hexdigest()
raw = lambda p: gzip.decompress(p.read_bytes()) if p.suffix == '.gz' else lzma.decompress(p.read_bytes()) if p.suffix == '.xz' else p.read_bytes()
load = lambda p: json.loads(raw(p))
ok = []


def check(cond, msg):
    assert cond, 'FAIL: ' + msg
    ok.append(msg)


def tar_files(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        return {m.name.removeprefix('./'): t.extractfile(m).read() for m in t.getmembers() if m.isfile()}


# 1. manifest
paths = list(HERE.rglob('*'))
check(not any(p.is_symlink() for p in paths), 'manifest rejects symlinks')
check(all(p.is_file() or p.is_dir() for p in paths), 'manifest rejects special files')
sums = {}
for line in (HERE / 'SHA256SUMS.txt').read_text().splitlines():
    if line.strip():
        h, name = line.split(None, 1)
        name = name.strip(); n = PurePosixPath(name)
        check(str(n) == name and not n.is_absolute() and '..' not in n.parts and name not in sums,
              'manifest path is canonical, relative and unique: ' + name)
        sums[name] = h
present = {p.relative_to(HERE).as_posix() for p in paths if p.is_file() and p != HERE / 'SHA256SUMS.txt'}
check(present == set(sums), f'manifest lists exactly the files present ({len(present)})')
for name, h in sorted(sums.items()):
    check(sha((HERE / name).read_bytes()) == h, f'sha256 {name}')

# 2. sources: the parent tree is rebuilt from repository inputs; the shipped tree is sources/source.tar.gz
pinv = json.loads((HERE / 'sources/source-inputs.parent.json').read_text())
sinv = json.loads((HERE / 'sources/source-inputs.json').read_text())
check(len(pinv) == len(sinv) == 67 and set(pinv) == set(sinv), 'parent and shipped inventories list the same 67 crate inputs')
check(sorted(k for k in pinv if pinv[k] != sinv[k]) == PATCHED, f'the shipped tree differs from the parent only in {", ".join(Path(f).name for f in PATCHED)}')
check(json.loads((REPO / PARENT_INVENTORY).read_text()) == pinv, f'parent inventory == {PARENT_INVENTORY} on main')
parent = {}
for step in PARENT_TREE:
    if step[0] == 'tar':
        parent = tar_files((REPO / step[1]).read_bytes())
    else:
        for f in sorted((REPO / step[1]).iterdir()):
            parent[step[2] + '/' + f.name] = f.read_bytes()
check({k: sha(v) for k, v in parent.items()} == pinv, 'parent tree rebuilt from repository inputs == parent inventory (67 files)')
shipped = tar_files((HERE / 'sources/source.tar.gz').read_bytes())
check({k: sha(v) for k, v in shipped.items()} == sinv, 'sources/source.tar.gz holds exactly the shipped inventory (67 files)')
for f in PATCHED:
    check((HERE / 'sources/parent' / f).read_bytes() == parent[f], f'sources/parent/{f} == parent tree copy')
    check((HERE / 'sources/shipped' / f).read_bytes() == shipped[f], f'sources/shipped/{f} == shipped tree copy')


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
      and sum(ln.startswith('+++ ') for ln in patch) == len(PATCHED), 'source.patch touches only the changed files')
for n, f in enumerate(PATCHED):
    hunks = patch[heads[n] + 2:heads[n + 1] if n + 1 < len(heads) else len(patch)]
    while hunks and hunks[-1] == '':
        hunks = hunks[:-1]
    check(apply_unified(parent[f].decode().split('\n'), hunks) == shipped[f].decode().split('\n'), f'source.patch reproduces shipped {f}')
check({f: [parent[f].count(b'\n'), shipped[f].count(b'\n')] for f in PATCHED} == LINES, f'line counts parent -> shipped: {LINES}')

# 3. ELFs + builds (Codex qualified438 root recipe, paths only differ)
br = json.loads((HERE / 'builds/build-result.json').read_text())
rr = json.loads((HERE / 'builds/repeat-build-result.json').read_text())
check(sha(raw(HERE / 'builds/candidate.so.gz')) == CAND == br['candidate_sha256'] == rr['candidate_sha256'], f'candidate.so.gz == both builds\' stripped digest {CAND[:8]}')
check(sha(raw(HERE / 'builds/symbols.so.gz')) == SYMS == br['symbols_sha256'] == rr['symbols_sha256'], f'symbols.so.gz == both builds\' symbols digest {SYMS[:8]}')
for name, r in [('build-result', br), ('repeat-build-result', rr)]:
    check(r['returncode'] == 0 and r['source_unchanged'] and r['archives_unchanged'] and r['tools_unchanged'] and r['stack_offset_warnings'] == 0,
          f'{name}: exit 0, sources/dependency archives/tools unchanged, no stack-offset warning')
la, lb = (json.loads((HERE / f'builds/{n}.json').read_text()) for n in ('launch', 'repeat-launch'))
check(la['source_inputs'] == lb['source_inputs'] == sinv, 'both builds compiled exactly the shipped 67-file tree')
dep = lambda l: [x for x in l['command'] if x.startswith('dependency=') and 'sbpf-solana-solana' in x]
check(la['cwd'] != lb['cwd'] and set(dep(la)).isdisjoint(dep(lb)), 'clean build: separate source copy and separate dependency-cache clone')
controllers = {sha((HERE / 'builds' / n).read_bytes()) for n in ('crecipe.py', 'rbuild.py') if (HERE / 'builds' / n).is_file()}
check(la['controller_sha256'] == sha((HERE / 'builds/crecipe.py').read_bytes()) and lb['controller_sha256'] in controllers, 'build controllers shipped in builds/')
q = REPO / Q438 / 'builds/first'
check(la['packet_launch_sha256'] == lb['packet_launch_sha256'] == sha((q / 'launch.json').read_bytes())
      and la['packet_linker_sha256'] == lb['packet_linker_sha256'] == sha((q / 'linker.py').read_bytes()), 'recipe source: qualified438 builds/first launch.json and linker.py on main')
for n in ('ordered.ld', 'default.ld'):
    src = HERE / 'builds/ordered.ld' if (n == 'ordered.ld' and ORDERED_FROM_PACKET) else q / n
    for l in (la, lb):
        check(sorted(h for p, h in l['tools'].items() if p.endswith('/' + n)) == [sha(src.read_bytes())],
              f'linker input {n} == ' + ('builds/ordered.ld (generated link script shipped here)' if src.parent == HERE / 'builds' else f'qualified438 builds/first/{n}'))
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
m = json.loads((HERE / 'measurement/measure-vs-parent.json').read_text())
check(m['candidate_symbols_sha256'] == SYMS, 'measurement bound to the shipped symbols ELF')
check(m['gains'] == GAINS and m['raw_gains'] == RAW_GAINS, f'vs parent: gains are exactly {GAINS}, raw gains ' + (str(RAW_GAINS) if len(RAW_GAINS) <= 10 else f'{len(RAW_GAINS)} windows'))
check(m['no_losses'] and not any(m[k] for k in ('body_losses', 'raw_losses', 'profile_losses', 'edge_losses', 'source_losses')),
      'vs parent: no losses of any kind (body/raw/profile/edge/source)')
c = m['counts']
check((c['matched_before'], c['matched_after'], c['raw_before'], c['raw_after'], c['edges_before'], c['edges_after'], c['source_before'], c['source_after']) == COUNTS,
      f'normalized {COUNTS[0]} -> {COUNTS[1]}; raw {COUNTS[2]} -> {COUNTS[3]}, edges {COUNTS[4]} -> {COUNTS[5]}, Source {COUNTS[6]} -> {COUNTS[7]}')
check(m['unmatched_ids'] == UNMATCHED and m['unmatched_window_bytes'] == UNMATCHED_BYTES, f'remaining unmatched: {UNMATCHED} ({UNMATCHED_BYTES} bytes)')
spec = importlib.util.spec_from_file_location('mg_elf_check', HERE / 'elf_check.py')
elf_check = importlib.util.module_from_spec(spec); spec.loader.exec_module(elf_check)
actual = elf_check.inspect(REPO, HERE)
check(actual == json.loads((HERE / 'measurement/recomputed-elf.json').read_text()),
      'actual ELF: full 441-window census, gained normalized bodies, calls and Source profiles')
pa, ca = actual['parent'], actual['candidate']
check((sum(pa['counts'].values()) - pa['counts'].get('unmatched', 0), sum(ca['counts'].values()) - ca['counts'].get('unmatched', 0)) == (c['matched_before'], c['matched_after'])
      and (pa['counts'].get('raw', 0), ca['counts'].get('raw', 0), pa['positive_edges'], ca['positive_edges'], pa['positive_Source'], ca['positive_Source'])
      == (c['raw_before'], c['raw_after'], c['edges_before'], c['edges_after'], c['source_before'], c['source_after']),
      'saved measurement totals agree with recomputed ELF totals')
check(sha(gzip.decompress((REPO / PARENT_IMAGES['candidate']).read_bytes())) == PARENT
      and sha(gzip.decompress((REPO / PARENT_IMAGES['symbols']).read_bytes())) == PARENT_SYMS, f'parent images: {PARENT[:8]} / {PARENT_SYMS[:8]}')
we = actual['whole_elf']
check(we['candidate_sha256'] == CAND and we['original_sha256'] == ORIGINAL and we['equal'] == WHOLE_EQUAL and (we['candidate_bytes'], we['original_bytes']) == WHOLE_BYTES,
      f'whole ELF equal={WHOLE_EQUAL} ({WHOLE_BYTES[0]:,} vs {WHOLE_BYTES[1]:,} bytes)')
check((we['meaningful_prefix_differing_bytes'], we['original_tail_zero'], we['section_headers_equal'], we['differing_bytes_by_section']) == WHOLE_DETAIL,
      f'whole ELF vs the original\'s first {WHOLE_BYTES[0]:,} bytes: {WHOLE_DETAIL[0]} differing bytes {WHOLE_DETAIL[3]}; original tail zero={WHOLE_DETAIL[1]}; section headers equal={WHOLE_DETAIL[2]}')

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
      'sweep execution: shipped ELF vs parent control, signature and blockhash checks on')
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
    check(d['candidate_sha256'] == CAND and d['original_sha256'] == ORIGINAL and d['case_count'] == len(d['cases']) == count and d['mismatches'] == []
          and not any(x['differences'] for x in d['cases']), f'initializer {k}: {count} signed original/candidate pairs, no differences')
    summary['initializer'][k] = dict(cases=d['case_count'], listed=len(d['cases']), mismatches=len(d['mismatches']),
                                     recomputed_bad=sum(bool(x['differences']) for x in d['cases']), candidate_sha256=d['candidate_sha256'],
                                     signed_records=sum(len(x['original_executions']) + len(x['candidate_executions']) for x in d['cases']))
il = load(R / 'initializer/launch.json'); ir = load(R / 'initializer/result.json')
check(il['candidate_sha256'] == CAND and ir['returncode'] == 0 and ir['inputs_unchanged'] and il['controller_sha256'] == sha((R / 'controllers/run_initializer.py').read_bytes()),
      'initializer launch bound to the shipped ELF and controller, exit 0')
d = load(R / 'target-rates/differential.json.gz'); a = load(R / 'target-rates/attested.json.gz')
check(d['candidate_sha256'] == a['candidate_sha256'] == CAND and d['parent_sha256'] == a['control_sha256'] == PARENT and d['original_sha256'] == a['original_sha256'] == ORIGINAL
      and d['case_count'] == len(d['cases']) == 856 and d['mismatches'] == [] and d['log_differences_modulo_cu'] == [] and d['candidate_vs_parent_differences'] == []
      and all(x['equal'] and x['logs_equal_modulo_cu'] for x in d['cases']) and len(a['records']) == 3 and all(len(v) == 856 for v in a['records'].values()),
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
print('Not checked here: ' + ('' if WHOLE_EQUAL else 'whole-ELF identity (unequal), ') + 'fresh dependency builds (the recipe reuses the qualified434 rlibs), '
      'signature re-verification of saved transactions (needs solders), arbitrary data/indirect-call equivalence.')
