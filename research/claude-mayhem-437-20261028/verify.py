#!/usr/bin/env python3
"""Verify the historical PR417 packet from saved evidence; no compiler or VM.

Requires this repository's hash-pinned original image, parent436 images and
existing reader. Recomputes the full 441-window census and O0079 body match.
Saved sweep output equality is checked; trade execution remains producer-reported
because its per-family signed records were not included in this historical packet.
"""
import gzip, hashlib, importlib.util, json, re, sys
from pathlib import Path, PurePosixPath

if not __debug__:
    raise SystemExit('run with assertions enabled')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = next(p for p in HERE.parents if (p / 'evidence/original/mayhem/deployed.so').is_file())
CAND = '4bfd62f2550fdcf75d3e40c2ee0e11a2fe92df66bff2a4c2a08018f97755413f'
SYMS = '847485d3368e14226ad041ba257c1190ca39858734761bb8169ec24f5f6d603b'
ORIGINAL = 'a87fa9f866272514e6acb852b668c4a08aeb173d56c883039991d114d1199bdb'  # evidence/original/mayhem/deployed.so
P436 = 'research/claude-mayhem-436-20261027'
PATCHED = 'src/instructions/sell_pump_swap.rs'
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

# 2. sources
pinv = json.loads((HERE / 'sources/source-inputs.parent436.json').read_text())
sinv = json.loads((HERE / 'sources/source-inputs.json').read_text())
check(len(pinv) == len(sinv) == 67 and set(pinv) == set(sinv), 'parent and shipped inventories list the same 67 crate inputs')
check([k for k in sorted(pinv) if pinv[k] != sinv[k]] == [PATCHED], 'the 437 tree differs from parent-436 only in sell_pump_swap.rs')
if (REPO / P436 / 'sources/source-inputs.json').is_file():
    check(json.loads((REPO / P436 / 'sources/source-inputs.json').read_text()) == pinv, 'parent-436 inventory == the 436 tree merged on main (PR #404)')
    check((REPO / P436 / 'sources/shipped/instructions/sell_pump_swap.rs').read_bytes() == (HERE / 'sources/parent/instructions/sell_pump_swap.rs').read_bytes(),
          'sources/parent/sell_pump_swap.rs == main 436 shipped file')
else:
    raise AssertionError('parent436 source evidence is required')


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
check(patch[0] == '--- a/programs/mayhem/' + PATCHED and patch[1] == '+++ b/programs/mayhem/' + PATCHED
      and sum(ln.startswith('+++ ') for ln in patch) == 1, 'source.patch touches only sell_pump_swap.rs')
hunks = patch[2:]
while hunks and hunks[-1] == '':
    hunks = hunks[:-1]
pb = (HERE / 'sources/parent/instructions/sell_pump_swap.rs').read_bytes()
sb = (HERE / 'sources/shipped/instructions/sell_pump_swap.rs').read_bytes()
check(sha(pb) == pinv[PATCHED] and sha(sb) == sinv[PATCHED], 'parent/shipped sell_pump_swap.rs match their inventories')
check(apply_unified(pb.decode().split('\n'), hunks) == sb.decode().split('\n'), 'source.patch reproduces shipped sell_pump_swap.rs')
check(pb.count(b'\n') == sb.count(b'\n'), f'line count preserved ({sb.count(chr(10).encode())})')

# 3. ELFs + builds
br = json.loads((HERE / 'builds/build-result.json').read_text())
rr = json.loads((HERE / 'builds/repeat-build-result.json').read_text())
check(sha(raw(HERE / 'builds/candidate.so.gz')) == CAND == br['candidate_sha256'], 'candidate.so.gz == clean-build stripped digest 4bfd62f2')
check(sha(raw(HERE / 'builds/symbols.so.gz')) == SYMS == br['symbols_sha256'], 'symbols.so.gz == clean-build symbols digest 847485d3')
check(rr['candidate_sha256'] == CAND, 'second (incremental) build record reports the same stripped ELF digest')
for name, r in [('build-result', br), ('repeat-build-result', rr)]:
    check(r['returncode'] == 0 and r['source_unchanged'] and r['tools_unchanged'] and r['target_libraries_unchanged'], f'{name}: exit 0, inputs unchanged')
la, lb = (json.loads((HERE / f'builds/{n}.json').read_text()) for n in ('launch', 'repeat-launch'))
check(la['clean_anchor'] and la['environment_overrides']['CARGO_TARGET_DIR'] != lb['environment_overrides']['CARGO_TARGET_DIR'],
      'clean build: own fresh target dir, anchor re-cleaned')
check(la['source_inputs'] == lb['source_inputs'] == sinv, 'both builds compiled exactly the shipped 67-file tree')
stderr = raw(HERE / 'builds/build-stderr.gz').decode('utf-8', 'replace')
check('exceeded max offset' not in stderr and 'Stack offset' not in stderr, 'no stack-offset warning')

# 4. measurement
m = json.loads((HERE / 'measurement/measure-vs-parent436.json').read_text())
check(m['candidate_symbols_sha256'] == SYMS, 'measurement bound to the shipped symbols ELF')
check(m['gains'] == ['O0079'], 'vs parent-436: gains are exactly O0079')
check(m['no_losses'] and not any(m[k] for k in ('body_losses', 'raw_losses', 'profile_losses', 'edge_losses', 'source_losses')),
      'vs parent-436: no losses of any kind (body/raw/profile/edge/source)')
c = m['counts']
check((c['matched_before'], c['matched_after']) == (436, 437) and c['raw_after'] >= c['raw_before'] and c['edges_after'] >= c['edges_before']
      and c['source_after'] >= c['source_before'], f'436 -> 437 normalized windows; raw {c["raw_before"]}->{c["raw_after"]}, '
      f'edges {c["edges_before"]}->{c["edges_after"]}, source {c["source_before"]}->{c["source_after"]}')
check(m['unmatched_ids'] == ['O0076', 'O0077', 'O0083', 'O0084'], 'remaining unmatched: O0076 O0077 O0083 O0084')

# Independently recompute the saved ELF census; no measurement booleans are trusted.
spec = importlib.util.spec_from_file_location('historical417_elf_check', HERE / 'elf_check.py')
elf_check = importlib.util.module_from_spec(spec); spec.loader.exec_module(elf_check)
actual = elf_check.inspect(REPO, HERE)
check(actual == json.loads((HERE / 'measurement/recomputed-elf.json').read_text()),
      'actual ELF: full 441-window census, O0079 normalized body, calls and Source profiles')
check((sum(v for k,v in actual['parent']['counts'].items() if k != 'unmatched'),
       sum(v for k,v in actual['candidate']['counts'].items() if k != 'unmatched')) == (c['matched_before'], c['matched_after'])
      and actual['candidate']['counts']['raw'] == c['raw_after']
      and actual['parent']['counts']['raw'] == c['raw_before']
      and actual['parent']['positive_edges'] == c['edges_before']
      and actual['candidate']['positive_edges'] == c['edges_after']
      and actual['parent']['positive_Source'] == c['source_before']
      and actual['candidate']['positive_Source'] == c['source_after'],
      'saved measurement totals agree with recomputed ELF totals')

# 5. historical output records (no signed trade receipts are present)

CU = re.compile(r'consumed \d+ of \d+ compute units')
FIELDS = ['error', 'accounts', 'events', 'inner', 'return_data']
state = lambda r: {k: r[k] for k in FIELDS}
logs = lambda r: [CU.sub('consumed <cu>', x) for x in r['logs']]
sw = json.loads(raw(HERE / 'runtime/sweeps-differential.json.gz'))
check(sw['candidate_sha256'] == CAND and sw['original_sha256'] == ORIGINAL, 'saved sweep output record names the shipped ELF and deployed original digests')
check(sw['case_count'] == len(sw['cases']) == 692 and sw['mismatches'] == [], 'stock sweep: 692 cases, 0 recorded mismatches')
check(all(c['equal'] and state(c['original']) == state(c['candidate']) and logs(c['original']) == logs(c['candidate']) for c in sw['cases']),
      'saved stock sweep outputs: state, errors, events, CPIs, return data and logs (mod CU) equal on all 692')
t = json.loads((HERE / 'runtime/trades-summary.json').read_text())
check(t['candidate_sha256'] == CAND, 'trade summary bound to the shipped stripped ELF')
runs = t['runs']
check(len(runs) == 14 and len({r['family'] for r in runs}) == 14 and all(
    r['returncode'] == 0 and r['cases'] == r['expected_cases'] and r['mismatches'] == 0 and r['noncompute_log_diffs'] == 0 for r in runs),
    'producer-reported trade summary: 14 families, exit 0, full counts and zero differences')
check(sum(r['cases'] for r in runs) == t['total_cases'] == 6636 and t['total_mismatches'] == 0 and t['total_noncompute_log_diffs'] == 0
      and t['all_ok'], 'producer-reported trade summary: 6636 cases total, 0 mismatches')

print('\n'.join('  OK  ' + x for x in ok))
print(f'\nPASS - {len(ok)} checks')

print('Historical trade execution is producer-reported only; full signed runtime records are absent.')
