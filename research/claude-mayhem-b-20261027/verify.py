"""Verify a lane mayhem-b checkpoint with the standard library only.

python -B research/claude-mayhem-b-20261027/verify.py [--checkpoint NAME]

Checks, for the checkpoint directory (default: the newest one with a SHA256SUMS
covering every file):
  1. SHA256SUMS covers exactly the files present.
  2. The 432 parent source is rebuilt from the committed parent packet chain and equals
     research/mayhem-quotes-current-recovery-20261027/source-inputs.json (67 files).
  3. parent + overrides == source-inputs.json, and source.patch is the unified diff of
     exactly those overrides.
  4. The gzipped ELFs hash to the recorded build result; the build used these sources,
     exited 0, and its stderr has no "Stack offset ... exceeded max offset" warning.
  5. Window progress versus the parent symbols (progress.compare from the initializer
     packet) equals analysis/progress.json, with 432 normalized / 100 raw and no losses.
  6. The runtime receipts are bound to this candidate: sweep differential report
     (all cases equal, zero non-compute log differences recomputed here) and the trade
     suite summary.
Nothing here reads HOME or any toolchain.
"""
from pathlib import Path, PurePosixPath
import argparse, difflib, gzip, hashlib, importlib.util, json, re, sys, tarfile

if not __debug__:
    raise RuntimeError('verification requires assertions')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT_DIGEST = '73dff97e65535ce7d2552ba6f29f94fe0e08ebd414a51871a81c6cba2d7d6168'
PARENT_SYMBOLS = '440b92811753dd9af1468f6bf2d0e9139309984de3519a8f9a937babfdb6c903'
CU = re.compile(r'consumed \d+ of \d+ compute units')
sha = lambda b: hashlib.sha256(b).hexdigest()


def raw(p):
    b = Path(p).read_bytes()
    return gzip.decompress(b) if str(p).endswith('.gz') else b


def load(p):
    return json.loads(raw(p))


def module(n, p):
    s = importlib.util.spec_from_file_location(n, p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def parent_sources():
    """The 432 parent exactly as research/mayhem-quotes-current-recovery-20261027/verify.py composes it."""
    I = ROOT / 'research/mayhem-initializer-current-recovery-20261027'
    O = ROOT / 'research/mayhem-current-ownership-composition-20261027'
    S = ROOT / 'research/mayhem-sell-current-recovery-20261027'
    Q = ROOT / 'research/mayhem-quotes-current-recovery-20261027'
    out = {}
    with tarfile.open(I / 'source.tar.gz') as t:
        for m in t:
            n = PurePosixPath(m.name)
            assert m.isfile() and not n.is_absolute() and '..' not in n.parts and str(n) == m.name and m.name not in out
            out[m.name] = t.extractfile(m).read()
    out['src/instructions/pump_interface.rs'] = raw(O / 'sources/qualified.rs')
    for n in ['src/state.rs', 'src/instructions/sell_pump_swap.rs']:
        out[n] = raw(S / 'overrides' / n)
    for n in ['src/instructions/buy_pump_swap.rs', 'src/state.rs']:
        out[n] = raw(Q / 'overrides' / n)
    assert {n: sha(b) for n, b in out.items()} == load(Q / 'source-inputs.json') and len(out) == 67
    return out


def verify(C):
    # 1. manifest
    files = {p.relative_to(C).as_posix(): p for p in C.rglob('*') if p.is_file()}
    assert not any(p.is_symlink() for p in C.rglob('*')), 'symlink'
    sums = {}
    for line in (C / 'SHA256SUMS').read_text().splitlines():
        h, n = line.split('  ', 1)
        sums[n] = h
    assert set(sums) == set(files) - {'SHA256SUMS'}, sorted(set(sums) ^ (set(files) - {'SHA256SUMS'}))
    for n, h in sums.items():
        assert sha(files[n].read_bytes()) == h, ('hash', n)
    assert not any(n.endswith('.pyc') or '__pycache__' in n for n in files)

    # 2-3. sources
    parent = parent_sources()
    expected = dict(parent)
    overrides = sorted(n[len('overrides/'):] for n in files if n.startswith('overrides/'))
    patch = []
    for n in overrides:
        assert n in parent, n
        expected[n] = (C / 'overrides' / n).read_bytes()
        assert expected[n] != parent[n], n
        patch.extend(difflib.unified_diff(parent[n].decode().splitlines(True), expected[n].decode().splitlines(True),
                                          fromfile='a/' + n, tofile='b/' + n))
    assert ''.join(patch).encode() == (C / 'source.patch').read_bytes(), 'source.patch'
    inputs = {n: sha(b) for n, b in expected.items()}
    assert inputs == load(C / 'source-inputs.json'), 'source-inputs'

    # 4. build
    cand, syms = raw(C / 'candidate.so.gz'), raw(C / 'symbols.so.gz')
    r, l = load(C / 'build/result.json'), load(C / 'build/launch.json')
    assert r['returncode'] == 0 and r['source_unchanged'] and r['tools_unchanged'] and r['target_libraries_unchanged']
    assert sha(cand) == r['candidate_sha256'] and sha(syms) == r['symbols_sha256'] and len(cand) == r['candidate_bytes']
    assert (C / 'ELF-SHA256.txt').read_text() == f'candidate.so {sha(cand)}\nsymbols.so {sha(syms)}\n'
    assert l['source_inputs'] == inputs, 'build used different sources'
    assert l['command'][l['command'].index('--target') + 1] == 'sbpf-solana-solana'
    assert l['linker_script_sha256'] == sha(raw(ROOT / 'research/mayhem-quotes-current-recovery-20261027/layout/ordered.ld'))
    assert l['target_inputs'] == load(ROOT / 'research/mayhem-provider-sharing/builds/recovered/launch.json')['target_inputs']
    stderr = raw(C / 'build/stderr.gz')
    assert sha(stderr) == r['stderr_sha256'] and b'exceeded max offset' not in stderr and b'Stack offset' not in stderr

    # 5. progress versus the parent
    original = (ROOT / 'evidence/original/mayhem/deployed.so').read_bytes()
    psyms = raw(ROOT / 'research/mayhem-quotes-current-recovery-20261027/builds/current/symbols.so.gz')
    assert sha(psyms) == PARENT_SYMBOLS
    progress = module('lane_b_progress', ROOT / 'research/mayhem-initializer-current-recovery-20261027/progress.py')
    p = progress.compare(original, psyms, syms)
    p['scope'] = 'Lane mayhem-b checkpoint versus the 432 quotes-current parent symbols (440b9281...).'
    assert p == load(C / 'analysis/progress.json'), 'progress'
    assert p['baseline_matches'] == 432 and p['matches'] >= 432 and p['raw_matches'] >= 100 and not p['body_losses']
    assert cand != original

    # 6. runtime receipts
    rt = load(C / 'runtime/summary.json')
    assert rt['candidate_sha256'] == sha(cand)
    sw = load(C / 'runtime/sweeps.json.gz')
    assert sw['candidate_sha256'] == sha(cand) and sw['original_sha256'] == sha(original)
    assert sw['case_count'] == len(sw['cases']) == rt['sweeps']['case_count'] and not sw['mismatches']
    assert all(c['equal'] for c in sw['cases'])
    clean = lambda logs: [x for x in logs if not CU.search(x)]
    diffs = sum(clean(c['original']['logs']) != clean(c['candidate']['logs']) for c in sw['cases'])
    assert diffs == rt['sweeps']['noncompute_log_differences']
    assert rt['trade_mismatches'] == 0 and rt['trade_cases'] == sum(v['cases'] for v in rt['trades'].values())
    for fam, v in rt['trades'].items():
        assert v['mismatches'] == 0, fam
    trade_dir = C / 'runtime/trades'
    if trade_dir.exists():
        for fam, v in rt['trades'].items():
            rep = load(trade_dir / f'{fam}.json.gz')
            assert sha(raw(trade_dir / f'{fam}.json.gz')) == v['report_sha256'] and rep['candidate_sha256'] == sha(cand)
            assert rep['case_count'] == v['cases'] and not rep['mismatches']
    return {'checkpoint': C.name, 'candidate_sha256': sha(cand), 'symbols_sha256': sha(syms),
            'overrides': overrides, 'normalized': p['matches'], 'raw': p['raw_matches'], 'gains': p['gains'],
            'sweep_cases': sw['case_count'], 'sweep_noncompute_log_differences': diffs,
            'parent_sweep_noncompute_log_differences': rt['parent_sweeps']['noncompute_log_differences'],
            'trade_cases': rt['trade_cases'], 'trade_normalized_log_differences': rt['trade_normalized_log_differences']}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--checkpoint', default=None)
    a = ap.parse_args()
    cps = sorted(d for d in (HERE / 'checkpoints').iterdir() if (d / 'source-inputs.json').exists())
    C = (HERE / 'checkpoints' / a.checkpoint) if a.checkpoint else cps[-1]
    print(json.dumps(verify(C.resolve()), indent=2))
