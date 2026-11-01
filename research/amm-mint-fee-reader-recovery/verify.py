"""Verify the mint-reader source, native builds, original body and signed receipts."""
from pathlib import Path
import difflib, gzip, hashlib, importlib.util, json, tomllib
if not __debug__:
    raise SystemExit('Verification requires Python without -O')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = 'programs/pump-amm/src/utils/transfer_fee.rs'
ORIGINAL = '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
RUSTC = 'c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
CARGO = 'd28444578306fe5a4f40524331411340123004e9e6556322fcabdbe351fe265d'
STRIP = '12415dc01e08e4f606a1a4eac8c197d560c7883161d266312c821bf5db7bf8be'
def digest(data): return hashlib.sha256(data).hexdigest()
def module(name):
    spec = importlib.util.spec_from_file_location('mint_' + name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result
io = module('runtime_check')
document, archive = io.document, io.archive

def source_change(parent):
    before = parent.decode()
    after = before.replace('return Ok(None);', 'return const { Ok(None) };', 1)
    first = after.index('    let Some((older, newer)) = fees else')
    last = after.index('\n}', first)
    replacement = ('    let epoch = Clock::get()?.epoch;\n'
                   '    Ok(fees.map(|(older, newer)| if epoch >= newer.epoch { newer } else { older }))\n\n\n')
    assert after[first:last].count('\n') == replacement.count('\n')
    after = after[:first] + replacement + after[last:]
    after = after.replace('fn decode_transfer_fees(', '#[inline(never)]\nfn decode_transfer_fees(', 1)
    lines = after.splitlines()
    assert '.map_err(|_| error!(PumpAmmError::UnsupportedQuoteMint))?;' in lines[31]
    assert '.ok_or_else(|| error!(PumpAmmError::Overflow)),' in lines[66]
    return after.encode()

def main():
    evidence = document(HERE / 'evidence.json')
    assert evidence['schema'] == 1 and evidence['original_sha256'] == ORIGINAL
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file() and p.name != 'evidence.json' and '__pycache__' not in p.parts}
    assert actual == set(evidence['files'])
    for name, sha in evidence['files'].items(): assert digest((HERE / name).read_bytes()) == sha, name
    for name, sha in evidence['harnesses'].items(): assert digest((ROOT / name).read_bytes()) == sha, name
    harnesses = archive(HERE / 'harness-inputs.tar.gz')
    assert {name: digest(raw) for name, raw in harnesses.items()} == evidence['harnesses']
    sources = {}
    for name, spec in evidence['archives'].items():
        sources[name] = archive(HERE / spec['path'])
        assert len(sources[name]) == 52
        assert {n: digest(raw) for n, raw in sources[name].items()} == spec['inputs']
        assert not any(n.endswith(('.so', '.o', '.a', '.bc')) for n in sources[name])
    parent, proposal = sources['parent'], sources['proposal']
    assert set(parent) == set(proposal) and {n for n in parent if parent[n] != proposal[n]} == {SOURCE}
    assert proposal[SOURCE] == source_change(parent[SOURCE]) == (HERE / 'proposed/transfer_fee.rs').read_bytes()
    patch = ''.join(difflib.unified_diff(parent[SOURCE].decode().splitlines(keepends=True), proposal[SOURCE].decode().splitlines(keepends=True), fromfile='a/' + SOURCE, tofile='b/' + SOURCE))
    assert patch == (HERE / 'source.patch').read_text()
    origins = {n: archive(HERE / ('origins/' + n + '.tar.gz')) for n in ('recipient', 'deposit')}
    composition = document(HERE / 'builds/composition.json')
    for name, key in [('recipient', 'pr383'), ('deposit', 'pr381')]:
        assert digest((HERE / ('origins/' + name + '.tar.gz')).read_bytes()) == composition['parent_archives'][key]['sha256']
    owned = {'programs/pump-amm/src/lib.rs', 'programs/pump-amm/src/instructions/liquidity/deposit.rs'}
    assert all(parent[n] == origins['deposit' if n in owned else 'recipient'][n] for n in parent)
    assert {n: digest(b) for n, b in parent.items()} == composition['source_sha256']
    profile = tomllib.loads(proposal['Cargo.toml'].decode())['profile']['release']
    assert profile == dict(panic='abort', lto=False, **{'codegen-units': 1, 'overflow-checks': True})
    packages = tomllib.loads(proposal['Cargo.lock'].decode())['package']
    locked = document(HERE / 'builds/locked-archives.json.gz')
    assert locked['count'] == 257
    assert locked['sha256'] == {f"{p['name']}-{p['version']}.crate": p['checksum'] for p in packages if p.get('source', '').startswith('registry+')}
    images = {}
    for name, spec in evidence['builds'].items():
        launch, result = document(HERE / spec['launch']), document(HERE / spec['result'])
        log = gzip.decompress((HERE / spec['log']).read_bytes())
        assert result['exit_code'] == 0 and result['compiled_root'] and result['source_unchanged']
        assert digest(log) == result['log_sha256'] and log.count(b'--crate-name pump_amm_recovered ') == 1
        assert b' -C opt-level=3 ' in log
        key = 'proposal' if name == 'repeat' else name
        inputs = evidence['archives'][key]['inputs']
        assert launch['inputs'] == result['source_sha256'] == result['source_after_sha256'] == inputs
        assert launch['tool_sha256'] == {'rust/bin/rustc': RUSTC, 'rust/bin/cargo': CARGO}
        command = launch['command']
        assert command[command.index('--network') + 1] == 'none'
        assert '--locked' in command and '--offline' in command and 'sbpf-solana-solana' in command
        assert not any('evidence/original/' in part for part in command)
        assert result['strip_sha256'] == STRIP and result['strip_command'][1] == '--strip-all'
        images[name] = {kind: gzip.decompress((HERE / spec[kind]).read_bytes()) for kind in ('candidate', 'symbols')}
        for kind, raw in images[name].items():
            assert digest(raw) == result[kind + '_sha256'] and len(raw) == result[kind + '_bytes']
    assert images['proposal'] == images['repeat']
    cli = document(HERE / 'builds/cli-rebuild/result.json.gz')
    assert cli['compiled_root'] and cli['source_unchanged']
    for kind in ('candidate', 'symbols'):
        assert cli[kind + '_sha256'] == digest(images['proposal'][kind])
    cli_log = gzip.decompress((HERE / 'builds/cli-rebuild/build.log.gz').read_bytes())
    assert cli_log.count(b'--crate-name pump_amm_recovered ') == 1
    analysis = module('analysis')
    comparison = analysis.recompute(images=images)
    assert comparison == document(HERE / 'comparison.json')
    for name, size in [('no_const', 1288), ('no_boundary', 1592), ('late_clock', 1320)]:
        folder = HERE / 'controls' / name
        control = archive(folder / 'sources.tar.gz')
        assert set(control) == set(proposal) and {n for n in control if control[n] != proposal[n]} == {SOURCE}
        expected = proposal[SOURCE].decode()
        if name == 'no_const': expected = expected.replace('return const { Ok(None) };', 'return Ok(None);', 1)
        elif name == 'no_boundary': expected = expected.replace('#[inline(never)]\nfn decode_transfer_fees', 'fn decode_transfer_fees')
        else:
            a = expected.index('    let epoch = Clock::get()?.epoch;'); b = expected.index('\n}', a)
            old = parent[SOURCE].decode(); c = old.index('    let Some((older, newer)) = fees else'); d = old.index('\n}', c)
            expected = expected[:a] + old[c:d] + expected[b:]
        assert control[SOURCE].decode() == expected
        launch, result = document(folder / 'launch.json.gz'), document(folder / 'result.json.gz')
        assert launch['inputs'] == result['source_sha256'] == result['source_after_sha256'] == {n: digest(raw) for n, raw in control.items()}
        log = gzip.decompress((folder / 'build.log.gz').read_bytes())
        assert result['compiled_root'] and result['source_unchanged'] and result['exit_code'] == 0
        assert digest(log) == result['log_sha256'] and log.count(b'--crate-name pump_amm_recovered ') == 1
        assert b' -C opt-level=3 ' in log
        raw = gzip.decompress((folder / 'symbols.so.gz').read_bytes()); assert digest(raw) == result['symbols_sha256']
        elf = analysis.image(raw); functions = [f for f in elf.funcs if 'from_mint' in f['name']]
        assert len(functions) == 1 and functions[0]['size'] == size
    full = io.runtime(evidence, images)
    focused = module('focused_check').verify(evidence, images)
    print(f"PASS: 1312-byte normalized mint reader; 730 -> 731, no losses; 9/10 direct callees; {full['cases']} suite cases; {focused['cases']} fresh triples")

if __name__ == '__main__': main()
