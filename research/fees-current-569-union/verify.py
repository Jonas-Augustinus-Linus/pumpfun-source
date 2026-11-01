"""Verify transfer adapter/CPI source recovery and bounded execution evidence."""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return path.read_bytes() if path.exists() else gzip.decompress(path.with_name(path.name + '.gz').read_bytes())


def load(path):
    return json.loads(read(path))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def location(w, image, target):
    low, ptr, size, line, column = struct.unpack('<IIQII', w.m.at_address(image, target, 24))
    assert low == 0 and 0 < size <= 300 and 0 < line <= 100000 and 0 < column <= 300
    name = w.m.at_address(image, ptr, size)
    assert name.endswith(b'.rs')
    return name, line, column


def verify():
    manifest = load(HERE / 'manifest.json')
    files = list(HERE.rglob('*'))
    assert not any(p.is_symlink() for p in files)
    assert {str(p.relative_to(HERE)) for p in files if p.is_file() and p.name != 'manifest.json'} == set(manifest)
    assert {str(p.relative_to(HERE)) for p in files if p.is_dir()} == {str(p) for n in manifest for p in Path(n).parents if str(p) != '.'}
    for n, h in manifest.items():
        assert sha((HERE / n).read_bytes()) == h, n
    for n, h in load(HERE / 'external-inputs.json').items():
        assert sha((ROOT / n).read_bytes()) == h, n
    meta = load(HERE / 'parent.json')
    parent = ROOT / meta['path']
    assert sha((parent / 'manifest.json').read_bytes()) == meta['manifest_sha256']
    parent_manifest = load(parent / 'manifest.json')
    assert sha((parent / 'verify.py').read_bytes()) == parent_manifest['verify.py']
    p = module('auth_parent', parent / 'verify.py')
    p.verify()
    w = module('auth_windows', ROOT / 'research/fees-composed-frontier188/window_map.py')
    original = (ROOT / 'evidence/original/pump_fees/deployed.so').read_bytes()
    historical = read(parent / 'artifacts/candidate-symbols.so')
    baseline = read(HERE / 'artifacts/baseline-symbols.so')
    candidate = read(HERE / 'artifacts/candidate-symbols.so')
    stripped = read(HERE / 'artifacts/candidate-candidate.so')
    assert stripped != original and stripped != original[:w.m.elf_layout(original)['elf_extent']]
    sources = {str(f.relative_to(HERE / 'sources/candidate')).removesuffix('.gz'): sha(gzip.decompress(f.read_bytes())) for f in (HERE / 'sources/candidate').rglob('*') if f.is_file()}
    previous = {str(f.relative_to(HERE / 'sources/baseline')).removesuffix('.gz'): sha(gzip.decompress(f.read_bytes())) for f in (HERE / 'sources/baseline').rglob('*') if f.is_file()}
    assert len(sources) == 43 and sources.keys() == previous.keys()
    assert {k for k in sources if sources[k] != previous[k]} == {'programs/pump-fees/src/sharing_update.rs'}
    expected = {str(f.relative_to(parent / 'sources')).removesuffix('.gz'): gzip.decompress(f.read_bytes()) for f in (parent / 'sources').rglob('*') if f.is_file()}
    parser = ROOT / meta['parser_path']
    payout = ROOT / meta['payout_path']
    assert sha((parser / 'manifest.json').read_bytes()) == meta['parser_manifest_sha256']
    assert sha((payout / 'manifest.json').read_bytes()) == meta['payout_manifest_sha256']
    parser_source = (parser / meta['parser_source']).read_bytes()
    assert sha(parser_source) == meta['parser_source_sha256']
    key = 'programs/pump-fees/src/sharing_update.rs'
    old = b'&wsol_mint.key(),&token_program.key()'
    new = b'&anchor_spl::token::spl_token::native_mint::ID,&anchor_spl::token::ID'
    assert expected[key].count(old) == 1 and new in parser_source
    expected[key] = expected[key].replace(old, new)
    old = b'pub quote_mint:InterfaceAccount'
    new = b'#[account(mint::token_program=token_program)]pub quote_mint:InterfaceAccount'
    assert expected[key].count(old) == 1 and new in parser_source
    expected[key] = expected[key].replace(old, new)
    for name, digest in meta['payout_sources'].items():
        data = (payout / 'overrides' / name).read_bytes()
        assert sha(data) == digest
        expected[name] = data
    assert {k: sha(v) for k, v in expected.items()} == previous
    for label in ['baseline', 'candidate', 'repeat']:
        launch, result = load(HERE / f'builds/{label}-launch.json'), load(HERE / f'builds/{label}-result.json')
        assert launch['inputs'] == (previous if label == 'baseline' else sources) and result['source_unchanged'] and result['exit_code'] == 0
        assert '--offline' in launch['command'] and '--locked' in launch['command'] and 'sbpf-solana-solana' in launch['command']
        assert sum(x.startswith('--remap-path-prefix=') for x in launch['command']) == 3
        actual_symbols = baseline if label == 'baseline' else candidate
        actual_stripped = read(HERE / 'artifacts/baseline-candidate.so') if label == 'baseline' else stripped
        assert result['symbols_sha256'] == sha(actual_symbols) and result['candidate_sha256'] == sha(actual_stripped)
        assert sha(read(HERE / f'builds/{label}-build.log')) == result['log_sha256']
    ow = w.windows(original)
    oi = {x['address']: x for x in ow}
    rel = dict(w.m.relocations(original))
    reports = {}
    for label, image, total, unique, locations_expected, equal_expected in [('historical', historical, 564, 417, 168, 3392), ('baseline', baseline, 566, 419, 168, 3623), ('candidate', candidate, 569, 422, 168, 3656)]:
        cw = w.windows(image)
        ci = {x['address']: x for x in cw}
        result = w.compare(ow, cw)
        assert len(result['unique_pairs']) == unique
        sigs, raw = {x['signature'] for x in cw}, {x['raw_sha256'] for x in cw}
        covered = {x['address'] for x in ow if x['signature'] in sigs}
        raw_covered = {x['address'] for x in ow if x['raw_sha256'] in raw}
        assert len(covered) == total and len(raw_covered) == 143
        edges, locations = {}, 0
        for pair in result['unique_pairs']:
            a, b = pair['original'], pair['candidate']
            for x, y in zip(w.m.instructions(original, a['address'], a['bytes']), w.m.instructions(image, b['address'], b['bytes'])):
                kind = rel.get(a['address'] + x['offset'], 0) & 0xffffffff
                if kind == 8:
                    try:
                        left = location(w, original, x['lddw_value'])
                    except (AssertionError, ValueError, StopIteration, struct.error):
                        continue
                    assert left == location(w, image, y['lddw_value'])
                    locations += 1
                if 'call_target' in x and kind != 10:
                    edges[a['address'], x['offset']] = oi[x['call_target']]['signature'] == ci[y['call_target']]['signature']
        assert locations == locations_expected and sum(edges.values()) == equal_expected
        reports[label] = covered, raw_covered, edges, result, ci
    a, b = reports['baseline'], reports['candidate']
    assert b[0] - a[0] == {237464, 582624, 586976} and not a[0] - b[0] and a[1] == b[1]
    assert all(not equal or b[2].get(key, False) for key, equal in a[2].items())
    h = reports['historical']
    assert h[0] <= b[0] and h[1] <= b[1]
    assert all(not equal or b[2].get(key, False) for key, equal in h[2].items())
    parser_report = load(parser / 'expected.json')['reports']['candidate']
    assert set(parser_report['normalized_inventory']) <= b[0]
    assert set(parser_report['raw_inventory']) <= b[1]
    assert {484816, 502096} <= b[0]
    for target, size, calls in [(237464, 2624, 13), (582624, 4352, 10), (586976, 4608, 10)]:
        actual = {offset: equal for (address, offset), equal in b[2].items() if address == target}
        assert len(actual) == calls and all(actual.values())
        pair = next(x for x in b[3]['unique_pairs'] if x['original']['address'] == target)
        assert pair['original']['bytes'] == pair['candidate']['bytes'] == size
        left = {x['offset']: x for x in w.m.instructions(original, target, size)}
        right = {x['offset']: x for x in w.m.instructions(candidate, pair['candidate']['address'], size)}
        assert not any(x['opcode'] == 0x8d for x in left.values())
        data = {offset for offset in left if rel.get(target + offset, 0) & 0xffffffff == 8}
        assert data == ({192} if target == 237464 else set())
        for offset in data:
            assert w.m.at_address(original, left[offset]['lddw_value'], 32) == bytes(32)
            assert w.m.at_address(candidate, right[offset]['lddw_value'], 32) == bytes(32)
    assert 240088 not in b[0]  # The V2 outer adapter remains unmatched.
    run = load(HERE / 'runtime.json')
    assert run['case_count'] == 17331 and len(run['suites']) == 18 and not run['mismatches']
    assert run['candidate_sha256'] == sha(stripped) and run['original_sha256'] == sha(original)
    assert sum(s['case_count'] for s in run['suites'].values()) == 17331
    for suite in run['suites'].values():
        assert suite['candidate_sha256'] == sha(stripped) and suite['original_sha256'] == sha(original)
        assert len(suite['cases']) == suite['case_count']
        assert not suite.get('mismatches', suite.get('failures', []))
    boundary = load(HERE / 'native-boundary-runtime.json')
    assert boundary['case_count'] == len(boundary['cases']) == 119
    assert boundary['hashes']['proposal'] == sha(stripped) and boundary['hashes']['original'] == sha(original)
    assert boundary['hashes']['control'] == sha(read(payout / 'artifacts/baseline-candidate.so'))
    assert not boundary['mismatches']['proposal'] and len(boundary['mismatches']['control']) == 38
    for row in boundary['cases']:
        assert not row['differences']['proposal']
        assert all(row['results']['original'][k] == row['results']['proposal'][k] for k in boundary['fields'])
    quote = load(HERE / 'quote-owner-runtime.json')
    assert quote['candidate_sha256'] == sha(stripped) and quote['original_sha256'] == sha(original)
    assert len(quote['cases']) == 8 and not quote['mismatches']
    for row in quote['cases']:
        assert row['match'] and all(row['original'][k] == row['candidate'][k] for k in ['error', 'before', 'after', 'events', 'inner', 'return', 'transaction_base64'])
        app = lambda value: [line for line in value['logs'] if line.startswith(('Program log:', 'Program data:', 'Program return:'))]
        assert app(row['original']) == app(row['candidate'])
    prep = load(HERE / 'preprocess-runtime.json')
    assert prep['candidate_sha256'] == sha(stripped) and prep['original_sha256'] == sha(original)
    assert len(prep['cases']) == 24 and not prep['mismatches']
    for row in prep['cases']:
        assert row['match'] and all(row['original'][k] == row['candidate'][k] for k in ['error', 'before', 'after', 'events', 'inner', 'return', 'transaction_base64'])
    print('PASS: current Fees union569; parser and arithmetic recoveries retained; 33 new transfer callees; 17331+119+8+24 cases; whole ELF unequal')


if __name__ == '__main__':
    verify()
