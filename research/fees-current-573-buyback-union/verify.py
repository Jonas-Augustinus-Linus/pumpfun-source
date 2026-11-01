"""Verify current Fees573 union with the merged SweepBuyback source proposal."""
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
    assert dict(w.m.relocations(image)).get(target, 0) & 0xffffffff == 8
    low, ptr, n, line, column = struct.unpack('<IIQII', w.m.at_address(image, target, 24))
    assert low == 0 and 0 < n <= 300 and 0 < line <= 100000 and 0 < column <= 300
    name = w.m.at_address(image, ptr, n)
    assert name.endswith(b'.rs') and all(32 <= c < 127 for c in name)
    return name.decode(), line, column


def data_objects(w, original, candidate, address, left, right, oi, ci):
    assert address == 225920
    blobs = {k:4 for k in [40,184,1264,1408,1688,1832,2936,3080,3408,3552]}
    blobs.update({k:71 for k in [1120,1544,1968,3216,3984]})
    blobs.update({232:55,4616:16,4632:16,4960:32,5096:17})
    tables = {88:48,1312:48,1736:48,2984:48,3456:48,256:32}
    locations = [272]
    seen = set()
    for offset, size in blobs.items():
        assert w.m.at_address(original, left[offset]['lddw_value'], size) == w.m.at_address(candidate, right[offset]['lddw_value'], size)
        seen.add(offset)
    for offset, size in tables.items():
        pointers = {0,24,32,40} if size == 48 else {0,24}
        for k in range(0, size, 8):
            x = struct.unpack('<Q', w.m.at_address(original,left[offset]['lddw_value']+k,8))[0]
            y = struct.unpack('<Q', w.m.at_address(candidate,right[offset]['lddw_value']+k,8))[0]
            if k in pointers:
                assert x & 0xffffffff == y & 0xffffffff == 0
                assert oi[x >> 32]['signature'] == ci[y >> 32]['signature']
            else:
                assert x == y
        seen.add(offset)
    for offset in locations:
        assert location(w,original,left[offset]['lddw_value']) == location(w,candidate,right[offset]['lddw_value'])
        seen.add(offset)
    refs = {offset for offset in left if dict(w.m.relocations(original)).get(address+offset,0)&0xffffffff==8}
    assert seen == refs


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
    baseline = read(parent / 'artifacts/candidate-symbols.so')
    candidate = read(HERE / 'artifacts/candidate-symbols.so')
    stripped = read(HERE / 'artifacts/candidate-candidate.so')
    assert stripped != original and stripped != original[:w.m.elf_layout(original)['elf_extent']]
    sources = {str(f.relative_to(HERE / 'sources')).removesuffix('.gz'): sha(gzip.decompress(f.read_bytes())) for f in (HERE / 'sources').rglob('*') if f.is_file()}
    previous = {str(f.relative_to(parent / 'sources')).removesuffix('.gz'): sha(gzip.decompress(f.read_bytes())) for f in (parent / 'sources').rglob('*') if f.is_file()}
    assert len(sources) == 44 and sources.keys() == previous.keys()
    changed = {'programs/pump-fees/src/buyback.rs', 'programs/pump-fees/src/state.rs', 'programs/pump-fees/src/instructions/buyback/mod.rs'}
    assert {k for k in sources if sources[k] != previous[k]} == changed
    for name in changed:
        original_path = 'research/fees-sweep-buyback-source-proposal/overrides/' + name
        assert sources[name] == sha((ROOT / original_path).read_bytes())
    for label in ['candidate', 'repeat']:
        launch, result = load(HERE / f'builds/{label}-launch.json'), load(HERE / f'builds/{label}-result.json')
        assert launch['inputs'] == sources and result['source_unchanged'] and result['exit_code'] == 0
        assert '--offline' in launch['command'] and '--locked' in launch['command'] and 'sbpf-solana-solana' in launch['command']
        assert sum(x.startswith('--remap-path-prefix=') for x in launch['command']) == 3
        assert result['symbols_sha256'] == sha(candidate) and result['candidate_sha256'] == sha(stripped)
        assert sha(read(HERE / f'builds/{label}-build.log')) == result['log_sha256']
    ow = w.windows(original)
    oi = {x['address']: x for x in ow}
    rel = dict(w.m.relocations(original))
    reports = {}
    for label, image, total, unique, locations_expected, equal_expected in [('baseline', baseline, 573, 426, 171, 3765), ('candidate', candidate, 573, 426, 171, 3765)]:
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
    assert b[0] - a[0] == set() and not a[0] - b[0] and a[1] == b[1]
    assert all(not equal or b[2].get(key, False) for key, equal in a[2].items())
    assert 120816 not in b[0]
    sweep = [row for row in b[4].values() if '12instructions7buyback13sweep_buyback' in (row['name'] or '')]
    assert len(sweep) == 1 and sweep[0]['bytes'] == 6984
    run = load(HERE / 'runtime.json')
    assert run['case_count'] == 17331 and len(run['suites']) == 18 and not run['mismatches']
    assert run['candidate_sha256'] == sha(stripped) and run['original_sha256'] == sha(original)
    assert sum(s['case_count'] for s in run['suites'].values()) == 17331
    for suite in run['suites'].values():
        assert suite['candidate_sha256'] == sha(stripped) and suite['original_sha256'] == sha(original)
        assert len(suite['cases']) == suite['case_count']
        assert not suite.get('mismatches', suite.get('failures', []))
    for name, count in [('quote-owner-runtime.json', 8), ('preprocess-runtime.json', 24)]:
        current = load(HERE / name)
        previous_run = load(parent / name)
        assert current['candidate_sha256'] == sha(stripped) and current['original_sha256'] == sha(original)
        assert len(current['cases']) == count and not current['mismatches']
        for old, row in zip(previous_run['cases'], current['cases']):
            assert old['case'] == row['case']
            assert row['match'] and all(row['original'][k] == row['candidate'][k] for k in ['error', 'before', 'after', 'events', 'inner', 'return', 'transaction_base64'])
            if name == 'quote-owner-runtime.json':
                app = lambda value: [line for line in value['logs'] if line.startswith(('Program log:', 'Program data:', 'Program return:'))]
                assert app(row['original']) == app(row['candidate'])
    boundary = load(HERE / 'native-boundary-runtime.json')
    old_boundary = load(parent / 'native-boundary-runtime.json')
    assert boundary['case_count'] == len(boundary['cases']) == 119
    assert boundary['hashes']['proposal'] == sha(stripped) and boundary['hashes']['original'] == sha(original)
    assert boundary['hashes']['control'] == old_boundary['hashes']['control']
    assert not boundary['mismatches']['proposal'] and len(boundary['mismatches']['control']) == 38
    for old, row in zip(old_boundary['cases'], boundary['cases']):
        assert old['case'] == row['case']
        assert not row['differences']['proposal'] and all(row['results']['original'][k] == row['results']['proposal'][k] for k in boundary['fields'])
    old_run = load(parent / 'runtime.json')
    application = lambda value: [line for line in value['logs'] if line.startswith(('Program log:', 'Program data:', 'Program return:'))]
    old_cases, new_cases = old_run['suites']['buyback']['cases'], run['suites']['buyback']['cases']
    assert len(old_cases) == len(new_cases) == 1249
    assert sum(application(c['original']) != application(c['candidate']) for c in old_cases) == 275
    for old, new in zip(old_cases, new_cases):
        assert old['case'] == new['case']
        assert application(old['original']) == application(new['original']) == application(new['candidate'])
    print('PASS: current Fees573 union; merged buyback source;275 log differences repaired;143raw;171Locations;wholeELFunequal')


if __name__ == '__main__':
    verify()
