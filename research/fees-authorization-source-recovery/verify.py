"""Verify ordinary Rust authorization recovery and bounded execution evidence."""
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
    previous = {str(f.relative_to(parent / 'sources/candidate')).removesuffix('.gz'): sha(gzip.decompress(f.read_bytes())) for f in (parent / 'sources/candidate').rglob('*') if f.is_file()}
    assert len(sources) == 43 and sources.keys() == previous.keys()
    assert {k for k in sources if sources[k] != previous[k]} == {'programs/pump-fees/src/sharing_update.rs', 'programs/pump-fees/src/instructions/fee_sharing/mod.rs'}
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
    for label, image, total, unique, locations_expected, equal_expected in [('baseline', baseline, 563, 416, 167, 3383), ('candidate', candidate, 564, 417, 168, 3392)]:
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
                        left = p.location(w, original, x['lddw_value'])
                    except (AssertionError, ValueError, StopIteration, struct.error):
                        continue
                    assert left == p.location(w, image, y['lddw_value'])
                    locations += 1
                if 'call_target' in x and kind != 10:
                    edges[a['address'], x['offset']] = oi[x['call_target']]['signature'] == ci[y['call_target']]['signature']
        assert locations == locations_expected and sum(edges.values()) == equal_expected
        reports[label] = covered, raw_covered, edges, result, ci
    a, b = reports['baseline'], reports['candidate']
    assert b[0] - a[0] == {234096} and not a[0] - b[0] and a[1] == b[1]
    assert all(not equal or b[2].get(key, False) for key, equal in a[2].items())
    assert len([k for k in b[2] if k[0] == 234096]) == 9
    assert all(equal for (address, offset), equal in b[2].items() if address == 234096)
    pair = next(x for x in b[3]['unique_pairs'] if x['original']['address'] == 234096)
    assert pair['original']['bytes'] == pair['candidate']['bytes'] == 1208
    left = {x['offset']: x for x in w.m.instructions(original, 234096, 1208)}
    right = {x['offset']: x for x in w.m.instructions(candidate, pair['candidate']['address'], 1208)}
    assert not any(x['opcode'] == 0x8d for x in left.values())
    seen = set()
    for offset, size in [(288, 4), (432, 4), (488, 4), (632, 4), (680, 55), (840, 54), (1080, 54)]:
        assert w.m.at_address(original, left[offset]['lddw_value'], size) == w.m.at_address(candidate, right[offset]['lddw_value'], size)
        seen.add(offset)
    for offset, size, pointers in [(336, 48, {0, 24, 32, 40}), (536, 48, {0, 24, 32, 40}), (704, 32, {0, 24})]:
        for k in range(0, size, 8):
            x = struct.unpack('<Q', w.m.at_address(original, left[offset]['lddw_value'] + k, 8))[0]
            y = struct.unpack('<Q', w.m.at_address(candidate, right[offset]['lddw_value'] + k, 8))[0]
            if k in pointers:
                assert x & 0xffffffff == y & 0xffffffff == 0
                assert oi[x >> 32]['signature'] == b[4][y >> 32]['signature']
            else:
                assert x == y
        seen.add(offset)
    assert p.location(w, original, left[720]['lddw_value']) == p.location(w, candidate, right[720]['lddw_value'])
    seen.add(720)
    assert seen == {offset for offset in left if rel.get(234096 + offset, 0) & 0xffffffff == 8}
    run = load(HERE / 'runtime.json')
    assert run['case_count'] == 17331 and len(run['suites']) == 18 and not run['mismatches']
    assert run['candidate_sha256'] == sha(stripped) and run['original_sha256'] == sha(original)
    assert sum(s['case_count'] for s in run['suites'].values()) == 17331
    for suite in run['suites'].values():
        assert suite['candidate_sha256'] == sha(stripped) and suite['original_sha256'] == sha(original)
        assert len(suite['cases']) == suite['case_count']
        assert not suite.get('mismatches', suite.get('failures', []))
    print('PASS: Fees563 -> 564; 1208-byte authorization; 9 callees and all 11 data objects; 143 raw; 168 Locations; whole ELF unequal')


if __name__ == '__main__':
    verify()
