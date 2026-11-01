"""Verify a complete caller-body match; its preparation callee remains unequal."""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import json
import re
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
    paths = list(HERE.rglob('*'))
    assert not any(p.is_symlink() for p in paths)
    assert {str(p.relative_to(HERE)) for p in paths if p.is_file() and p.name != 'manifest.json'} == set(manifest)
    assert {str(p.relative_to(HERE)) for p in paths if p.is_dir()} == {
        str(p) for name in manifest for p in Path(name).parents if str(p) != '.'}
    for name, digest in manifest.items():
        assert sha((HERE / name).read_bytes()) == digest, name
    for name, digest in load(HERE / 'external-inputs.json').items():
        assert sha((ROOT / name).read_bytes()) == digest, name
    parent = load(HERE / 'parent.json')
    assert sha((ROOT / parent['path'] / 'manifest.json').read_bytes()) == parent['manifest_sha256']
    assert sha((ROOT / parent['old_path'] / 'manifest.json').read_bytes()) == parent['old_manifest_sha256']
    w = module('payout_windows', ROOT / 'research/fees-composed-frontier188/window_map.py')
    original = (ROOT / 'evidence/original/pump_fees/deployed.so').read_bytes()
    ow = w.windows(original)
    oi = {x['address']: x for x in ow}
    rel = dict(w.m.relocations(original))
    reports, images, source_maps = {}, {}, {}
    for label, total, unique in [('old', 558, 411), ('baseline', 559, 412), ('candidate', 563, 416), ('repeat', 563, 416)]:
        launch = load(HERE / f'builds/{label}-launch.json')
        result = load(HERE / f'builds/{label}-result.json')
        source_label = 'candidate' if label == 'repeat' else label
        sources = {str(p.relative_to(HERE / 'sources' / source_label)).removesuffix('.gz'): sha(gzip.decompress(p.read_bytes()))
                   for p in (HERE / 'sources' / source_label).rglob('*') if p.is_file()}
        assert len(sources) == (42 if label == 'old' else 43) and sources == launch['inputs']
        source_maps[label] = sources
        assert result['exit_code'] == 0 and result['source_unchanged']
        assert sha(read(HERE / f'builds/{label}-build.log')) == result['log_sha256']
        assert '--offline' in launch['command'] and '--locked' in launch['command']
        assert 'sbpf-solana-solana' in launch['command']
        assert sum(x.startswith('--remap-path-prefix=') for x in launch['command']) == 3
        b = read(HERE / f'artifacts/{label}-symbols.so')
        c = read(HERE / f'artifacts/{label}-candidate.so')
        assert sha(b) == result['symbols_sha256'] and sha(c) == result['candidate_sha256']
        assert c != original and c != original[:w.m.elf_layout(original)['elf_extent']]
        images[label] = b, c
        cw = w.windows(b)
        ci = {x['address']: x for x in cw}
        comparison = w.compare(ow, cw)
        assert len(comparison['unique_pairs']) == unique
        sigs, raw = {x['signature'] for x in cw}, {x['raw_sha256'] for x in cw}
        covered = {x['address'] for x in ow if x['signature'] in sigs}
        raw_covered = {x['address'] for x in ow if x['raw_sha256'] in raw}
        assert len(covered) == total and len(raw_covered) == (118 if label == 'old' else 143)
        edges, locations = {}, 0
        for pair in comparison['unique_pairs']:
            a, z = pair['original'], pair['candidate']
            for x, y in zip(w.m.instructions(original, a['address'], a['bytes']), w.m.instructions(b, z['address'], z['bytes'])):
                kind = rel.get(a['address'] + x['offset'], 0) & 0xffffffff
                if kind == 8:
                    try:
                        left = location(w, original, x['lddw_value'])
                    except (AssertionError, ValueError, StopIteration, struct.error):
                        continue
                    assert left == location(w, b, y['lddw_value'])
                    locations += 1
                if 'call_target' in x and kind != 10:
                    edges[a['address'], x['offset']] = oi[x['call_target']]['signature'] == ci[y['call_target']]['signature']
        assert locations == (166 if label in ['old', 'baseline'] else 167)
        assert sum(edges.values()) == {'old': 3310, 'baseline': 3341, 'candidate': 3383, 'repeat': 3383}[label]
        reports[label] = covered, raw_covered, edges, comparison
    expected_sources = {str(p.relative_to(ROOT / parent['old_path'] / 'sources/candidate')).removesuffix('.gz'): sha(read(p.with_name(p.name.removesuffix('.gz'))))
                        for p in (ROOT / parent['old_path'] / 'sources/candidate').rglob('*') if p.is_file()}
    assert source_maps['old'] == expected_sources
    assert source_maps['baseline'] == load(ROOT / parent['path'] / 'manifest.json')['after']
    changed = {k for k in source_maps['baseline'] if source_maps['baseline'][k] != source_maps['candidate'][k]}
    assert changed == {'programs/pump-fees/src/lib.rs', 'programs/pump-fees/src/sharing_update.rs', 'programs/pump-fees/src/instructions/fee_sharing/mod.rs'}
    assert images['old'] == (read(ROOT / parent['old_path'] / 'artifacts/candidate-symbols.so'), read(ROOT / parent['old_path'] / 'artifacts/candidate-candidate.so'))
    assert sha(images['baseline'][0]) == parent['baseline_symbols'] and sha(images['baseline'][1]) == parent['baseline_candidate']
    assert images['repeat'] == images['candidate']
    a, b = reports['baseline'], reports['candidate']
    assert b[0] - a[0] == {204080, 231576, 235304, 236240} and not a[0] - b[0] and a[1] == b[1]
    assert all(not equal or b[2].get(key, False) for key, equal in a[2].items())
    old = reports['old']
    assert old[0] <= b[0] and old[1] <= b[1]
    assert all(not equal or b[2].get(key, False) for key, equal in old[2].items())
    assert {offset: equal for (address, offset), equal in b[2].items() if address == 204080} == {80: False, 1344: True, 1680: True}
    pair = next(p for p in b[3]['unique_pairs'] if p['original']['address'] == 204080)
    assert pair['original']['bytes'] == pair['candidate']['bytes'] == 1688
    assert 199072 not in b[0]  # The actual preparation callee is still unequal.
    left = w.m.instructions(original, 204080, 1688)
    right = w.m.instructions(images['candidate'][0], pair['candidate']['address'], 1688)
    data_offsets = set()
    for x, y in zip(left, right):
        if rel.get(204080 + x['offset'], 0) & 0xffffffff == 8:
            assert w.m.at_address(original, x['lddw_value'], 32) == w.m.at_address(images['candidate'][0], y['lddw_value'], 32)
            data_offsets.add(x['offset'])
    assert data_offsets == {1312, 1328}
    norm = lambda rows: [x for x in rows if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units', x)]
    run = load(HERE / 'runtime/all.json')
    assert run['case_count'] == 17331 and len(run['suites']) == 18 and not run['mismatches']
    assert run['candidate_sha256'] == sha(images['candidate'][1]) and run['original_sha256'] == sha(original)
    assert sum(s['case_count'] for s in run['suites'].values()) == 17331
    for suite in run['suites'].values():
        assert suite['candidate_sha256'] == run['candidate_sha256'] and suite['original_sha256'] == run['original_sha256']
        assert not suite.get('mismatches', suite.get('failures', []))
    sharing = run['suites']['sharing_update']
    assert len(sharing['cases']) == 417
    for row in sharing['cases']:
        assert row['match'] and all(row['original'][k] == row['candidate'][k] for k in ['error', 'before', 'after', 'events', 'inner', 'return', 'transaction_base64'])
    boundary = load(HERE / 'runtime/boundary.json')
    assert len(boundary['cases']) == 24 and not boundary['mismatches']
    assert boundary['candidate_sha256'] == sha(images['candidate'][1])
    for row in boundary['cases']:
        assert row['match'] and all(row['original'][k] == row['candidate'][k] for k in ['error', 'before', 'after', 'events', 'inner', 'return', 'transaction_base64'])
    print('PASS: main559 + old558 -> 563; full 1688-byte caller; preparation callee unequal; 143 raw; 167 Locations; 17331+24 cases; whole ELF unequal')


if __name__ == '__main__':
    verify()
