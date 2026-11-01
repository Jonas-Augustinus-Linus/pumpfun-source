"""Recheck reconstructed Sharing code and saved native evidence without execution."""
from pathlib import Path
from collections import Counter
from functools import lru_cache
import argparse
import contextlib
import difflib
import gzip
import hashlib
import importlib.util
import io
import json
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT = ROOT / 'research/fees-common-quote-data-order'
SOURCE = 'programs/pump-fees/src/instructions/fee_sharing/create_fee_sharing_config.rs'
SHARING = 177720


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    if path.is_file():
        return path.read_bytes()
    return gzip.decompress(path.with_name(path.name + '.gz').read_bytes())


def load(path):
    return json.loads(read(path))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def check_manifest(root):
    files = list(root.rglob('*'))
    assert not any(p.is_symlink() for p in files)
    assert all(p.is_dir() or p.is_file() for p in files)
    assert {str(p.relative_to(root)): sha(p.read_bytes()) for p in files
            if p.is_file() and p != root / 'manifest.json'} == load(root / 'manifest.json')


def source_inputs(parent):
    sources = parent.source_inputs()
    before = sources[SOURCE]
    names = sorted(str(p.relative_to(HERE / 'overrides'))
                   for p in (HERE / 'overrides').rglob('*') if p.is_file())
    assert names == [SOURCE]
    sources[SOURCE] = read(HERE / 'overrides' / SOURCE)
    assert {n: sha(b) for n, b in sources.items()} == load(HERE / 'source-inputs.json')
    assert len(sources) == 46
    patch = ''.join(difflib.unified_diff(before.decode().splitlines(True),
                                       sources[SOURCE].decode().splitlines(True),
                                       fromfile='parent/' + SOURCE,
                                       tofile='recovered/' + SOURCE))
    assert patch.encode() == read(HERE / 'source.patch')
    return sources


def check_recipe(parent, plan, actual):
    lines = []
    for row in plan:
        selector = '*(' + json.dumps(row['section']) + ')' if row['owner'] == '<internal>' else parent.owner(row['owner']) + '(' + json.dumps(row['section']) + ')'
        assert selector == row['selector']
        lines.append('    ' + selector)
    before = read(PARENT / 'layout/ordered.ld').decode()
    marker = '  .rodata : { *(.rodata*) } :rodata'
    assert before.count(marker) == 1 and len(plan) == 623
    expected = before.replace(marker, '  .rodata : {\n' + '\n'.join(lines) + '\n    *(.rodata*)\n  } :rodata')
    assert actual == expected.encode()


def check_sharing(w, original, image):
    ow = {x['address']: x for x in w.windows(original)}
    cw = {x['address']: x for x in w.windows(image)}
    matches = [x for x in cw.values() if 'create_fee_sharing_config14create_sharing' in (x['name'] or '')]
    assert len(matches) == 1
    a, b = ow[SHARING], matches[0]
    assert a['bytes'] == b['bytes'] == 12384 and a['signature'] == b['signature']
    ar, br = dict(w.m.relocations(original)), dict(w.m.relocations(image))
    ad, bd = w.dynamic_symbols(original), w.dynamic_symbols(image)
    direct = external = rows = 0
    for x, y in zip(w.m.instructions(original, a['address'], a['bytes']),
                    w.m.instructions(image, b['address'], b['bytes'])):
        rows += 1
        if 'call_target' not in x:
            continue
        left, right = ar.get(a['address'] + x['offset'], 0), br.get(b['address'] + y['offset'], 0)
        if left & 0xffffffff == 10:
            assert right & 0xffffffff == 10
            assert ad[left >> 32]['name'] == bd[right >> 32]['name']
            external += 1
        else:
            assert ow[x['call_target']]['signature'] == cw[y['call_target']]['signature']
            direct += 1
    assert rows == 1510 and direct == 64 and external == 1
    return {'instructions': rows, 'direct_targets': direct, 'external_targets': external}


def check_other_functions(w, parent, before, after, before_map, after_map):
    aw = {x['address']: x for x in w.windows(before)}
    bw = {x['address']: x for x in w.windows(after)}
    key = lambda x: (parent.owner(x['owner']), x['section'])
    am = {key(x): x for x in parent.input_sections(before_map, '.text')}
    bm = {key(x): x for x in parent.input_sections(after_map, '.text')}
    assert len(am) == len(bm) == len(aw) == len(bw) == 586 and am.keys() == bm.keys()
    mapping = {am[k]['address']: bm[k]['address'] for k in am}
    changed, calls = [], 0
    rel = dict(w.m.relocations(before))
    for address, target in mapping.items():
        a, b = aw[address], bw[target]
        if a['signature'] != b['signature']:
            changed.append(b['name'])
            continue
        for x, y in zip(w.m.instructions(before, address, a['bytes']),
                        w.m.instructions(after, target, b['bytes'])):
            if 'call_target' in x and rel.get(address + x['offset'], 0) & 0xffffffff != 10:
                assert mapping[x['call_target']] == y['call_target']
                calls += 1
    assert len(changed) == 1 and 'create_fee_sharing_config14create_sharing' in changed[0]
    assert calls == 4523
    return calls


def verify():
    check_manifest(HERE)
    assert load(HERE / 'parent.json') == {'path': str(PARENT.relative_to(ROOT)), 'manifest_sha256': sha((PARENT / 'manifest.json').read_bytes())}
    for name, digest in load(HERE / 'external-inputs.json').items():
        assert sha((ROOT / name).read_bytes()) == digest
    parent = module('sharing_parent', PARENT / 'verify.py')
    with contextlib.redirect_stdout(io.StringIO()):
        parent.verify()
    prior = module('sharing_prior', ROOT / 'research/fees-qualified-linker-layout/verify.py')
    locations = module('sharing_locations', ROOT / 'research/fees-sharing-slice-recovery/verify.py')
    w = module('sharing_windows', ROOT / 'research/fees-composed-frontier188/window_map.py')
    w.m.elf_layout = lru_cache(maxsize=8)(w.m.elf_layout)
    w.m.relocations = lru_cache(maxsize=8)(w.m.relocations)
    sources = source_inputs(parent)
    check_recipe(parent, load(HERE / 'layout/readonly-order.json'), read(HERE / 'layout/ordered.ld'))
    original = (ROOT / 'evidence/original/pump_fees/deployed.so').read_bytes()
    before = parent.read(PARENT / 'artifacts/candidate-symbols.so')
    candidate = read(HERE / 'builds/candidate/symbols.so')
    stripped = read(HERE / 'builds/candidate/candidate.so')
    assert candidate == read(HERE / 'builds/repeat/symbols.so')
    assert stripped == read(HERE / 'builds/repeat/candidate.so')
    assert stripped != original and stripped != original[:w.m.elf_layout(original)['elf_extent']]
    for role, label in [('candidate', 'sharing578-composed-order'), ('repeat', 'sharing578-composed-order-repeat')]:
        folder = HERE / 'builds' / role
        launch, result = load(folder / 'launch.json'), load(folder / 'result.json')
        assert result['exit_code'] == 0 and result['source_unchanged'] is True
        assert result['symbols_sha256'] == sha(candidate) and result['candidate_sha256'] == sha(stripped)
        assert result['log_sha256'] == sha(read(folder / 'build.log'))
        assert launch['inputs'] == {**{n: sha(b) for n, b in sources.items()}, 'ordered.ld': sha(read(HERE / 'layout/ordered.ld')), 'linker.sh': sha(read(folder / 'linker.sh'))}
        command = launch['command']
        assert command[0:2] == ['podman', 'exec'] and '--locked' in command and '--offline' in command
        assert command[command.index('--target') + 1] == 'sbpf-solana-solana'
        assert command[command.index('--manifest-path') + 1] == '/work/next622/' + label + '/programs/pump-fees/Cargo.toml'
        assert '-C' in command and 'linker=/work/next622/' + label + '/linker.sh' in command
        assert struct.unpack_from('<H', stripped, 56)[0] == struct.unpack_from('<H', candidate, 56)[0] == 4
    before_map = parent.read(PARENT / 'builds/candidate.map').decode()
    after_map = read(HERE / 'builds/candidate/link.map').decode()
    calls = check_other_functions(w, parent, before, candidate, before_map, after_map)
    sharing = check_sharing(w, original, candidate)
    refs = parent.check_data(w, original, candidate, after_map)
    ow, aw, bw = w.windows(original), w.windows(before), w.windows(candidate)
    covered = lambda rows: {x['address'] for x in ow if x['signature'] in {y['signature'] for y in rows}}
    raw = lambda rows: {x['address'] for x in ow if x['raw_sha256'] in {y['raw_sha256'] for y in rows}}
    assert covered(bw) == covered(aw) | {SHARING} and len(covered(bw)) == 578
    assert raw(bw) == raw(aw) and len(raw(bw)) == 198
    pairs = w.compare(ow, bw)['unique_pairs']
    assert len(pairs) == 431
    oi, ci = ({x['address']: x for x in rows} for rows in [ow, bw])
    rel = dict(w.m.relocations(original))
    edges, observations = [], 0
    for pair in pairs:
        a, b = pair['original'], pair['candidate']
        for x, y in zip(w.m.instructions(original, a['address'], a['bytes']),
                        w.m.instructions(candidate, b['address'], b['bytes'])):
            kind = rel.get(a['address'] + x['offset'], 0) & 0xffffffff
            if kind == 8:
                try:
                    source = locations.location(w, original, x['lddw_value'])
                except (AssertionError, ValueError, StopIteration, struct.error, UnicodeDecodeError):
                    pass
                else:
                    assert source == locations.location(w, candidate, y['lddw_value'])
                    observations += 1
            if 'call_target' in x and kind != 10:
                edges.append(oi[x['call_target']]['signature'] == ci[y['call_target']]['signature'])
    assert observations == 182 and len(edges) == 3941 and sum(edges) == 3935
    counters = []
    for image in [original, candidate]:
        found = Counter()
        for address, kind in w.m.relocations(image):
            if kind & 0xffffffff != 8:
                continue
            try:
                found[locations.location(w, image, address)] += 1
            except (AssertionError, ValueError, StopIteration, struct.error, UnicodeDecodeError):
                pass
        counters.append(found)
    assert counters[0] == counters[1] and sum(counters[0].values()) == 105
    run = load(HERE / 'runtime.json')
    prior.check_runtime(run, parent.load(PARENT / 'runtime.json'), sha(original), sha(stripped))
    execution = load(HERE / 'runtime-execution.json')
    assert execution['candidate_sha256'] == sha(stripped) and execution['jobs'] == 6
    ro, rc = w.m.section_data(original, '.rodata'), w.m.section_data(candidate, '.rodata')
    assert len(ro) == len(rc) == 21079 and sum(x != y for x, y in zip(ro, rc)) == 73
    return {'normalized_functions': 578, 'raw_local_functions': 198, 'unique_pairs': 431,
            'matched_source_observations': observations, 'equal_direct_call_observations': sum(edges),
            'sharing': sharing, 'other_functions_preserved': 585, 'preserved_direct_calls_checked': calls,
            'global_source_records': 105, 'data_pointer_targets_checked': len(refs),
            'readonly_bytes': 21079, 'readonly_differing_bytes': 73,
            'runtime_cases': 17331, 'runtime_suites': 18,
            'candidate_sha256': sha(stripped), 'symbols_sha256': sha(candidate),
            'whole_elf_equal': False, 'whole_capture_equal': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialize', type=Path)
    args = parser.parse_args()
    result = verify()
    if args.materialize:
        assert not args.materialize.exists()
        parent = module('sharing_materialize_parent', PARENT / 'verify.py')
        for name, data in source_inputs(parent).items():
            path = args.materialize / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (args.materialize / 'ordered.ld').write_bytes(read(HERE / 'layout/ordered.ld'))
        (args.materialize / 'linker.sh').write_bytes(read(HERE / 'builds/candidate/linker.sh'))
        (args.materialize / 'linker.sh').chmod(0o755)
    print(json.dumps(result, indent=2))
