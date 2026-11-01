"""Verify the shared quote helper and relative data layout; execute no compiler or VM."""
from pathlib import Path
from functools import lru_cache
from collections import Counter
import bisect
import difflib
import gzip
import hashlib
import importlib.util
import json
import re
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT = ROOT / 'research/fees-qualified-linker-layout'
SOURCE_PARENT = ROOT / 'research/fees-sharing-slice-recovery'
SOURCE_FILE = 'programs/pump-fees/src/instructions/fee_sharing/create_donation_fee_pda.rs'


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


def expected_source(before):
    old = b'let quote = donation_raw_curve_quote(curve.to_account_info())?;'
    assert before.count(old) == 1
    after = before.replace(old, b'let quote = crate::common::curve_quote_mint(&curve.to_account_info())?;')
    marker = b'fn donation_raw_curve_quote(info: AccountInfo'
    assert after.count(marker) == 1
    start = after.index(marker)
    after = after[:start] + b'\n' * after[start:].count(b'\n')
    assert len(after.splitlines()) == len(before.splitlines())
    return after


def check_source(before, after):
    assert after == expected_source(before)


def source_inputs():
    sources = {str(p.relative_to(SOURCE_PARENT / 'sources')).removesuffix('.gz'): gzip.decompress(p.read_bytes())
               for p in (SOURCE_PARENT / 'sources').rglob('*.gz')}
    assert len(sources) == 46
    assert {n: sha(b) for n, b in sources.items()} == load(SOURCE_PARENT / 'composition.json')['final_inputs']
    names = [str(p.relative_to(HERE / 'overrides')) for p in (HERE / 'overrides').rglob('*') if p.is_file()]
    assert names == [SOURCE_FILE]
    before = sources[SOURCE_FILE]
    after = read(HERE / 'overrides' / SOURCE_FILE)
    check_source(before, after)
    patch = ''.join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                        fromfile='accepted577/create_donation_fee_pda.rs',
                                        tofile='common-quote/create_donation_fee_pda.rs'))
    assert patch.encode() == read(HERE / 'source.patch')
    sources[SOURCE_FILE] = after
    return sources


def input_sections(text, prefix):
    rows = []
    pattern = r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\d+)\s+(\S+):\((\.[^)]*)\)\s*'
    for line in text.splitlines():
        m = re.fullmatch(pattern, line)
        if m and m[6].startswith(prefix):
            rows.append(dict(address=int(m[1], 16), size=int(m[3], 16), align=int(m[4]), owner=m[5], section=m[6]))
    return rows


def owner(path):
    name = path.rsplit('/', 1)[-1]
    return '*' + (name[:-1].replace('(', ':') if '(' in name else name)


def data_script(parent, rows):
    needle = '  .data.rel.ro : { *(.data.rel.ro*) } :rodata'
    assert parent.count(needle) == 1
    new = '  .data.rel.ro : {\n' + '\n'.join('    ' + owner(row['owner']) + '(' + json.dumps(row['section']) + ')' for row in rows)
    return parent.replace(needle, new + '\n    *(.data.rel.ro*)\n  } :rodata')


def check_data(w, original, candidate, link_map):
    os = {s['name']: s for s in w.m.elf_layout(original)['sections']}
    cs = {s['name']: s for s in w.m.elf_layout(candidate)['sections']}
    original_data = bytearray(w.m.section_data(original, '.data.rel.ro'))
    candidate_data = bytearray(w.m.section_data(candidate, '.data.rel.ro'))
    assert len(original_data) == len(candidate_data) == 6744
    original_relocations = {p - os['.data.rel.ro']['address']: kind for p, kind in w.m.relocations(original)
                            if os['.data.rel.ro']['address'] <= p < os['.data.rel.ro']['address'] + 6744}
    candidate_relocations = {p - cs['.data.rel.ro']['address']: kind for p, kind in w.m.relocations(candidate)
                             if cs['.data.rel.ro']['address'] <= p < cs['.data.rel.ro']['address'] + 6744}
    assert original_relocations.keys() == candidate_relocations.keys()
    assert len(original_relocations) == 379
    for offset in original_relocations:
        assert original_relocations[offset] & 0xffffffff == candidate_relocations[offset] & 0xffffffff == 8
        original_data[offset:offset + 8] = candidate_data[offset:offset + 8] = bytes(8)
    assert original_data == candidate_data
    ow = {row['address']: row for row in w.windows(original)}
    cw = {row['address']: row for row in w.windows(candidate)}
    objects = []
    for row in input_sections(link_map, '.rodata'):
        match = re.search(r'cst(\d+)$', row['section']) if row['owner'] == '<internal>' else None
        step = int(match[1]) if match else row['size']
        for start in range(row['address'], row['address'] + row['size'], step):
            objects.append((start, min(step, row['address'] + row['size'] - start)))
    objects.sort()
    starts = [a for a, size in objects]
    groups, references = Counter(), []
    for offset in sorted(candidate_relocations):
        original_field = os['.data.rel.ro']['address'] + offset
        candidate_field = cs['.data.rel.ro']['address'] + offset
        low_o, op = struct.unpack('<II', w.m.at_address(original, original_field, 8))
        low_c, cp = struct.unpack('<II', w.m.at_address(candidate, candidate_field, 8))
        assert low_o == low_c == 0
        if cp in cw:
            assert op in ow and ow[op]['signature'] == cw[cp]['signature']
            kind = 'complete-normalized-function'
        elif cs['.data.rel.ro']['address'] <= cp < cs['.data.rel.ro']['address'] + 6744:
            assert op - os['.data.rel.ro']['address'] == cp - cs['.data.rel.ro']['address']
            kind = 'internal-data-reference'
        elif cs['.rodata']['address'] <= cp < cs['.rodata']['address'] + cs['.rodata']['size']:
            index = bisect.bisect_right(starts, cp) - 1
            assert index >= 0
            start, size = objects[index]
            assert start <= cp < start + size
            original_start = op - (cp - start)
            assert os['.rodata']['address'] <= original_start
            assert original_start + size <= os['.rodata']['address'] + os['.rodata']['size']
            assert w.m.at_address(original, original_start, size) == w.m.at_address(candidate, start, size)
            kind = 'complete-compiled-rodata-allocation'
        else:
            raise AssertionError(('unclassified data target', offset, op, cp))
        groups[kind] += 1
        references.append(dict(offset=offset, original_target=op, candidate_target=cp, evidence=kind))
    assert groups == {'complete-compiled-rodata-allocation': 268, 'complete-normalized-function': 108,
                      'internal-data-reference': 3}
    assert w.m.section_data(original, '.data.rel.ro') != w.m.section_data(candidate, '.data.rel.ro')
    return references


def verify():
    files = list(HERE.rglob('*'))
    assert not any(p.is_symlink() for p in files)
    assert {str(p.relative_to(HERE)): sha(p.read_bytes()) for p in files if p.is_file() and p != HERE / 'manifest.json'} == load(HERE / 'manifest.json')
    assert load(HERE / 'parent.json') == dict(path='research/fees-qualified-linker-layout', manifest_sha256=sha((PARENT / 'manifest.json').read_bytes()))
    for name, digest in load(PARENT / 'manifest.json').items():
        assert sha((PARENT / name).read_bytes()) == digest
    for name, digest in load(HERE / 'external-inputs.json').items():
        assert sha((ROOT / name).read_bytes()) == digest
    sources = source_inputs()
    inputs = {n: sha(b) for n, b in sources.items()}
    parent = module('data_order_parent', PARENT / 'verify.py')
    old = module('data_order_locations', SOURCE_PARENT / 'verify.py')
    w = module('data_order_windows', ROOT / 'research/fees-composed-frontier188/window_map.py')
    w.m.elf_layout = lru_cache(maxsize=8)(w.m.elf_layout)
    w.m.relocations = lru_cache(maxsize=8)(w.m.relocations)
    original = (ROOT / 'evidence/original/pump_fees/deployed.so').read_bytes()
    control = read(HERE / 'artifacts/control-symbols.so')
    candidate = read(HERE / 'artifacts/candidate-symbols.so')
    stripped = read(HERE / 'artifacts/candidate-candidate.so')
    assert candidate == read(HERE / 'artifacts/repeat-symbols.so')
    assert stripped == read(HERE / 'artifacts/repeat-candidate.so')
    assert stripped != original and stripped != original[:w.m.elf_layout(original)['elf_extent']]
    assert w.m.elf_layout(stripped)['elf_extent'] == len(stripped)
    assert struct.unpack_from('<H', stripped, 56)[0] == 4
    allocated = lambda image: {s['name']: s for s in w.m.elf_layout(image)['sections'] if s['flags'] & 2}
    symbol_sections, stripped_sections = allocated(candidate), allocated(stripped)
    assert symbol_sections.keys() == stripped_sections.keys()
    for name, section in symbol_sections.items():
        assert all(section[key] == stripped_sections[name][key] for key in ['address', 'size', 'type', 'flags'])
        if section['type'] != 8:
            assert w.m.section_data(candidate, name) == w.m.section_data(stripped, name)
    data_order = load(HERE / 'layout/data-order.json')
    assert len(data_order) == 265
    next_address = next(s['address'] for s in w.m.elf_layout(original)['sections'] if s['name'] == '.data.rel.ro')
    for row in data_order:
        assert row['original'] == next_address
        next_address += row['size']
    assert data_script(read(PARENT / 'layout/ordered.ld').decode(), data_order).encode() == read(HERE / 'layout/ordered.ld')
    for label, directory in [('control', 'next612'), ('candidate', 'next614'), ('repeat', 'next614')]:
        launch, result = load(HERE / f'builds/{label}-launch.json'), load(HERE / f'builds/{label}-result.json')
        layout = read(PARENT / 'layout/ordered.ld') if label == 'control' else read(HERE / 'layout/ordered.ld')
        expected_wrapper = read(PARENT / 'layout/linker.sh').decode().replace('next605', directory).replace('qualified-replaced', 'common-quote-layout' if label == 'control' else 'common-quote-data-layout').encode()
        assert expected_wrapper == read(HERE / f'builds/{label}-wrapper.sh')
        assert launch['inputs'] == dict(inputs, **{'ordered.ld': sha(layout), 'linker.sh': sha(expected_wrapper)})
        assert result['exit_code'] == 0 and result['source_unchanged'] is True
        symbol_bytes, binary_bytes = read(HERE / f'artifacts/{label}-symbols.so'), read(HERE / f'artifacts/{label}-candidate.so')
        assert result['symbols_sha256'] == sha(symbol_bytes) and result['candidate_sha256'] == sha(binary_bytes)
        log = read(HERE / f'builds/{label}-build.log')
        assert result['log_sha256'] == sha(log) and log.count(b'--crate-name pump_fees_candidate ') == 1
        parent_label = 'repeat' if label == 'repeat' else 'candidate'
        controller = read(PARENT / f'builds/{parent_label}-controller.py').decode()
        controller = controller.replace('next605', directory).replace('qualified-replaced', 'common-quote-layout' if label == 'control' else 'common-quote-data-layout')
        assert controller.encode() == read(HERE / f'builds/{label}-controller.py')
        parent_command = load(PARENT / f'builds/{parent_label}-launch.json')['command']
        name = 'common-quote-layout' if label == 'control' else 'common-quote-data-layout'
        old_source = 'qualified-repeat' if label == 'repeat' else 'qualified-replaced'
        new_source = name + ('-repeat' if label == 'repeat' else '')
        expected_command = [arg.replace('next605', directory).replace(old_source, new_source).replace('qualified-replaced', name) for arg in parent_command]
        assert launch['command'] == expected_command
    cw = w.windows(candidate)
    parent_windows = w.windows(read(PARENT / 'artifacts/candidate-symbols.so'))
    for label, image in [('control', control), ('candidate', candidate), ('repeat', candidate)]:
        if label != 'control':
            emitted = input_sections(read(HERE / f'builds/{label}.map').decode(), '.data.rel.ro')
            assert len(emitted) == len(data_order)
            section = next(s for s in w.m.elf_layout(image)['sections'] if s['name'] == '.data.rel.ro')
            base = data_order[0]['original']
            for expected, actual in zip(data_order, emitted):
                assert expected['section'] == actual['section'] and owner(expected['owner']) == owner(actual['owner'])
                assert actual['size'] == expected['size']
                assert actual['address'] - section['address'] == expected['original'] - base
        functions = w.windows(image)
        assert [(x['address'], x['signature']) for x in functions] == [(x['address'], x['signature']) for x in cw]
        assert parent.check_direct_targets(w, control, image, {x['address']: x['address'] for x in cw}) > 3877
    refs = check_data(w, original, candidate, read(HERE / 'builds/candidate.map').decode())
    assert refs == load(HERE / 'data/targets.json')['references']
    ow = w.windows(original)
    oi = {x['address']: x for x in ow}
    ci = {x['address']: x for x in cw}
    comparison = w.compare(ow, cw)
    assert len(comparison['unique_pairs']) == 430
    covered = {x['address'] for x in ow if x['signature'] in {c['signature'] for c in cw}}
    raw = {x['address'] for x in ow if x['raw_sha256'] in {c['raw_sha256'] for c in cw}}
    parent_signatures = {x['signature'] for x in parent_windows}
    parent_raw = {x['raw_sha256'] for x in parent_windows}
    assert covered == {x['address'] for x in ow if x['signature'] in parent_signatures}
    assert raw == {x['address'] for x in ow if x['raw_sha256'] in parent_raw}
    assert len(covered) == 577 and len(raw) == 198
    rel = dict(w.m.relocations(original))
    edges, locations = {}, 0
    for pair in comparison['unique_pairs']:
        a, b = pair['original'], pair['candidate']
        for x, y in zip(w.m.instructions(original, a['address'], a['bytes']), w.m.instructions(candidate, b['address'], b['bytes'])):
            kind = rel.get(a['address'] + x['offset'], 0) & 0xffffffff
            if kind == 8:
                try:
                    loc = old.location(w, original, x['lddw_value'])
                except (AssertionError, ValueError, StopIteration, struct.error):
                    continue
                assert loc == old.location(w, candidate, y['lddw_value'])
                locations += 1
            if 'call_target' in x and kind != 10:
                edges[a['address'], x['offset']] = oi[x['call_target']]['signature'] == ci[y['call_target']]['signature']
    assert locations == 181 and len(edges) == 3877 and sum(edges.values()) == 3870
    parent_image = read(PARENT / 'artifacts/candidate-symbols.so')
    parent_by_address = {x['address']: x for x in parent_windows}
    parent_edges = {}
    for pair in w.compare(ow, parent_windows)['unique_pairs']:
        a, b = pair['original'], pair['candidate']
        for x, y in zip(w.m.instructions(original, a['address'], a['bytes']), w.m.instructions(parent_image, b['address'], b['bytes'])):
            if 'call_target' in x and rel.get(a['address'] + x['offset'], 0) & 0xffffffff != 10:
                parent_edges[a['address'], x['offset']] = oi[x['call_target']]['signature'] == parent_by_address[y['call_target']]['signature']
    assert parent_edges == edges
    source_locations = []
    for image in [original, candidate]:
        values = []
        for address, kind in w.m.relocations(image):
            if kind & 0xffffffff != 8:
                continue
            try:
                values.append(old.location(w, image, address))
            except (AssertionError, ValueError, StopIteration, struct.error, UnicodeDecodeError):
                continue
        source_locations.append(Counter(values))
    assert source_locations[0] == source_locations[1] and sum(source_locations[0].values()) == 105
    run = load(HERE / 'runtime.json')
    parent.check_runtime(run, load(PARENT / 'runtime.json'), sha(original), sha(stripped))
    execution = load(HERE / 'runtime-execution.json')
    assert execution['jobs'] == 6 and execution['candidate_sha256'] == sha(stripped)
    assert execution['canonical_runner_sha256'] == sha((ROOT / 'scripts/fees_validate_all.py').read_bytes())
    assert execution['suites'].keys() == run['suites'].keys()
    for record in execution['suites'].values():
        assert record['exit_code'] == 0
        assert record['script_sha256'] == sha((ROOT / 'scripts' / Path(record['command'][2]).name).read_bytes())
    result = dict(normalized_functions=577, raw_local_matches=198, unique_pairs=430, cohort_locations=181,
                  equal_direct_calls=3870, global_source_records=105, ordered_data_objects=265,
                  data_pointer_targets_checked=379, exact_relative_nonpointer_data_bytes=3712,
                  runtime_cases=17331, runtime_suites=18, whole_meaningful_elf_equal=False,
                  whole_capture_equal=False, candidate_sha256=sha(stripped), symbols_sha256=sha(candidate))
    assert result == load(HERE / 'claims.json')
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialize', type=Path)
    args = parser.parse_args()
    verify()
    if args.materialize:
        args.materialize.mkdir(parents=True, exist_ok=False)
        for name, data in source_inputs().items():
            path = args.materialize / 'source' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        config = args.materialize / 'config'
        config.mkdir()
        (config / 'ordered.ld').write_bytes(read(HERE / 'layout/ordered.ld'))
        (config / 'linker.sh').write_bytes(read(HERE / 'builds/candidate-wrapper.sh'))
        (config / 'linker.sh').chmod(0o755)
