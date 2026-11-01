"""Verify saved Rust builds and the qualified linker layout; executes no compiler or VM."""
from pathlib import Path
from collections import Counter
from functools import lru_cache
import gzip
import hashlib
import importlib.util
import json
import re
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT = ROOT / 'research/fees-sharing-slice-recovery'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def read(path):
    return path.read_bytes() if path.exists() else gzip.decompress(path.with_name(path.name + '.gz').read_bytes())


def load(path):
    return json.loads(read(path))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def map_sections(text):
    result = []
    pattern = r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\d+)\s+(\S+):\((\.text[^)]*)\)\s*'
    for line in text.splitlines():
        match = re.fullmatch(pattern, line)
        if match:
            result.append(dict(address=int(match[1], 16), size=int(match[3], 16),
                               file=match[5], section=match[6]))
    return result


def owner_pattern(path):
    name = path.rsplit('/', 1)[-1]
    return '*' + (name[:-1].replace('(', ':') if '(' in name else name)


def layout_rows(sections, plan):
    by_address = {row['address']: row for row in sections}
    assert len(by_address) == len(sections) == 586
    rows = []
    for binding in plan['ordered']:
        section = by_address[binding['candidate']]
        rows.append({**binding, **section, 'selector': owner_pattern(section['file'])})
    assert len(rows) == len({row['address'] for row in rows}) == 585
    used = {row['address'] for row in rows}
    for section in sections:
        if section['address'] not in used:
            rows.append({**section, 'selector': owner_pattern(section['file']), 'basis': 'unmatched-extra'})
    return rows


def ordered_script(default, rows):
    old = '  .text : { *(.text*) } :text'
    assert default.count(old) == 1
    new = '  .text : {\n' + '\n'.join('    ' + row['selector'] + '(' + json.dumps(row['section']) + ')' for row in rows)
    return default.replace(old, new + '\n    *(.text*)\n  } :text')


def check_direct_targets(w, before, after, mapping):
    before_windows = {row['address']: row for row in w.windows(before)}
    after_windows = {row['address']: row for row in w.windows(after)}
    assert set(mapping) == set(before_windows) and set(mapping.values()) == set(after_windows)
    relocations = dict(w.m.relocations(before))
    checked = 0
    for address, target in mapping.items():
        left, right = before_windows[address], after_windows[target]
        assert left['signature'] == right['signature']
        for x, y in zip(w.m.instructions(before, address, left['bytes']),
                        w.m.instructions(after, target, right['bytes'])):
            if 'call_target' in x and relocations.get(address + x['offset'], 0) & 0xffffffff != 10:
                assert mapping[x['call_target']] == y['call_target']
                checked += 1
    return checked


def check_runtime(run, previous, original_sha, candidate_sha):
    assert run['candidate_sha256'] == candidate_sha and run['original_sha256'] == original_sha
    assert run['case_count'] == 17331 and not run['mismatches']
    assert run['suites'].keys() == previous['suites'].keys() and len(run['suites']) == 18
    assert sum(suite['case_count'] for suite in run['suites'].values()) == 17331
    logs = 0
    for name, suite in run['suites'].items():
        assert suite['candidate_sha256'] == candidate_sha and suite['original_sha256'] == original_sha
        assert len(suite['cases']) == suite['case_count']
        assert not suite.get('mismatches', suite.get('failures', []))
        identity = lambda case: json.dumps(case.get('case', case.get('name')), sort_keys=True)
        # The parent configuration suite intentionally repeats one input.
        assert [identity(c) for c in suite['cases']] == [identity(c) for c in previous['suites'][name]['cases']]
        for case in suite['cases']:
            assert name == 'queries' or case.get('match') is True
            left, right = case.get('original'), case.get('candidate')
            assert isinstance(left, dict) and isinstance(right, dict) and left.keys() == right.keys()
            assert all(left[key] == right[key] for key in left if key != 'logs')
            if 'logs' in left:
                application = lambda value: [line for line in value['logs'] if line.startswith(('Program log:', 'Program data:'))]
                assert application(left) == application(right)
                logs += 1
    assert logs == 6413


def check_build(label, sources, symbols, stripped):
    launch = load(HERE / f'builds/{label}-launch.json')
    result = load(HERE / f'builds/{label}-result.json')
    expected = dict(sources)
    if label != 'baseline':
        expected.update({'ordered.ld': sha(read(HERE / 'layout/ordered.ld')),
                         'linker.sh': sha(read(HERE / 'layout/linker.sh'))})
    assert launch['inputs'] == expected
    assert result['exit_code'] == 0 and result['source_unchanged'] is True
    assert result['symbols_sha256'] == sha(symbols) and result['candidate_sha256'] == sha(stripped)
    log = read(HERE / f'builds/{label}-build.log')
    assert sha(log) == result['log_sha256']
    assert log.count(b'--crate-name pump_fees_candidate ') == 1
    command = launch['command']
    assert '--offline' in command and '--locked' in command and 'sbpf-solana-solana' in command
    assert sum(arg.startswith('--remap-path-prefix=') for arg in command) == 3
    if label != 'baseline':
        assert command.count('linker=/work/next605/qualified-replaced/linker.sh') == 1


def verify():
    files = list(HERE.rglob('*'))
    assert not any(path.is_symlink() for path in files)
    actual = {str(path.relative_to(HERE)): sha(path.read_bytes()) for path in files
              if path.is_file() and path != HERE / 'manifest.json'}
    assert actual == load(HERE / 'manifest.json')
    parent = load(HERE / 'parent.json')
    assert parent == dict(path='research/fees-sharing-slice-recovery', manifest_sha256=sha((PARENT / 'manifest.json').read_bytes()))
    for name, digest in load(PARENT / 'manifest.json').items():
        assert sha((PARENT / name).read_bytes()) == digest
    for name, digest in load(HERE / 'external-inputs.json').items():
        assert sha((ROOT / name).read_bytes()) == digest
    sources = {str(path.relative_to(PARENT / 'sources')).removesuffix('.gz'): sha(gzip.decompress(path.read_bytes()))
               for path in (PARENT / 'sources').rglob('*') if path.is_file()}
    assert len(sources) == 46
    assert sources == load(PARENT / 'composition.json')['final_inputs']

    w = module('qualified_windows', ROOT / 'research/fees-composed-frontier188/window_map.py')
    w.m.elf_layout = lru_cache(maxsize=8)(w.m.elf_layout)
    w.m.relocations = lru_cache(maxsize=8)(w.m.relocations)
    old = module('qualified_parent', PARENT / 'verify.py')
    original = (ROOT / 'evidence/original/pump_fees/deployed.so').read_bytes()
    baseline = read(HERE / 'artifacts/baseline-symbols.so')
    candidate = read(HERE / 'artifacts/candidate-symbols.so')
    stripped = read(HERE / 'artifacts/candidate-candidate.so')
    assert baseline == read(PARENT / 'artifacts/candidate-symbols.so')
    assert read(HERE / 'artifacts/baseline-candidate.so') == read(PARENT / 'artifacts/candidate-candidate.so')
    assert candidate == read(HERE / 'artifacts/repeat-symbols.so')
    assert stripped == read(HERE / 'artifacts/repeat-candidate.so')
    assert struct.unpack_from('<H', stripped, 56)[0] == 4
    assert struct.unpack_from('<H', candidate, 56)[0] == 4
    assert stripped != original and stripped != original[:w.m.elf_layout(original)['elf_extent']]
    for label, symbols, binary in [('baseline', baseline, read(HERE / 'artifacts/baseline-candidate.so')),
                                   ('candidate', candidate, stripped), ('repeat', candidate, stripped)]:
        check_build(label, sources, symbols, binary)
    allocated = lambda image: {s['name']: s for s in w.m.elf_layout(image)['sections'] if s['flags'] & 2}
    a, b = allocated(candidate), allocated(stripped)
    assert a.keys() == b.keys()
    assert a['.text']['address'] == b['.text']['address'] == 288
    for name in a:
        assert all(a[name][key] == b[name][key] for key in ['address', 'size', 'type', 'flags'])
        if a[name]['type'] != 8:
            assert w.m.section_data(candidate, name) == w.m.section_data(stripped, name)

    ow, bw, cw = w.windows(original), w.windows(baseline), w.windows(candidate)
    oi, bi, ci = ({row['address']: row for row in values} for values in [ow, bw, cw])
    sections = map_sections(read(HERE / 'builds/baseline.map').decode())
    assert sections == load(HERE / 'layout/baseline-sections.json')
    assert {row['address'] for row in sections} == set(bi)
    assert all(row['size'] == bi[row['address']]['bytes'] for row in sections)
    plan = load(HERE / 'layout/order-plan.json')
    assert [row['original'] for row in plan['ordered']] == sorted(oi)
    assert Counter(row['basis'] for row in plan['ordered']) == {
        'exact-window/call-graph': 499, 'ambiguous-equal-window; original identity unproven': 78,
        'semantic-handler-boundary; body still unequal': 8}
    for row in plan['ordered']:
        assert row['name'] == bi[row['candidate']]['name']
        equal = oi[row['original']]['signature'] == bi[row['candidate']]['signature']
        assert equal == (row['basis'] != 'semantic-handler-boundary; body still unequal')
    rows = layout_rows(sections, plan)
    assert rows == load(HERE / 'layout/ordered-sections.json')
    assert read(HERE / 'layout/default.ld') == (ROOT / 'repro/donation-relay/linked-elf-reproduction/layout/default.ld').read_bytes()
    assert ordered_script(read(HERE / 'layout/default.ld').decode(), rows).encode() == read(HERE / 'layout/ordered.ld')
    for label in ['candidate', 'repeat']:
        actual_sections = map_sections(read(HERE / f'builds/{label}.map').decode())
        assert len(actual_sections) == len(rows)
        next_address = 288
        mapping = {}
        for row, emitted in zip(rows, actual_sections):
            assert owner_pattern(emitted['file']) == row['selector'] and emitted['section'] == row['section']
            assert emitted['address'] == next_address and emitted['size'] == row['size']
            next_address += row['size']
            assert bi[row['address']]['signature'] == ci[emitted['address']]['signature']
            mapping[row['address']] = emitted['address']
        assert check_direct_targets(w, baseline, candidate, mapping) > 3877

    reports = {}
    rel = dict(w.m.relocations(original))
    for label, image, windows in [('baseline', baseline, bw), ('candidate', candidate, cw)]:
        matched = w.compare(ow, windows)
        assert len(matched['unique_pairs']) == 430
        signatures = {row['signature'] for row in windows}
        raw = {row['raw_sha256'] for row in windows}
        covered = {row['address'] for row in ow if row['signature'] in signatures}
        literal = {row['address'] for row in ow if row['raw_sha256'] in raw}
        assert len(covered) == 577
        targets = {row['address']: row for row in windows}
        edges, locations = {}, 0
        for pair in matched['unique_pairs']:
            left, right = pair['original'], pair['candidate']
            for x, y in zip(w.m.instructions(original, left['address'], left['bytes']), w.m.instructions(image, right['address'], right['bytes'])):
                kind = rel.get(left['address'] + x['offset'], 0) & 0xffffffff
                if kind == 8:
                    try:
                        location = old.location(w, original, x['lddw_value'])
                    except (AssertionError, ValueError, StopIteration, struct.error):
                        continue
                    assert location == old.location(w, image, y['lddw_value'])
                    locations += 1
                if 'call_target' in x and kind != 10:
                    edges[left['address'], x['offset']] = oi[x['call_target']]['signature'] == targets[y['call_target']]['signature']
        assert locations == 181 and len(edges) == 3877 and sum(edges.values()) == 3870
        reports[label] = covered, literal, edges
    before, after = reports['baseline'], reports['candidate']
    assert before[0] == after[0] and before[2] == after[2]
    assert len(before[1]) == 143 and len(after[1]) == 198 and before[1] <= after[1]
    claims = dict(normalized_functions=577, total_original_functions=585, raw_local_matches=198,
                  gained_raw_addresses=sorted(after[1] - before[1]), unique_pairs=430,
                  equal_locations=181, equal_direct_callee_observations=3870,
                  whole_meaningful_elf_equal=False, whole_capture_equal=False,
                  candidate_sha256=sha(stripped), symbols_sha256=sha(candidate),
                  runtime_cases=17331, runtime_suites=18)
    assert claims == load(HERE / 'claims.json')
    run = load(HERE / 'runtime.json')
    check_runtime(run, load(PARENT / 'runtime.json'), sha(original), sha(stripped))
    execution = load(HERE / 'runtime-execution.json')
    assert execution['candidate_sha256'] == sha(stripped) and execution['jobs'] == 4
    assert execution['canonical_runner_sha256'] == sha((ROOT / 'scripts/fees_validate_all.py').read_bytes())
    assert execution['suites'].keys() == run['suites'].keys()
    for record in execution['suites'].values():
        assert record['exit_code'] == 0
        assert sha((ROOT / 'scripts' / Path(record['command'][2]).name).read_bytes()) == record['script_sha256']
    print(json.dumps(claims, indent=2))
    return claims


if __name__ == '__main__':
    verify()
