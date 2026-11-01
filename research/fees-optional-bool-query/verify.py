"""Check the complete wrapper recovery and all retained execution evidence."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    for name, expected in json.loads((HERE / 'manifest.json').read_text()).items():
        path = HERE / name
        assert path.resolve().is_relative_to(HERE) and sha(path.read_bytes()) == expected, name
    e = json.loads((HERE / 'experiment.json').read_text())
    assert len(e['harness_sha256']) == 187
    for name, expected in e['harness_sha256'].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    for label, variant in e['variants'].items():
        assert len(variant['input_sha256']) == 26
        for name, expected in variant['input_sha256'].items():
            override = variant['source_overrides'].get(name)
            path = HERE / override if override else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
        build = json.loads((HERE / 'builds' / f'{label}-result.json').read_text())
        assert build['exit_code'] == build['strip_exit_code'] == 0
        assert build['source_unchanged'] and build['input_sha256'] == variant['input_sha256']
        replay = e['strip_replay'][label]
        assert replay['exit_code'] == 0 and replay['sha256'] == variant['files']['candidate']['sha256']
    a, b = e['variants']['control'], e['variants']['optional']
    assert {name for name in a['input_sha256'] if a['input_sha256'][name] != b['input_sha256'][name]} == {
        'programs/pump-fees/src/lib.rs', 'programs/pump-fees/src/types.rs'}
    spec = importlib.util.spec_from_file_location('optional_analysis', HERE / 'analyze.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    assert len(actual['variants']['control']['unique_pairs']) == 343
    assert len(actual['variants']['optional']['unique_pairs']) == 344
    assert len(actual['variants']['optional']['unmatched_original']) == 94
    assert actual['variants']['optional']['candidate_windows'] == 580
    assert actual['delta'] == {'added_original_windows': [636160], 'lost_original_windows': []}
    assert not actual['variants']['optional']['equals_original_capture']
    assert not actual['variants']['optional']['equals_original_elf_extent']
    assert set(e['behavioral_receipts']) == set(e['flag_receipts']) == {'control', 'optional'}
    for label in e['variants']:
        receipt = e['behavioral_receipts'][label]
        report = json.loads(gzip.decompress((HERE / receipt['path']).read_bytes()))
        assert report['candidate_sha256'] == e['variants'][label]['files']['candidate']['sha256']
        assert report['original_sha256'] == actual['original_sha256']
        assert report['case_count'] == receipt['cases'] == 17331 and len(report['suites']) == 18
        assert not report['mismatches']
        for suite in report['suites'].values():
            assert suite['original_sha256'] == report['original_sha256']
            assert suite['candidate_sha256'] == report['candidate_sha256']
            assert not suite.get('mismatches', suite.get('failures'))
        receipt = e['flag_receipts'][label]
        flags = json.loads(gzip.decompress((HERE / receipt['path']).read_bytes()))
        assert flags['candidate_sha256'] == report['candidate_sha256']
        assert flags['original_sha256'] == report['original_sha256']
        assert flags['case_count'] == receipt['cases'] == len(flags['cases']) == 1542
        expected = 1539 if label == 'control' else 0
        assert flags['expected_baseline_differences'] == expected
        outcome = [i for i, row in enumerate(flags['cases']) if row['original']['outcome'] != row['candidate']['outcome']]
        logs = [i for i, row in enumerate(flags['cases']) if row['original']['logs'] != row['candidate']['logs']]
        compute = [i for i, row in enumerate(flags['cases']) if row['original']['compute_units'] != row['candidate']['compute_units']]
        assert outcome == flags['outcome_failures'] == []
        assert logs == flags['log_failures'] == flags['failures'] and len(logs) == expected
        assert compute == flags['compute_differences'] and len(compute) == expected
        combinations = {(row['cap'], row['pool'], row['flag_hex']) for row in flags['cases']}
        assert combinations == {(cap, pool, flag.hex()) for cap in (0, 1000, 2**128 - 1)
                                for pool in (0, 1) for flag in [b''] + [bytes([v]) for v in range(256)]}
    print('PASS: complete 1,560-byte wrapper, encoded error/callee/format bindings, 34,662 retained suite cases and 3,084 focused flag executions')


if __name__ == '__main__':
    main()
