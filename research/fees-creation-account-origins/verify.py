"""Verify source-origin recovery, complete windows and retained local executions."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    for name, expected in json.loads((HERE / 'manifest.json').read_text()).items():
        path = HERE / name
        assert path.resolve().is_relative_to(HERE) and sha(path.read_bytes()) == expected, name
    e = json.loads((HERE / 'experiment.json').read_text())
    assert len(e['harness_sha256']) == 187
    assert sha((HERE / 'exhaustive_flags.py').read_bytes()) == e['focused_driver']['sha256']
    for name, expected in e['harness_sha256'].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    for label, variant in e['variants'].items():
        assert len(variant['input_sha256']) == e['expected_input_counts'][label]
        for name, expected in variant['input_sha256'].items():
            override = variant['source_overrides'].get(name)
            path = HERE / override if override else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
        build = json.loads((HERE / 'builds' / f'{label}-result.json').read_text())
        assert build['exit_code'] == build['strip_exit_code'] == 0
        assert build['source_unchanged'] and build['input_sha256'] == variant['input_sha256']
        replay = e['strip_replay'][label]
        assert replay['exit_code'] == 0 and replay['sha256'] == variant['files']['candidate']['sha256']
    spec = importlib.util.spec_from_file_location('account_origin_analysis', HERE / 'analyze.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    for label, expected in e['expected_counts'].items():
        if label in ('control', 'origins'):
            assert len(actual['variants'][label]['unique_pairs']) == expected
    assert len(actual['variants']['origins']['unmatched_original']) == e['expected_counts']['unmatched']
    assert actual['variants']['origins']['candidate_windows'] == 580
    assert actual['delta'] == {'added_original_windows': sorted(row[0] for row in e['targets']), 'lost_original_windows': []}
    assert len(actual['origin_bindings']) == len(e['targets'])
    assert not actual['variants']['origins']['equals_original_capture']
    assert not actual['variants']['origins']['equals_original_elf_extent']
    assert set(e['behavioral_receipts']) == set(e['flag_receipts']) == {'control', 'origins'}
    for label, descriptor in e['behavioral_receipts'].items():
        report = json.loads(gzip.decompress((HERE / descriptor['path']).read_bytes()))
        assert report['candidate_sha256'] == e['variants'][label]['files']['candidate']['sha256']
        assert report['original_sha256'] == actual['original_sha256']
        assert report['case_count'] == descriptor['cases'] == 17331 and len(report['suites']) == 18
        assert not report['mismatches']
        for suite in report['suites'].values():
            assert suite['candidate_sha256'] == report['candidate_sha256']
            assert suite['original_sha256'] == report['original_sha256']
            assert not suite.get('mismatches', suite.get('failures'))
        descriptor = e['flag_receipts'][label]
        flags = json.loads(gzip.decompress((HERE / descriptor['path']).read_bytes()))
        assert flags['candidate_sha256'] == report['candidate_sha256']
        assert flags['original_sha256'] == report['original_sha256']
        assert flags['case_count'] == descriptor['cases'] == len(flags['cases']) == 1542
        assert not flags['failures'] and not flags['compute_differences']
        for row in flags['cases']:
            assert row['original'] == row['candidate']
        assert {(row['cap'], row['pool'], row['flag_hex']) for row in flags['cases']} == {
            (cap, pool, value.hex()) for cap in (0, 1000, 2**128 - 1)
            for pool in (0, 1) for value in [b''] + [bytes([v]) for v in range(256)]}
    print(f"PASS: {len(e['targets'])} complete parser windows, exact source path/line bindings, preserved declarations, 34,662 suite cases and 3,084 exact outcome/log/compute comparisons")


if __name__ == '__main__':
    main()
