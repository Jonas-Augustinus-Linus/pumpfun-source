"""Verify source-controlled ownership changes and actual retained executions."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    manifest = json.loads((HERE / 'manifest.json').read_text())
    members = {str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file() and p.name != 'manifest.json' and '__pycache__' not in p.parts}
    assert members == set(manifest)
    for name, expected in manifest.items():
        path = HERE / name
        assert path.resolve().is_relative_to(HERE) and not path.is_symlink() and sha(path.read_bytes()) == expected
    e = json.loads((HERE / 'experiment.json').read_text())
    assert len(e['harness_sha256']) == 187
    for name, expected in e['harness_sha256'].items():
        assert sha((ROOT / name).read_bytes()) == expected
    for label, variant in e['variants'].items():
        assert len(variant['input_sha256']) == e['expected_input_counts'][label] == 34
        for name, expected in variant['input_sha256'].items():
            override = variant['source_overrides'].get(name)
            assert sha((HERE / override if override else ROOT / name).read_bytes()) == expected
        result = json.loads((HERE / f'builds/{label}-result.json').read_text())
        launch = json.loads((HERE / f'builds/{label}-launch.json').read_text())
        assert result['exit_code'] == result['strip_exit_code'] == 0 and result['source_unchanged']
        assert result['input_sha256'] == launch['input_sha256'] == variant['input_sha256']
        assert launch['rustc_sha256'] == e['tool_sha256']['rustc-v144']
        assert e['strip_replay'][label]['exit_code'] == 0
        assert e['strip_replay'][label]['sha256'] == variant['files']['candidate']['sha256']
        report = json.loads(gzip.decompress((HERE / f'receipts/{label}-full.json.gz').read_bytes()))
        assert report['candidate_sha256'] == variant['files']['candidate']['sha256']
        assert report['original_sha256'] == '4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
        assert report['case_count'] == 17331 and len(report['suites']) == 18 and not report['mismatches']
        for suite in report['suites'].values():
            assert suite['candidate_sha256'] == report['candidate_sha256'] and suite['original_sha256'] == report['original_sha256']
            assert not suite.get('mismatches', suite.get('failures'))
        flags = json.loads(gzip.decompress((HERE / f'receipts/{label}-exhaustive.json.gz').read_bytes()))
        assert flags['candidate_sha256'] == report['candidate_sha256'] and flags['original_sha256'] == report['original_sha256']
        assert flags['case_count'] == len(flags['cases']) == 1542
        assert not flags['failures'] and not flags['compute_differences']
        assert all(r['original'] == r['candidate'] for r in flags['cases'])
        assert {(r['cap'], r['pool'], r['flag_hex']) for r in flags['cases']} == {
            (cap, pool, flag) for cap in (0, 1000, 2**128 - 1) for pool in (0, 1)
            for flag in [''] + [bytes([b]).hex() for b in range(256)]}
    assert sha((HERE / 'exhaustive_flags.py').read_bytes()) == e['focused_driver']['sha256']
    spec = importlib.util.spec_from_file_location('ownership_analysis', HERE / 'analyze.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    for label in ('control', 'origins'):
        row = actual['variants'][label]
        assert len(row['unique_pairs']) == e['expected_counts'][label]
        assert row['candidate_windows'] == e['expected_counts'][label + '_windows']
        assert row['unique_raw_pairs'] == e['expected_counts'][label + '_raw']
        assert not row['equals_original_capture'] and not row['equals_original_elf_extent']
    assert len(actual['variants']['origins']['unmatched_original']) == e['expected_counts']['unmatched']
    assert actual['delta'] == dict(added_original_windows=sorted(r[0] for r in e['targets']), lost_original_windows=[])
    print(f"PASS: {len(e['targets'])} new complete body windows; raw-equal 776-byte cleanup, exact encoded cleanup calls and dispatch copy size; 34,662 suite cases plus 3,084 exact focused comparisons")


if __name__ == '__main__':
    main()
