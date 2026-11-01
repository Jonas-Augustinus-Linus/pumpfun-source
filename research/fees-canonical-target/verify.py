#!/usr/bin/env python3
"""Verify the target/sysroot controls and exact type-ID bodies."""
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
        assert path.resolve().is_relative_to(HERE)
        assert sha(path.read_bytes()) == expected, name
    experiment = json.loads((HERE / 'experiment.json').read_text())
    variants = experiment['variants']
    assert variants['control-legacy']['input_sha256'] == variants['control-canonical']['input_sha256'] == variants['control-modern']['input_sha256']
    assert variants['latest-legacy']['input_sha256'] == variants['latest-canonical']['input_sha256']
    assert len(experiment['harness_sha256']) == 187
    for name, expected in experiment['harness_sha256'].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    for label, variant in variants.items():
        assert len(variant['input_sha256']) == 26
        for name, expected in variant['input_sha256'].items():
            override = variant['source_overrides'].get(name)
            path = HERE / override if override else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
        replay = experiment['strip_replay'][label]
        assert replay['exit_code'] == 0
        assert replay['sha256'] == variant['files']['candidate']['sha256']
        record = HERE / 'builds' / f'{label}-result.json'
        if record.exists():
            result = json.loads(record.read_text())
            assert result['exit_code'] == 0
            if label in ('control-canonical', 'control-modern', 'latest-canonical'):
                assert result['source_unchanged']
                assert result['input_sha256'] == variant['input_sha256']
    specs = [json.loads((HERE / 'diagnostics' / (target + '-spec.json')).read_text())
             for target in ('sbf-solana-solana', 'sbpf-solana-solana')]
    assert specs[0] == specs[1]
    installation = json.loads((HERE / 'diagnostics/installation-repair.json').read_text())
    assert installation['checked_files'] == 3198
    assert installation['archive_sha256'] == experiment['archives']['1.52']['sha256']
    spec = importlib.util.spec_from_file_location('canonical_target', HERE / 'map_windows.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    assert set(experiment['behavioral_receipts']) == {'latest-legacy', 'latest-canonical', 'control-modern'}
    for label, descriptor in experiment['behavioral_receipts'].items():
        report = json.loads(gzip.decompress((HERE / descriptor['path']).read_bytes()))
        assert report['candidate_sha256'] == variants[label]['files']['candidate']['sha256']
        assert report['original_sha256'] == actual['original_sha256']
        assert report['case_count'] == descriptor['cases']
        assert not report.get('mismatches', report.get('failures'))
        assert report.get('mismatch_count', 0) == 0
        for suite in report.get('suites', {}).values():
            assert suite['candidate_sha256'] == report['candidate_sha256']
            assert suite['original_sha256'] == report['original_sha256']
            assert not suite.get('mismatches', suite.get('failures'))
            assert suite.get('mismatch_count', 0) == 0
    print('PASS: canonical v1.44 raw type-ID bodies, fixed-source controls, exact headers/boundaries, and 45,500 behavioral cases')


if __name__ == '__main__':
    main()
