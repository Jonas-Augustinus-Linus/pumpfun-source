#!/usr/bin/env python3
"""Check the Fees buffer/result-boundary packet without rebuilding."""
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
    assert len(experiment['harness_sha256']) == 187
    for name, expected in experiment['harness_sha256'].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    for label, variant in experiment['variants'].items():
        for name, expected in variant['input_sha256'].items():
            path = HERE / variant['source_override'] if name == 'programs/pump-fees/src/types.rs' else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
        replay = experiment['strip_replay'][label]
        assert replay['exit_code'] == 0
        assert replay['sha256'] == variant['files']['candidate']['sha256']
    sources = json.loads((HERE / 'extracted-source-verification.json').read_text())
    assert not sources['failures'] and sources['crate_count'] == len(sources['crates']) == 252
    assert sources['checked_files'] == sum(c['checked_files'] for c in sources['crates']) == 7936
    compiler_source = experiment['variants']['anchor-result-v144']['input_sha256']
    for label in ('anchor-result-v145', 'anchor-result-v146', 'anchor-result-v1461'):
        assert experiment['variants'][label]['input_sha256'] == compiler_source
    targets = json.loads((HERE / 'attempts/target-results.json').read_text())
    assert targets['sbf-solana-solana']['spec'] == targets['sbpf-solana-solana']['spec']
    assert targets['sbf-solana-solana']['minimal_compile_exit_code'] == 1
    assert targets['sbpf-solana-solana']['minimal_compile_exit_code'] == 0
    canonical = json.loads((HERE / 'attempts/v1461-canonical-result.json').read_text())
    assert canonical['exit_code'] == canonical['strip_exit_code'] == 0
    assert canonical['source_unchanged'] and canonical['input_sha256'] == compiler_source
    spec = importlib.util.spec_from_file_location('fees_result_boundary', HERE / 'analyze.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads((HERE / 'analysis.json').read_text())
    for label, descriptor in experiment['behavioral_receipts'].items():
        report = json.loads(gzip.decompress((HERE / descriptor['path']).read_bytes()))
        assert report['candidate_sha256'] == experiment['variants'][label]['files']['candidate']['sha256']
        assert report['original_sha256'] == actual['original_sha256']
        assert report['case_count'] == descriptor['cases']
        assert not report.get('mismatches', report.get('failures'))
        if 'mismatch_count' in report:
            assert report['mismatch_count'] == 0
        for suite in report.get('suites', {}).values():
            assert suite['candidate_sha256'] == report['candidate_sha256']
            assert suite['original_sha256'] == report['original_sha256']
            assert not suite.get('mismatches', suite.get('failures'))
    print('PASS: complete normalized parser body, source/artifact bindings, dependency receipt, and behavioral receipts')


if __name__ == '__main__':
    main()
