#!/usr/bin/env python3
"""Verify the retained Fees decoder-body experiment without rebuilding."""
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
        assert len(variant['input_sha256']) == 26
        for name, expected in variant['input_sha256'].items():
            path = HERE / variant['source_override'] if name == 'programs/pump-fees/src/types.rs' else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
        replay = experiment['strip_replay'][label]
        assert replay['exit_code'] == 0
        assert replay['sha256'] == variant['files']['candidate']['sha256']
    sources = json.loads((HERE / 'extracted-source-verification.json').read_text())
    assert not sources['failures'] and sources['crate_count'] == len(sources['crates']) == 252
    assert sources['checked_files'] == sum(c['checked_files'] for c in sources['crates']) == 7936
    spec = importlib.util.spec_from_file_location('fees_decoder_body_match', HERE / 'analyze.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads((HERE / 'analysis.json').read_text())
    for label, descriptor in experiment['behavioral_receipts'].items():
        report = json.loads(gzip.decompress((HERE / descriptor['path']).read_bytes()))
        assert report['candidate_sha256'] == experiment['variants'][label]['files']['candidate']['sha256']
        assert report['original_sha256'] == actual['original_sha256']
        assert report['case_count'] == descriptor['cases'] == 17331
        assert not report['mismatches'] and len(report['suites']) == 18
        for suite in report['suites'].values():
            assert suite['candidate_sha256'] == report['candidate_sha256']
            assert suite['original_sha256'] == report['original_sha256']
            assert not suite.get('mismatches', suite.get('failures'))
            assert suite.get('mismatch_count', 0) == 0
    print('PASS: both complete normalized instruction windows, retained ELF/source bindings, and 34,662 behavioral cases')


if __name__ == '__main__':
    main()
