#!/usr/bin/env python3
"""Verify the complete-window map and unchanged-body dispatch experiment."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def methods(raw):
    matches = list(re.finditer(
        r'(    #\[allow\(unused_variables\)\]\n    pub fn (\w+)[\s\S]*?)(?=\n    #\[allow|\n})', raw))
    assert len(matches) == 31
    return matches


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
            override = variant['source_overrides'].get(name)
            path = HERE / override if override else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
        replay = experiment['strip_replay'][label]
        assert replay['exit_code'] == 0
        assert replay['sha256'] == variant['files']['candidate']['sha256']
    spec = importlib.util.spec_from_file_location('dispatch_windows', HERE / 'map_windows.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    before = (HERE / 'sources/control-lib.rs').read_text()
    after = (HERE / 'sources/dispatch-order-lib.rs').read_text()
    assert sha(before.encode()) == experiment['variants']['parser-control']['input_sha256']['programs/pump-fees/src/lib.rs']
    left, right = methods(before), methods(after)
    assert {r[2]: r[1] for r in left} == {r[2]: r[1] for r in right}
    assert before[:left[0].start()] == after[:right[0].start()]
    assert before[left[-1].end():] == after[right[-1].end():]
    assert [r[2] for r in right] == [r['name'] for r in actual['original_dispatch_order']]
    aligned = (HERE / 'sources/declaration-lines-lib.rs').read_text()
    assert after.splitlines(keepends=True)[0].startswith('//! Partial reconstruction:')
    assert after.splitlines(keepends=True)[1].startswith('//! It is not the deployed program source.')
    assert aligned == ''.join(after.splitlines(keepends=True)[2:])
    assert [(i, line) for i, line in enumerate(aligned.splitlines(), 1)
            if line.startswith('declare_program!')] == [
                (27, 'declare_program!(pump);'), (28, 'declare_program!(pump_amm);')]
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
    assert set(experiment['behavioral_receipts']) == {'dispatch-order', 'declaration-lines'}
    print('PASS: complete window map, unchanged handler bodies, recovered dispatch/line origins, and 34,662 behavioral cases')


if __name__ == '__main__':
    main()
