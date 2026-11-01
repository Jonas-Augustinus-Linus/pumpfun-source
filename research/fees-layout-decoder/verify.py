#!/usr/bin/env python3
"""Verify the bounded decoder reconstruction packet without rebuilding."""
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
        replay = experiment['strip_replay'][label]
        assert replay['exit_code'] == 0 and replay['matches_candidate']
        assert replay['sha256'] == variant['files']['candidate']['sha256']
        for name, expected in variant['input_sha256'].items():
            path = HERE / variant['source_override'] if name == 'programs/pump-fees/src/types.rs' else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
    assert experiment['variants']['control-v144']['input_sha256'] == experiment['variants']['control-v145']['input_sha256']
    launch = json.loads((HERE / 'v145-launch.json').read_text())
    result = json.loads((HERE / 'v145-result.json').read_text())
    assert launch['command'] == result['command']
    assert launch['input_sha256'] == result['input_sha256'] == experiment['variants']['control-v145']['input_sha256']
    assert result['exit_code'] == 0 and result['source_unchanged']
    spec = importlib.util.spec_from_file_location('fees_decoder_packet', HERE / 'analyze.py')
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
        for suite in report.get('suites', {}).values():
            assert suite['candidate_sha256'] == report['candidate_sha256']
            assert suite['original_sha256'] == report['original_sha256']
            assert not suite.get('mismatches', suite.get('failures'))
    print('PASS: source/artifact hashes, closed original CFG, decoder shape, compiler control, and receipt bindings')


if __name__ == '__main__':
    main()
