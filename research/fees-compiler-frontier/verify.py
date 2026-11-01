#!/usr/bin/env python3
"""Re-derive the fixed-source compiler matrix and raw type-ID comparisons."""
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
    inherited = json.loads((HERE / 'inherited-provenance.json').read_text())
    expected_inputs = inherited['variants']['anchor-result-v144']['input_sha256']
    assert len(expected_inputs) == 26
    for variant in inherited['variants'].values():
        assert variant['input_sha256'] == expected_inputs
    assert len(experiment['harness_sha256']) == 187
    for name, expected in experiment['harness_sha256'].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    labels = dict(v144='anchor-result-v144', v145='anchor-result-v145',
                  v146='anchor-result-v146', **{'v1461-canonical': 'anchor-result-v1461'})
    for label, variant in experiment['variants'].items():
        assert variant['input_sha256'] == expected_inputs
        for name, expected in expected_inputs.items():
            path = HERE / variant['source_override'] if name == 'programs/pump-fees/src/types.rs' else ROOT / name
            assert sha(path.read_bytes()) == expected, name
        for kind, descriptor in variant['files'].items():
            old = inherited['variants'][labels[label]]['files'][kind]
            assert (descriptor['bytes'], descriptor['sha256']) == (old['bytes'], old['sha256'])
        replay = experiment['strip_replay'][label]
        assert replay['exit_code'] == 0
        assert replay['sha256'] == variant['files']['candidate']['sha256']
    canonical = json.loads((HERE / 'canonical/result.json').read_text())
    assert canonical['exit_code'] == canonical['strip_exit_code'] == 0
    assert canonical['source_unchanged'] and canonical['input_sha256'] == expected_inputs
    spec = importlib.util.spec_from_file_location('compiler_frontier', HERE / 'map_windows.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    print('PASS: fixed 26-input compiler matrix, all inferred boundaries, strip/source bindings, and unmasked type-ID comparisons')


if __name__ == '__main__':
    main()
