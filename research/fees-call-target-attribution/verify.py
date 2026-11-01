"""Recompute the attribution evidence and reject mismatched inputs."""
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
    provenance = json.loads((HERE / 'input-provenance.json').read_text())
    assert len(provenance['harness_sha256']) == 187
    for name, expected in provenance['harness_sha256'].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    assert len(provenance['input_sha256']) == 26
    for name, expected in provenance['input_sha256'].items():
        override = provenance['source_overrides'].get(name)
        path = HERE / override if override else ROOT / name
        assert sha(path.read_bytes()) == expected, name
    build = provenance['build_result']
    assert build['exit_code'] == build['strip_exit_code'] == 0
    assert build['source_unchanged'] and build['input_sha256'] == provenance['input_sha256']
    spec = importlib.util.spec_from_file_location('call_attribution', HERE / 'attribute.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    assert actual['original_windows'] == 585 and actual['candidate_windows'] == 579
    assert actual['body_unique_pairs'] == 340
    assert actual['ambiguous_body_groups'] == 44 and actual['ambiguous_original_windows'] == 147
    assert actual['unmatched_original_windows'] == 98
    assert actual['unique_body_raw_equal_pairs'] == 57
    assert actual['graph_attributed_pairs'] == 393 and len(actual['newly_attributed_pairs']) == 53
    assert [len(row['additions']) for row in actual['rounds']] == [43, 10]
    assert len(actual['remaining_ambiguous']) == 31
    assert sum(len(row['original_unbound']) for row in actual['remaining_ambiguous']) == 94
    assert actual['local_call_edge_counts'] == {'bound_target': 2208, 'different_body_frontier': 26}
    assert not actual['encoded_call_conflicts']
    assert not actual['candidate_equals_original_capture']
    assert not actual['candidate_equals_original_elf_extent']
    for pair in actual['newly_attributed_pairs']:
        assert pair['original']['signature'] == pair['candidate']['signature']
        assert pair['final_witnesses']
    print('PASS: 340 unique body pairs, 53 call-context attributions in two rounds, 2,208 bound call edges; raw whole-file identity remains false')


if __name__ == '__main__':
    main()
