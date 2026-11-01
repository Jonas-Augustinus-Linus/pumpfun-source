"""Replay both graph inventories and prove the eight new duplicate attributions."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    manifest = json.loads((HERE / 'manifest.json').read_text())
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file() and p.name != 'manifest.json' and '__pycache__' not in p.parts}
    assert actual == set(manifest)
    for name, expected in manifest.items():
        path = HERE / name
        assert path.resolve().is_relative_to(HERE) and not path.is_symlink() and sha(path.read_bytes()) == expected
    records = []
    for name, count in [('input-provenance.json', 34), ('previous-input-provenance.json', 26)]:
        p = json.loads((HERE / name).read_text())
        assert re.fullmatch('[0-9a-f]{40}', p['candidate_source_commit'])
        assert re.fullmatch(r'https://github\.com/lalalune/pumpfun-source/pull/\d+', p['candidate_source_pr'])
        assert len(p['harness_sha256']) == 187 and len(p['input_sha256']) == count
        for item, digest in p['harness_sha256'].items():
            assert sha((ROOT / item).read_bytes()) == digest
        for item, digest in p['input_sha256'].items():
            override = p['source_overrides'].get(item)
            assert sha((HERE / override if override else ROOT / item).read_bytes()) == digest
        build = p['build_result']
        assert build['exit_code'] == build['strip_exit_code'] == 0 and build['source_unchanged']
        assert build['input_sha256'] == p['input_sha256']
        records.append(p)
    spec = importlib.util.spec_from_file_location('refreshed_call_attribution', HERE / 'attribute.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    current, previous = [m.analyze(p) for p in records]
    assert current == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    assert previous == json.loads(gzip.decompress((HERE / 'previous-analysis.json.gz').read_bytes()))
    assert current['original_windows'] == previous['original_windows'] == 585
    assert current['candidate_windows'] == 580 and previous['candidate_windows'] == 579
    assert current['body_unique_pairs'] == 354 and previous['body_unique_pairs'] == 340
    assert current['graph_attributed_pairs'] == 415 and previous['graph_attributed_pairs'] == 393
    assert len(current['newly_attributed_pairs']) == 61 and len(previous['newly_attributed_pairs']) == 53
    assert [len(row['additions']) for row in current['rounds']] == [52, 9]
    assert current['unmatched_original_windows'] == 84
    assert current['ambiguous_body_groups'] == 44 and current['ambiguous_original_windows'] == 147
    assert current['unique_body_raw_equal_pairs'] == 57
    assert len(current['remaining_ambiguous']) == 26
    assert sum(len(row['original_unbound']) for row in current['remaining_ambiguous']) == 86
    before = {r['original']['address'] for r in previous['newly_attributed_pairs']}
    after = {r['original']['address'] for r in current['newly_attributed_pairs']}
    assert before < after and len(after - before) == 8
    for result in (current, previous):
        assert not result['encoded_call_conflicts']
        assert not result['candidate_equals_original_capture'] and not result['candidate_equals_original_elf_extent']
        for pair in result['newly_attributed_pairs']:
            assert pair['original']['signature'] == pair['candidate']['signature'] and pair['final_witnesses']
    assert current['local_call_edge_counts']['different_body_frontier'] == 22
    assert current['local_call_edge_counts']['bound_target'] == 2485
    print('PASS: 354 unique bodies plus 61 call-attributed duplicate pairs = 415 correspondences; 8 new duplicate attributions, no conflicts; no new machine-code coverage claimed')


if __name__ == '__main__':
    main()
