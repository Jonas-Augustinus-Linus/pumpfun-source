"""Check source/build bindings, complete query windows, and differential receipts."""
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
            override = variant['source_overrides'].get(name)
            path = HERE / override if override else ROOT / name
            assert sha(path.read_bytes()) == expected, (label, name)
        build = json.loads((HERE / 'builds' / f'{label}-result.json').read_text())
        assert build['exit_code'] == build['strip_exit_code'] == 0
        assert build['source_unchanged'] and build['input_sha256'] == variant['input_sha256']
        replay = experiment['strip_replay'][label]
        assert replay['exit_code'] == 0 and replay['sha256'] == variant['files']['candidate']['sha256']
    control, proposal = experiment['variants']['control'], experiment['variants']['selectors']
    changed = {name for name in control['input_sha256']
               if control['input_sha256'][name] != proposal['input_sha256'][name]}
    assert changed == {'programs/pump-fees/src/lib.rs', 'programs/pump-fees/src/types.rs'}
    before = (HERE / control['source_overrides']['programs/pump-fees/src/types.rs']).read_text()
    after = (HERE / proposal['source_overrides']['programs/pump-fees/src/types.rs']).read_text()
    old = '#[derive(AnchorSerialize, AnchorDeserialize, Clone)]\npub struct Fees {'
    assert after == before.replace(old, old.replace('Clone)', 'Clone, Copy)'))
    before = (HERE / control['source_overrides']['programs/pump-fees/src/lib.rs']).read_text()
    after = (HERE / proposal['source_overrides']['programs/pump-fees/src/lib.rs']).read_text()
    prefix, suffix = after.split('\n#[inline(never)]\nfn select_quote_fees', 1)
    assert suffix.count('Pubkey::new_from_array(') == 3
    old_handler = next(line for line in before.splitlines() if line.startswith('    pub fn get_fees_with_quote_mint('))
    new_handler = next(line for line in prefix.splitlines() if line.startswith('    pub fn get_fees_with_quote_mint('))
    prefix = prefix.replace(new_handler, old_handler).replace('#[inline(never)] fn select_fee_tier', 'fn select_fee_tier')
    assert prefix.rstrip() == before.rstrip()
    spec = importlib.util.spec_from_file_location('query_analysis', HERE / 'analyze.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.analyze()
    assert actual == json.loads(gzip.decompress((HERE / 'analysis.json.gz').read_bytes()))
    assert len(actual['variants']['control']['unique_pairs']) == 340
    assert len(actual['variants']['selectors']['unique_pairs']) == 343
    assert len(actual['variants']['selectors']['unmatched_original']) == 95
    assert actual['variants']['selectors']['candidate_windows'] == 580
    assert len(actual['encoded_callee_bindings']) == 6 and len(actual['quote_constant_bindings']) == 3
    assert set(experiment['behavioral_receipts']) == {'control', 'selectors'}
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
    assert not actual['variants']['selectors']['equals_original_capture']
    assert not actual['variants']['selectors']['equals_original_elf_extent']
    print('PASS: three complete query windows, encoded callee/constant bindings, two-file source change, and 34,662 retained differential cases')


if __name__ == '__main__':
    main()
