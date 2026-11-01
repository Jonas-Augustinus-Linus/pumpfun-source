#!/usr/bin/env python3
"""Verify the native control and the rejected ONE-source-change experiment."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
PACKET = Path(__file__).resolve().parent
EXPECTED = {'candidate.so': '86dbc2c64e81988dead173039b61fa01ba5f68a00fbb6f6dd49f2cda0afec37f',
            'symbols.so': '7271aaf8afe13b6c8f13a6cf0e9534896a66650dda13a2aa1b32e41edd46426d'}
REJECTED = {'candidate.so': '21062eb2fdb791f385e6529a7d3d2bb580e64b13d59f53803d89e5b32f272ef3',
            'symbols.so': '8d7f1e82d36c103a5bce56251a769a4d82ae544144ef074928c60b171e930027'}
OLD = '    let data = user_volume_accumulator.try_borrow_data()?;'
NEW = '    let data = match user_volume_accumulator.try_borrow_data() { Ok(data) => data, Err(error) => return Err(error.into()) };'
SELL = 'programs/pump-amm/src/instructions/swap/sell.rs'
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load(path):
    return json.loads(Path(path).read_text())


def authenticate(packet=PACKET):
    manifest = load(packet/'MANIFEST.json')
    actual = {str(p.relative_to(packet)): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
              for p in packet.rglob('*') if p.is_file() and p.name != 'MANIFEST.json'
              and '__pycache__' not in p.parts}
    require(actual == manifest['files'], 'Packet manifest/file inventory mismatch')
    return manifest


def source_files(path):
    result = {}
    with tarfile.open(path) as archive:
        for item in archive:
            relative = Path(item.name)
            require(item.isfile() and not relative.is_absolute() and '..' not in relative.parts,
                    'Non-regular or unsafe source archive member')
            require(str(relative) not in result, 'Duplicate source archive member')
            result[str(relative)] = archive.extractfile(item).read()
    return result


def verify_source_pair(control, candidate):
    require(len(control) == len(candidate) == 69 and set(control) == set(candidate), '69-input source set differs')
    expected = dict(control)
    text = control[SELL].decode()
    require(text.count(OLD) == 1, 'Original borrow expression changed')
    expected[SELL] = text.replace(OLD, NEW).encode()
    require(candidate == expected, 'Candidate differs beyond the one frozen real borrow match')
    require(candidate[SELL].count(b'\n') == control[SELL].count(b'\n'), 'Source line coordinates moved')


def verify_wrapper(reference, adapted, destination, count):
    require(reference.count('/out/') == count, 'Reference wrapper changed')
    require(adapted == reference.replace('/out/', destination+'/'), 'Wrapper changed beyond output transport paths')


def verify_census(rows, recorded, normalized, raw):
    require(rows == recorded, 'Full official 785-window census changed')
    require(len(rows) == 785 and sum(r['match'] is not None for r in rows) == normalized
            and sum(bool(r['raw']) for r in rows) == raw, 'Official counts differ')
    require(next(r for r in rows if int(r['original'], 16) == 0x4c750)['match'] is None, 'Sell must remain officially UNEQUAL')


def membership(before, after):
    result = {}
    for key in ['match', 'raw']:
        a = {r['original'] for r in before if r[key]}
        b = {r['original'] for r in after if r[key]}
        result[key] = {'gains': sorted(b-a), 'losses': sorted(a-b)}
    return result


def delta(before, after):
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    ranges = []
    for at in changed:
        if ranges and ranges[-1][1] == at:
            ranges[-1][1] += 1
        else:
            ranges.append([at, at+1])
    return {'before_bytes': len(before), 'after_bytes': len(after),
            'differing_common_extent_bytes': len(changed),
            'missing_after_bytes': max(len(before)-len(after), 0),
            'added_after_bytes': max(len(after)-len(before), 0),
            'changed_offset_runs': ranges}


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def verify(repo, packet=PACKET):
    authenticate(packet)
    plan = load(packet/'recorded/plan.json')
    require(plan['controller_sha256'] == sha((packet/'recorded/controller.py').read_bytes()), 'Recorded controller changed')
    require(plan['dispatcher_sha256'] == sha((packet/'recorded/dispatcher.py').read_bytes()), 'Dispatcher binding changed')
    require(plan['dependencies_sha256'] == sha((packet/'recorded/dependency-inputs.json.gz').read_bytes()), 'Dependency inventory binding changed')
    require(plan['seed_snapshot_sha256'] == sha((packet/'recorded/seed-before.json').read_bytes()), 'Protected seed binding changed')
    require(plan['reference_sha256'] == {p.name: sha(p.read_bytes()) for p in (packet/'reference').iterdir()}, 'Original builder inputs changed')
    require(plan['sdk_files'] == 2775 and plan['registry_packages'] == 257 and plan['archive_files'] == 8180, 'Input authentication scope differs')
    sdk = json.loads(gzip.decompress((packet/'reference/sdk-sha256.json.gz').read_bytes()))
    require(len(sdk) == 2775, 'SDK inventory incomplete')
    require(sdk['rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld'] == 'f28db3647fcf67bd47f012a1c47fe679f5787a4e2bf9cd5b6fe4914b10622bda', 'Actual host linker binding changed')
    sources = {m: source_files(packet/'recorded'/m/'source.tar.gz') for m in ['control', 'candidate']}
    verify_source_pair(sources['control'], sources['candidate'])
    require({p: sha(v) for p, v in sources['control'].items()} == plan['workspace_sha256'], 'Control workspace differs from canonical69')
    standalone = source_files(packet/'canonical-source.tar.gz')
    canonical = load(packet/'canonical-build-record.json')
    require(canonical['candidate_sha256'] == EXPECTED['candidate.so'] and canonical['symbols_sha256'] == EXPECTED['symbols.so'], 'Published container output binding changed')
    require(len(standalone) == 68 and {p: sha(v) for p,v in standalone.items()} == canonical['canonical_sha256'], 'Canonical standalone68 binding changed')
    require(plan['workspace_sha256'] == canonical['workspace_sha256'], 'Native inputs differ from published container workspace')
    preparation = load(packet/'recorded/portable-input-preparation.json')
    prepared_plan = load(packet/'recorded/portable-input-preparation-plan.json')
    require(preparation['compiler_invocations'] == 0 and preparation['returncode'] == 0,
            'Portable adapter must only claim its actual non-compiling input check')
    require(preparation['preparer_sha256'] == sha((packet/'build.py').read_bytes())
            and preparation['verifier_sha256'] == sha((packet/'verify.py').read_bytes()),
            'Portable input check does not bind current helper source')
    require(preparation['plan_sha256'] == sha((packet/'recorded/portable-input-preparation-plan.json').read_bytes()),
            'Portable input preparation plan changed')
    require(prepared_plan['workspace_sha256'] == plan['workspace_sha256']
            and prepared_plan['reference_sha256'] == plan['reference_sha256']
            and prepared_plan['controller_sha256'] == plan['controller_sha256'],
            'Portable preparation changed frozen source/controller/reference bytes')
    recipe = module(packet/'reference/workspace_recipe.py', 'native_workspace_recipe')
    expected_workspace = dict(standalone)
    crate, workspace = recipe.transform_manifest(standalone['programs/pump-amm/Cargo.toml'])
    expected_workspace['programs/pump-amm/Cargo.toml'] = crate
    expected_workspace['Cargo.toml'] = workspace
    expected_workspace['Cargo.lock'] = expected_workspace.pop('programs/pump-amm/Cargo.lock')
    require(sources['control'] == expected_workspace, 'Standalone-to-workspace transformation changed Rust or other inputs')
    records = {}
    for mode, hashes in [('control', EXPECTED), ('candidate', REJECTED)]:
        folder = packet/'recorded'/mode
        record = load(folder/'record.json')
        records[mode] = record
        require(record['hashes'] == hashes and record['returncode'] == 0 and record['compiler_build_invocations'] == 1, 'Build outcome changed')
        require(all(record[k] for k in ['source_unchanged_during_build', 'seed_unchanged', 'sdk_unchanged', 'registry_unchanged',
                                       'root_original_args_equal_after_transport_paths', 'root_effective_args_equal_after_transport_paths']), 'Preservation/compiler argument gate failed')
        require(record['source_sha256'] == record['source_after_sha256'] == {p: sha(v) for p,v in sources[mode].items()}, 'Actual built-source binding changed')
        require(record['plan_sha256'] == sha((packet/'recorded/plan.json').read_bytes()), 'Plan binding changed')
        for name, count in [('rustc_wrapper.py', 2), ('linker_wrapper.py', 5)]:
            verify_wrapper((packet/'reference'/name).read_text(), (folder/name).read_text(),
                           record['environment']['AMM_NATIVE_ROOT_WRAPPER'].rsplit('/', 1)[0], count)
        clean, build, strip = record['commands']
        require(all(x in clean for x in ['--release', '--target', 'sbpf-solana-solana', 'pump-amm-recovered', 'native-transfer-fee', '--offline']), 'Both locals were not explicitly cleaned')
        require(all(x in build for x in ['--release', '--locked', '--offline', '--verbose']), 'Build recipe changed')
        log = (folder/'build.log').read_text()
        require('Compiling native-transfer-fee' in log and 'Compiling pump-amm-recovered' in log and 'Finished `release`' in log, 'Both local compiler executions not retained')
        invocation = load(folder/'root-rustc-invocation.json')
        reference = load(packet/'reference/root-rustc-invocation.json')
        old = '/Users/shawwalters/Documents/Codex/2026-10-24/pumpfun-source/work/'
        env = record['environment']
        substitutions = {env['CARGO_TARGET_DIR']: old+'amm-workspace-current-20261027/target',
                         env['RUSTC'].removesuffix('/rust/bin/rustc'): old+'amm-linux-v144-20261027/sdk',
                         env['AMM_NATIVE_ROOT_WRAPPER'].rsplit('/', 1)[0]: '/out'}
        def mapped(s):
            for before, after in substitutions.items():
                s = s.replace(before, after)
            return s
        for key in ['original_arguments', 'effective_arguments']:
            require([mapped(x) for x in invocation[key]] == reference[key], 'Actual compiler args differ beyond disclosed transport paths')
    require(records['control']['control_exact'] is True, 'Hard both-ELF control gate did not pass')
    tools = packet/'layout-frontier-reconcile/tools'
    cfg = module(tools/'cfg_attribution.py', 'native_cfg')
    original = repo/'evidence/original/pump_amm/deployed.so'
    require(sha(original.read_bytes()) == '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7', 'Captured original changed')
    with tempfile.TemporaryDirectory(prefix='amm-native-verify-') as scratch:
        scratch = Path(scratch)
        images, census = {}, {}
        for mode, hashes in [('control', EXPECTED), ('candidate', REJECTED)]:
            images[mode] = {}
            for name, expected in hashes.items():
                raw = gzip.decompress((packet/'recorded'/mode/(name+'.gz')).read_bytes())
                require(sha(raw) == expected, 'Actual ELF digest differs')
                path = scratch/(mode+'-'+name)
                path.write_bytes(raw)
                images[mode][name] = path
            census[mode] = cfg.measure(original, images[mode]['symbols.so'])
            verify_census(census[mode], load(packet/'recorded'/mode/'census-785.json'), 784, 784 if mode == 'control' else 257)
        changes = membership(census['control'], census['candidate'])
        require(changes == records['candidate']['membership_changes'] and len(changes['raw']['losses']) == 527
                and not changes['raw']['gains'] and not changes['match']['losses'] and not changes['match']['gains'], 'Negative raw-loss membership was omitted or changed')
        before = images['control']['candidate.so'].read_bytes()
        after = images['candidate']['candidate.so'].read_bytes()
        captured = original.read_bytes()
        require(not any(captured[1268504:]), 'Original allocation suffix is not zero')
        complete_delta = {'control_to_rejected': delta(before, after),
                          'original_to_control': delta(captured[:1268504], before),
                          'original_to_rejected': delta(captured[:1268504], after)}
        require(complete_delta == json.loads(gzip.decompress((packet/'recorded/complete-byte-delta.json.gz').read_bytes())), 'Complete meaningful-byte delta changed')
        require(len(before) == 1268504 and len(after) == 1268480, 'Meaningful ELF lengths differ')
        o, c = cfg.Inventory(original, True), cfg.Inventory(images['control']['symbols.so'])
        a, b = o.graph(0x4c750, True), c.graph(0x4c750, True)
        mapping = cfg.bijection(a, b)
        require(mapping['verified'] and mapping['mapped_blocks'] == 77, 'Diagnostic control CFG map changed')
        on, cn = ({n['offset']:n for n in g['nodes']} for g in [a,b])
        slots = calls = polarity = 0
        for x, y in mapping['mapping'].items():
            left, right = on[x], cn[y]
            for q, r in zip(left['code'], right['code']):
                require(q['official_normalized_value'] == r['official_normalized_value'] and q['relocation'] == r['relocation'], 'Diagnostic value/register equality changed')
                slots += 1
                if q['actual_direct_callee']:
                    require(q['actual_direct_callee']['actual_target'] == r['actual_direct_callee']['actual_target'], 'Actual callee target changed')
                    calls += 1
            if left['term']['kind'] == 'conditional':
                polarity += left['machine_terminators'][-1]['official_normalized_value'][:2] != right['machine_terminators'][-1]['official_normalized_value'][:2]
        require((slots, calls, polarity) == (1049, 80, 1), 'Diagnostic attribution scope differs')
        rejected = cfg.Inventory(images['candidate']['symbols.so'])
        function = next(f for f in rejected.functions.values() if '4sell8cashback' in f['name'] and f['size'] > 500)
        require(function['size'] == 9000, 'Rejected sell size changed')
        rejected_graph = rejected.graph(function['start'], True)
        require(not cfg.bijection(a, rejected_graph)['verified'] and cfg.bijection(a, rejected_graph, topology_only=True)['verified'], 'Rejected candidate CFG diagnosis changed')
    return {'control_hashes': EXPECTED, 'candidate_hashes': REJECTED, 'official_windows': 785,
            'control_normalized': 784, 'control_raw': 784, 'candidate_normalized': 784,
            'candidate_raw': 257, 'raw_losses': 527, 'sell': 'UNEQUAL',
            'diagnostic_control_blocks': 77, 'identical_nonbranch_words_including_registers': 1049,
            'exact_actual_depth2_calls': 80, 'conditional_polarity_differences': 1,
            'runtime_executed_for_rejected_candidate': False, 'selection_changed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.repo.resolve()), indent=2))
