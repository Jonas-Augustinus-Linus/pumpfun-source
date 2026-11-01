"""Replay sealed source, command, capture and raw-byte evidence without a compiler."""
from pathlib import Path
import base64
import gzip
import hashlib
import importlib.util
import json

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / 'amm-sell-compiler-boundary-20261029'
BASE = '65a7df192ae10e25cef9789cf28b40ed1b21e2c7c6ef46446ced47355056189c'
NAMED = '9700b485d6a535d120b3ba9b97b30e7cced2f25ad921d7f584b859452e7987e0'

def sha(data): return hashlib.sha256(data).hexdigest()
def read(path): return json.loads(path.read_bytes())
def unpack(path): return gzip.decompress(path.read_bytes())
def run_result(run):
    if run.name == '12-rust-mir-trace': return json.loads(unpack(run / 'result.json.gz'))
    return read(run / 'result.json')
def require(value, message):
    if not value: raise ValueError(message)
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
def inventory(root):
    return {p.relative_to(root).as_posix(): dict(bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
            for p in root.rglob('*') if p.is_file() and p.name != 'MANIFEST.json' and '__pycache__' not in p.parts}

def verify(check_seal=True):
    if check_seal: require(inventory(HERE) == read(HERE / 'MANIFEST.json'), 'packet seal')
    inputs = read(HERE / 'inputs.json')
    require(sha((PARENT / 'MANIFEST.json').read_bytes()) == inputs['parent_manifest_sha256'], 'parent seal identity')
    require(inventory(PARENT) == read(PARENT / 'MANIFEST.json'), 'unchanged parent packet')
    baseline = unpack(PARENT / inputs['parent_baseline'])
    named = unpack(HERE / 'outputs/named-symbols.so.gz')
    require(sha(baseline) == BASE and sha(named) == NAMED, 'raw compiler output identities')
    archive = json.loads(unpack(PARENT / 'sources.json.gz'))['workspace']
    source = {k: base64.b64decode(v) for k, v in archive.items()}
    source_hashes = {k: sha(v) for k, v in source.items()}
    binding = read(PARENT / 'source-binding.json')
    require(len(source) == 69 and source_hashes == binding['workspace_sha256'], '69 workspace inputs')
    prior = read(PARENT / 'runs/02-machine-trace/launch.json')
    prior_root = prior['cwd'].removesuffix('\\source')
    rows = read(HERE / 'runs.json')
    require(list(rows) == ['10-borrowed-guard', '11-rust-mir-trace', '12-rust-mir-trace', '13-named-ir-trace', '14-named-empty-condition'], 'five root recompiles')
    expected_changes = {
        '10-borrowed-guard': ('        let data = user_volume_accumulator.try_borrow_data()?;', '        let data = &user_volume_accumulator.try_borrow_data()?;'),
        '14-named-empty-condition': ('    if user_volume_accumulator.data_is_empty() {', '    let accumulator_empty = user_volume_accumulator.data_is_empty(); if accumulator_empty {'),
    }
    logs = {}
    for name, row in rows.items():
        run = HERE / 'runs' / name
        launch, result = read(run / 'launch.json'), run_result(run)
        root = launch['cwd'].removesuffix('\\source')
        command = [x.replace(prior_root, root) for x in prior['before']]
        extra = []
        if name == '11-rust-mir-trace': extra = ['-Zdump-mir=instructions::swap::sell::cashback', '-Zdump-mir-dir=' + root + '\\mir']
        if name == '12-rust-mir-trace': extra = ['-Zdump-mir=cashback', '-Zdump-mir-dir=' + root.split('\\amm-current-sell-controls\\')[0] + '\\mir12']
        if name == '13-named-ir-trace': extra = ['-Zfewer-names=no', '-C', 'llvm-args=-print-before-all', '-C', 'llvm-args=-print-after-all', '-C', 'llvm-args=-filter-print-funcs=' + prior['filter_function']]
        require(launch['command'] == command + extra, 'exact command delta: ' + name)
        if 'before' in launch: require(launch['before'] == command, 'recorded base command')
        require(launch['environment'] == {k: v.replace(prior_root, root) for k, v in prior['environment'].items()}, 'environment: ' + name)
        expected = dict(source_hashes)
        if name in expected_changes:
            change = launch['source_change']
            path = 'programs/pump-amm/src/instructions/swap/sell.rs'
            old, new = expected_changes[name]
            require(change == dict(path=path, old=old, new=new) and source[path].count(old.encode()) == 1, 'exact source replacement')
            altered = source[path].replace(old.encode(), new.encode())
            require(altered.count(b'\n') == source[path].count(b'\n'), 'unchanged source lines')
            expected[path] = sha(altered)
        require(launch['source_inputs'] == expected, 'complete source binding: ' + name)
        require(sha((HERE / row['controller']).read_bytes()) == launch['controller_sha256'], 'controller binding')
        require(result['source_unchanged'] and result['controller_unchanged'] and result['returncode'] == result['target_executions'] == 0, 'execution receipt')
        output = named if name == '13-named-ir-trace' else baseline
        require(result['sha256'] == row['output_sha256'] == sha(output) and row['output_bytes'] == len(output), 'output binding')
        require(row['baseline_output_equal'] == (name != '13-named-ir-trace'), 'full-file qualification')
        if 'complete_compiler_output_equal' in result: require(result['complete_compiler_output_equal'] == row['baseline_output_equal'], 'trace qualification')
        for filename, evidence in result['logs'].items():
            data = unpack(run / (filename + '.gz'))
            require(sha(data) == evidence['sha256'] and len(data) == evidence['bytes'], 'raw log identity')
            if filename == 'stderr.log':
                require(data.count(b'overwrites values in the frame') == 3, 'retained frame diagnostics')
                logs[name] = data
    require(read(HERE / 'runs/11-rust-mir-trace/result.json')['mir_files'] == {}, 'retained empty capture')
    captured = run_result(HERE / 'runs/12-rust-mir-trace')['mir_files']
    require(len(captured) == inputs['total_captured_mir_files'] == 3112, 'full capture receipt census')
    mirs = json.loads(unpack(HERE / 'mir/sell-snapshots.json.gz'))
    selected = {name: row for name, row in captured.items() if name.startswith('pump_amm_recovered.instructions-swap-sell-cashback.') and name.endswith('.mir')}
    require(len(mirs) == len(selected) == inputs['delivered_sell_mir_snapshots'] == 104 and set(mirs) == set(selected), 'delivered sell snapshot census')
    for name, text in mirs.items(): require(selected[name] == dict(bytes=len(text.encode()), sha256=sha(text.encode())), 'raw MIR identity')
    sources = json.loads(unpack(HERE / 'compiler/sources.json.gz'))
    identities = read(HERE / 'compiler/source-identities.json')
    require(len(sources) == len(identities) == 5, 'compiler source census')
    for source_row, identity in zip(sources, identities):
        data = source_row['content'].encode()
        require(all(source_row[k] == identity[k] for k in ['repository', 'path', 'revision']), 'compiler source coordinate')
        require(sha(data) == identity['sha256'] and len(data) == identity['bytes'] and hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == identity['git_blob'], 'compiler source Git binding')
        require(identity['revision'] == '08b7341888ab480dfaaa0698300cbbbbb2d75b53', 'recorded Rust revision')
    require((HERE / 'compiler/sdk-version.md').read_text().split()[0] == identities[0]['revision'], 'SDK recorded source revision')
    require(read(HERE / 'compiler/post-run-tools.json')['tools'] == read(PARENT / 'runs/01-baseline/launch.json')['tools'], 'retrospective tool hashes')
    analyzer = module('mir_cleanup_analysis', HERE / 'analyze.py')
    reader = module('mir_cleanup_reader', PARENT / 'elf_reader.py')
    observation = analyzer.analyze(mirs[inputs['final_mir']], logs['13-named-ir-trace'])
    comparison = analyzer.compare_sections(reader, baseline, named)
    result = dict(observation=observation, output_comparison=comparison, root_compiler_invocations=5, target_executions=0,
                  unchanged_output_runs=[name for name, row in rows.items() if row['baseline_output_equal']],
                  failed_capture='11-rust-mir-trace produced zero MIR files despite compiler success; no MIR claim is based on it.')
    if check_seal: require(result == read(HERE / 'analysis.json'), 'analysis replay')
    return result

if __name__ == '__main__':
    verify()
    print('PASS: packet and parent seals; five source/command/output receipts; 104 MIR snapshots; Rust condition cleanup -> empty LLVM block -> first SimplifyCFG removal; code/data/relocations equal, full named ELF unequal. No target execution.')
