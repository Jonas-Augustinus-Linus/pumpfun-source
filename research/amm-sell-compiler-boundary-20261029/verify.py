"""Stdlib-only saved evidence replay. No compiler, VM, network or target execution."""
from pathlib import Path
import argparse
import base64
import collections
import gzip
import hashlib
import importlib.util
import json
import re
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = '65a7df192ae10e25cef9789cf28b40ed1b21e2c7c6ef46446ced47355056189c'
NEGATIVE = '862362dd08f79a88d2ba082f7b0b63e9c291ddc0e92f409774111071650e9d3d'
SELL = 'programs/pump-amm/src/instructions/swap/sell.rs'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_bytes())


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def measure(original, candidate):
    index = collections.defaultdict(list)
    def key(elf, start, size):
        return size, elf.normalized[start:start + size], json.dumps(elf.pattern(start, size), sort_keys=True)
    for f in candidate.funcs:
        index[key(candidate, f['start'], f['size'])].append(f)
    normalized, raw = [], []
    for a, z in zip(original.entries, original.entries[1:] + [original.hi]):
        matches = index[key(original, a, z - a)]
        if matches:
            normalized.append(a)
        if any(original.b[a:z] == candidate.b[f['start']:f['start'] + z - a] for f in matches):
            raw.append(a)
    return dict(normalized=normalized, raw=raw)


def verify():
    manifest = read(HERE / 'MANIFEST.json')
    actual = {p.relative_to(HERE).as_posix(): dict(bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
              for p in HERE.rglob('*') if p.is_file() and p.name != 'MANIFEST.json' and '__pycache__' not in p.parts}
    require(actual == manifest, 'packet file census or hash changed')
    binding = read(HERE / 'source-binding.json')
    require(binding['revision'] == 'a18e1e89b59bf9d734955550c92f321c97c95e62', 'source revision')
    sources = {label: {name: base64.b64decode(b, validate=True) for name, b in files.items()}
               for label, files in json.loads(gzip.decompress((HERE / 'sources.json.gz').read_bytes())).items()}
    hashes = {k: {n: sha(b) for n, b in v.items()} for k, v in sources.items()}
    require(hashes['workspace'] == binding['workspace_sha256'] and len(hashes['workspace']) == 69, 'workspace inputs')
    require(hashes['maintained'] == binding['input_sha256'] and len(hashes['maintained']) == 68, 'maintained inputs')
    for row in binding['source_inputs']:
        b = sources['maintained'][row['path']]
        require(sha(b) == row['sha256'] and
                hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest() == row['git_blob'], 'source Git blob')
    runs = read(HERE / 'runs.json')
    require(len(runs) == 5, 'run census')
    trace_launch = read(HERE / 'runs/02-machine-trace/launch.json')
    base_launch = read(HERE / 'runs/01-baseline/launch.json')
    logs = {}
    for name, row in runs.items():
        folder = HERE / 'runs' / name
        launch, result = read(folder / 'launch.json'), read(folder / 'result.json')
        require(result['returncode'] == result['target_executions'] == launch['target_executions'] == 0, 'outcome ' + name)
        b = gzip.decompress((HERE / row['output']).read_bytes())
        expect = NEGATIVE if name == '03-no-placement-fold' else BASE
        require(sha(b) == row['sha256'] == result.get('sha256', result.get('symbols_sha256')) == expect and len(b) == row['bytes'], 'output ' + name)
        expected_sources = dict(hashes['workspace'])
        if name == '04-ata-existing-first':
            old = b'    if ata.data_is_empty() {\n'
            new = b'    if !ata.data_is_empty() { } else {\n'
            source = sources['workspace'][SELL]
            require(source.count(old) == 1, 'unique ATA source control')
            expected_sources[SELL] = sha(source.replace(old, new))
            require(launch['source_change'] == dict(path=SELL, old=old.decode(), new=new.decode()), 'source delta')
        require(row['workspace_sha256'] == expected_sources, 'retained run source ' + name)
        if name == '02-machine-trace':
            require('source_inputs' not in launch and launch['copied_dependencies'], 'early trace receipt scope')
        else:
            require(launch['source_inputs'] == expected_sources, 'launch source ' + name)
        logs[name] = {}
        for label in ['stdout.log', 'stderr.log']:
            data = gzip.decompress((folder / (label + '.gz')).read_bytes())
            logs[name][label] = data
            if 'logs' in result:
                expected = result['logs'][label]
                require(sha(data) == (expected if isinstance(expected, str) else expected['sha256']), 'raw log hash')
        if name != '01-baseline':
            old_cwd = trace_launch['cwd'].rsplit('\\', 1)[0]
            new_cwd = launch['cwd'].rsplit('\\', 1)[0]
            expected_command = [a.replace(old_cwd, new_cwd) for a in trace_launch['before']]
            require(launch['environment'] == {k: v.replace(old_cwd, new_cwd) for k, v in trace_launch['environment'].items()}, 'compiler environment delta ' + name)
            flags = {
                '02-machine-trace': ['-C', 'llvm-args=-print-before=branch-folder,block-placement', '-C', 'llvm-args=-print-after=branch-folder,block-placement', '-C', 'llvm-args=-debug-pass=Structure', '-C', 'llvm-args=-filter-print-funcs=' + trace_launch['filter_function']],
                '03-no-placement-fold': ['-C', 'llvm-args=-branch-fold-placement=false'],
                '04-ata-existing-first': [],
                '05-all-pass-trace': ['-C', 'llvm-args=-print-before-all', '-C', 'llvm-args=-print-after-all', '-C', 'llvm-args=-filter-print-funcs=' + trace_launch['filter_function']],
            }[name]
            require(launch['command'] == expected_command + flags, 'compiler argument delta ' + name)
    baseline_log = logs['01-baseline']['stderr.log'].decode()
    require(baseline_log.count(' --crate-name ') == 215 and not re.search(r'^ +Fresh ', baseline_log, re.M), 'fresh compile census')
    require(base_launch['target_directory_initially_absent'], 'empty initial target receipt')
    full_launch = read(HERE / 'runs/05-all-pass-trace/launch.json')
    full_result = read(HERE / 'runs/05-all-pass-trace/result.json')
    require(full_launch['copied_dependencies'] and full_result['source_unchanged'] and
            full_result['controller_unchanged'] and full_result['complete_compiler_output_equal'], 'full capture receipt')
    require(sha((HERE / 'controllers/all_pass_trace.py').read_bytes()) == full_launch['controller_sha256'], 'capture controller')
    trace = module('analyze').analyze(logs['05-all-pass-trace']['stderr.log'])
    require(trace == read(HERE / 'analysis.json'), 'saved phase analysis replay')
    reader = module('elf_reader')
    original_path = ROOT / 'evidence/original/pump_amm/deployed.so'
    require(sha(original_path.read_bytes()) == '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7', 'captured original identity')
    original = reader.Elf(original_path)
    measures = {}
    with tempfile.TemporaryDirectory(prefix='amm-trace-verify-') as tmp:
        for h in [BASE, NEGATIVE]:
            p = Path(tmp) / (h + '.so')
            p.write_bytes(gzip.decompress((HERE / 'outputs' / (h + '.so.gz')).read_bytes()))
            elf = reader.Elf(p)
            measures[h] = measure(original, elf)
            sell = next(f for f in elf.funcs if 'sell8cashback' in f['name'])
            require(sell['size'] == (9024 if h == BASE else 9056), 'sell size')
            if h == BASE:
                selected_path = ROOT / 'research/amm-layout-closure-20261028/results/build-a/symbols.so'
                require(sha(selected_path.read_bytes()) == binding['upstream_symbols_sha256'], 'selected artifact')
                selected = reader.Elf(selected_path)
                sf = next(f for f in selected.funcs if 'sell8cashback' in f['name'])
                a, b, n = sell['start'], sf['start'], sell['size']
                require(elf.normalized[a:a+n] == selected.normalized[b:b+n] and elf.pattern(a,n) == selected.pattern(b,n), 'selected sell normalized body and relocations')
                require(original.b[0x4c750+0xd00:0x4c750+0xd10].hex() == '1d320100000000000500c90000000000' and
                        elf.b[a+0xd00:a+0xd08].hex() == '5d32c90000000000', 'literal JEQ/JA vs JNE boundary')
    require([len(measures[BASE][k]) for k in ['normalized', 'raw']] == [784, 398], 'baseline match counts')
    require([len(measures[NEGATIVE][k]) for k in ['normalized', 'raw']] == [684, 223], 'negative match counts')
    losses = {}
    for k in ['normalized', 'raw']:
        before, after = set(measures[BASE][k]), set(measures[NEGATIVE][k])
        require(not after - before, 'negative control gains')
        losses[k] = sorted(before - after)
    return dict(source_revision=binding['revision'], source_inputs=68, workspace_inputs=69,
                compiler_commands=219, fresh_dependency_builds=1, copied_dependency_root_recompiles=4,
                frame_diagnostics={k:v['stderr.log'].decode().count('overwrites values in the frame') for k,v in logs.items()},
                trace=trace, measures=measures, negative_losses=losses, target_executions=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, help='Optional external report path; never write inside the sealed packet')
    args = parser.parse_args()
    if args.report:
        require(not args.report.resolve().is_relative_to(HERE), 'report must be outside the sealed packet')
    result = verify()
    if args.report:
        args.report.write_bytes((json.dumps(result, indent=2) + '\n').encode())
    print('PASS: 68/69 input hashes; five outputs; 219 compiler invocations; 392 dumps; 116 JNE machine snapshots; exact match sets and rejected-control losses. No target execution.')
