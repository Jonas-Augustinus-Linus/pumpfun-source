#!/usr/bin/env python3
"""Run the current signature CLI and check adjacent comparisons in retained bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

PROGRAMS = ('pump', 'pump_amm', 'mayhem')
SOURCES = ('bytecode_signatures.py', 'window_elf_reader.py', 'deep_disassembly.py')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def scan(blob, start, end):
    """Decode the retained byte pairs independently of the analysis module."""
    offsets = []
    position = start
    while position < end:
        offsets.append(position)
        position += 16 if blob[position] == 0x18 else 8
    require(position == end, 'window ends inside an instruction')
    immediate = 0
    registers = []
    for first, second in zip(offsets, offsets[1:]):
        if blob[first] != 0x79 or struct.unpack_from('<h', blob, first + 2)[0] != 0:
            continue
        opcode = blob[second]
        if opcode in (0x15, 0x55):
            immediate += 1
        elif opcode in (0x1d, 0x5d):
            loaded = blob[first + 1] & 15
            operands = (blob[second + 1] & 15, blob[second + 1] >> 4)
            registers.append({'offset': hex(first), 'raw': blob[first:second + 8].hex(),
                              'loaded_register': loaded, 'compared_registers': list(operands),
                              'reads_loaded_register': loaded in operands})
    return immediate, registers


def collect(repo, *, revision=None, expected='fixed'):
    repo = Path(repo).resolve()
    sources = {name: (subprocess.check_output(
        ['git', '-C', str(repo), 'show', f'{revision}:scripts/{name}'])
        if revision else (repo / 'scripts' / name).read_bytes()) for name in SOURCES}
    inputs = {name: (repo / 'evidence/original' / name / 'deployed.so').read_bytes()
              for name in PROGRAMS}
    result = {'expectation': expected,
              'source_sha256': {name: sha(data) for name, data in sources.items()},
              'input_sha256': {name: sha(data) for name, data in inputs.items()},
              'programs': {}}
    with tempfile.TemporaryDirectory(prefix='signature-registers-') as temporary:
        root = Path(temporary)
        (root / 'scripts').mkdir()
        for name, data in sources.items():
            (root / 'scripts' / name).write_bytes(data)
        for name, data in inputs.items():
            path = root / 'evidence/original' / name / 'deployed.so'
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
        output = root / 'packet'
        command = [sys.executable, '-B', str(root / 'scripts/bytecode_signatures.py'),
                   '--output', str(output)]
        run = subprocess.run(command, capture_output=True, text=True, cwd=root)
        require(run.returncode == 0, run.stdout + run.stderr)
        verifier = subprocess.run([sys.executable, '-B', str(output / 'verify.py')],
                                  capture_output=True, text=True, cwd=root)
        require(verifier.returncode == 0, verifier.stdout + verifier.stderr)
        summary = json.loads((output / 'summary.json').read_bytes())
        for name, blob in inputs.items():
            patterns = json.loads((output / f'{name}-patterns.json').read_bytes())
            signatures = json.loads((output / f'{name}-signatures.json').read_bytes())
            require(len(patterns) == len(signatures), 'pattern/signature window count differs')
            immediate_total = register_total = checked_total = likely_total = 0
            witnesses = []
            for pattern, signature in zip(patterns, signatures):
                require(pattern['address'] == signature['address'], 'window identity differs')
                start = int(pattern['address'], 16)
                immediate, registers = scan(blob, start, start + pattern['size'])
                wanted = immediate + (len(registers) if expected == 'fixed' else 0)
                validation = pattern['validation']
                require(validation['discriminator_checks'] == wanted, 'raw comparison recount differs')
                require(validation['likely_account_validation'] == bool(wanted), 'window flag differs')
                require(signature['account_validation'] == validation, 'consumer validation differs')
                immediate_total += immediate
                register_total += len(registers)
                checked_total += wanted
                likely_total += bool(wanted)
                witnesses += [{'window': pattern['address'], **site} for site in registers]
            require(summary['programs'][name]['windows_with_validation'] == likely_total,
                    'summary validation count differs')
            result['programs'][name] = {'windows': len(patterns), 'immediate_pairs': immediate_total,
                'register_pairs': register_total, 'reported_checks': checked_total,
                'windows_with_validation': likely_total, 'register_witnesses': witnesses}
        result['packet_sha256'] = {path.name: sha(path.read_bytes()) for path in sorted(output.iterdir())}
        unchanged = {}
        for path in sorted(output.iterdir()):
            if path.name == 'manifest.json':
                continue  # It necessarily hashes the changed dependent report fields.
            data = path.read_bytes()
            if path.suffix == '.json':
                value = json.loads(data)
                if path.name in {f'{name}-{kind}.json' for name in PROGRAMS
                                 for kind in ('patterns', 'signatures')}:
                    key = 'validation' if path.name.endswith('-patterns.json') else 'account_validation'
                    for row in value:
                        for field in ('discriminator_checks', 'likely_account_validation'):
                            del row[key][field]
                elif path.name == 'summary.json':
                    for row in value['programs'].values():
                        del row['windows_with_validation']
                data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            elif path.name == 'README.md':
                lines = []
                for line in data.decode().splitlines():
                    if any(line.startswith('| ' + name + ' |') for name in PROGRAMS):
                        cells = line.split('|')
                        cells[-2] = ' VALIDATION_COUNT '
                        line = '|'.join(cells)
                    lines.append(line)
                data = '\n'.join(lines).encode()
            unchanged[path.name] = sha(data)
        result['unrelated_report_sha256'] = unchanged
        result['generated_verifier_exit'] = verifier.returncode
        require(all((root / 'evidence/original' / name / 'deployed.so').read_bytes() == data
                    for name, data in inputs.items()), 'private capture bytes changed')
    require(all((repo / 'evidence/original' / name / 'deployed.so').read_bytes() == data
                for name, data in inputs.items()), 'retained capture bytes changed')
    result['all_input_bytes_preserved'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--revision')
    parser.add_argument('--expect', choices=('base', 'fixed'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = collect(args.repo, revision=args.revision, expected=args.expect)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as target:
        json.dump(result, target, indent=2)
        target.write('\n')
    print(json.dumps({'expectation': args.expect, 'programs': {
        name: {key: value for key, value in row.items() if key != 'register_witnesses'}
        for name, row in result['programs'].items()}}))


if __name__ == '__main__':
    main()
