#!/usr/bin/env python3
"""Replay the saved-evidence CLI on owned copies; no RPC or program execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SOURCE_FILES = ('verify_evidence.py', 'capture.py', 'analyze.py')
MODES = (((), None), (('-O',), None), (('-OO',), None), ((), '1'), ((), '2'))
CAPTURE_CASES = (
    ('program', 'original/pump', '"program":"wrong-program",'),
    ('escaped_program', 'original/pump', '"\\u0070rogram":"wrong-program",'),
    ('commitment', 'original/pump', '"commitment":"processed",'),
    ('repeated_equal_value', 'original/pump', '"commitment":"finalized",'),
    ('legacy_owner', 'dependencies/associated_token', '"owner":"wrong-loader",'),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--revision', help='Read production source from this exact Git revision')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError('Choose a fresh proof output')
    sources = {}
    for name in SOURCE_FILES:
        sources[name] = (subprocess.check_output(['git', 'show', args.revision + ':scripts/' + name], cwd=repo)
                         if args.revision else (repo / 'scripts' / name).read_bytes())
    proof = {'revision': args.revision or 'working tree',
             'source_sha256': {name: sha(raw) for name, raw in sources.items()},
             'rows': [], 'network_calls': 0, 'program_executions': 0}
    with tempfile.TemporaryDirectory(prefix='evidence-json-members-') as temporary:
        root = Path(temporary)
        (root / 'scripts').mkdir()
        for name, raw in sources.items():
            (root / 'scripts' / name).write_bytes(raw)
        # Copy the exact retained nine-capture corpus and upstream provenance.
        for group in ('original', 'dependencies', 'upstream'):
            shutil.copytree(repo / 'evidence' / group, root / 'evidence' / group)
        inventory = {p.relative_to(root).as_posix(): sha(p.read_bytes())
                     for p in sorted((root / 'evidence').rglob('*')) if p.is_file()}
        proof['retained_input_sha256'] = inventory
        variants = [('unchanged', None, None)]
        for name, folder, prefix in CAPTURE_CASES:
            path = root / 'evidence' / folder / 'capture.json'
            text = path.read_text(encoding='utf-8')
            variants.append((name, path, ('{' + prefix + text[text.index('{') + 1:]).encode()))
        path = root / 'evidence/upstream/provenance.json'
        text = path.read_text(encoding='utf-8')
        for name, key in (('upstream_hash', 'pump.json'), ('escaped_upstream_hash', 'pump\\u002ejson')):
            mutated = text.replace('"pump.json":', '"' + key + '":"' + '0' * 64 + '","pump.json":', 1)
            assert mutated != text
            variants.append((name, path, mutated.encode()))
        variants.append(('upstream_map', path, ('{"file_sha256":{},' + text[text.index('{') + 1:]).encode()))
        path = root / 'evidence/original/pump/capture.json'
        wrong = json.loads(path.read_bytes())
        wrong['commitment'] = 'processed'
        variants.append(('unambiguous_wrong_commitment', path, json.dumps(wrong).encode()))
        for name, path, changed in variants:
            saved = path.read_bytes() if path else None
            if path:
                path.write_bytes(changed)
            try:
                for flags, optimize in MODES:
                    environment = dict(os.environ)
                    environment.pop('PYTHONOPTIMIZE', None)
                    if optimize is not None:
                        environment['PYTHONOPTIMIZE'] = optimize
                    command = [sys.executable, '-B', *flags, str(root / 'scripts/verify_evidence.py')]
                    run = subprocess.run(command, cwd=root, env=environment, capture_output=True,
                                         text=True, timeout=30)
                    proof['rows'].append({'case': name, 'flags': list(flags),
                                          'PYTHONOPTIMIZE': optimize, 'returncode': run.returncode,
                                          'verified_nine': '9 captures verified' in run.stdout,
                                          'stdout_sha256': sha(run.stdout.encode()),
                                          'duplicate_rejected': 'duplicate evidence field:' in run.stderr,
                                          'input_preserved': path is None or path.read_bytes() == changed})
            finally:
                if path:
                    path.write_bytes(saved)
        after = {p.relative_to(root).as_posix(): sha(p.read_bytes())
                 for p in sorted((root / 'evidence').rglob('*')) if p.is_file()}
        assert after == inventory
        proof['all_retained_inputs_preserved'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'invocations': len(proof['rows']),
                      'accepted': sum(row['verified_nine'] for row in proof['rows']),
                      'duplicates_rejected': sum(row['duplicate_rejected'] for row in proof['rows'])}))


if __name__ == '__main__':
    main()
