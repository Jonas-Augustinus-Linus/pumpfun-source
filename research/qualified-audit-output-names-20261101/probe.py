#!/usr/bin/env python3
"""Run the actual qualification CLI on unchanged retained workflow bytes.

The private manifest authenticates only this static YAML payload. No workflow,
packet verifier, compiler, VM or on-chain program is run. The generated audit's
ordinary JSON/hash verifier is run after each successful publication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ADAPTER = 'reconstruction/tooling/revalidation-qualification/audit.py'
CHECKER = 'scripts/revalidate_all.py'
PAYLOAD = '.github/workflows/search-dependency.yml'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_bytes(repo, name, revision):
    if revision is None:
        return (repo / name).read_bytes()
    return subprocess.check_output(['git', '-C', str(repo), 'show', f'{revision}:{name}'])


def cohort(repo, root, revision=None):
    for name in (ADAPTER, CHECKER):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source_bytes(repo, name, revision))
    packet = root / 'research/retained-workflow'
    packet.mkdir(parents=True)
    raw = source_bytes(repo, PAYLOAD, revision)
    (packet / 'workflow.yml').write_bytes(raw)
    (packet / 'manifest.json').write_text(
        json.dumps({'workflow.yml': sha(raw)}) + '\n', encoding='utf-8')


def inventory(root):
    return {path.relative_to(root).as_posix(): sha(path.read_bytes())
            for path in sorted(root.rglob('*')) if path.is_file()}


def invoke(root, output, *, limited=False):
    arguments = ['--repo', str(root), '--output', str(output)]
    if limited:
        # Actual filesystem write failure, with Python cleanup allowed to run.
        driver = (
            'import resource,runpy,signal,sys\n'
            'signal.signal(signal.SIGXFSZ,signal.SIG_IGN)\n'
            'resource.setrlimit(resource.RLIMIT_FSIZE,(64,64))\n'
            'sys.argv=sys.argv[1:]\n'
            'runpy.run_path(sys.argv[0],run_name="__main__")\n'
        )
        command = [sys.executable, '-B', '-c', driver, str(root / ADAPTER), *arguments]
    else:
        command = [sys.executable, '-B', str(root / ADAPTER), *arguments]
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


def observe(root, parent, name, *, occupied=None, limited=False):
    parent.mkdir(exist_ok=True)
    output = parent / name
    # Confirm that the final name itself is accepted by this filesystem.
    output.mkdir()
    output.rmdir()
    if occupied == 'directory':
        output.mkdir()
        (output / 'prior.txt').write_bytes(b'previous report\n')
    elif occupied == 'file':
        output.write_bytes(b'previous file\n')
    before = inventory(output) if output.is_dir() else (
        {'<file>': sha(output.read_bytes())} if output.exists() else {})
    completed = invoke(root, output, limited=limited)
    row = {
        'name_characters': len(name), 'name_encoded_bytes': len(os.fsencode(name)),
        'exit': completed.returncode,
        'stderr': completed.stderr.replace(str(root.parent), 'OWNED'),
        'published': output.is_dir() and (output / 'summary.json').is_file(),
        'auxiliary_entries': sorted(path.name for path in parent.iterdir() if path.name.startswith('.')),
    }
    if occupied:
        after = inventory(output) if output.is_dir() else {'<file>': sha(output.read_bytes())}
        row['prior_output_unchanged'] = after == before
    elif row['published']:
        summary = json.loads((output / 'summary.json').read_text(encoding='utf-8'))
        summary.pop('elapsed_seconds')
        row['summary'] = summary
        verified = subprocess.run([sys.executable, '-B', str(output / 'verify.py')],
                                  capture_output=True, text=True, timeout=30)
        row['generated_verifier_exit'] = verified.returncode
        row['static_inputs_sha256'] = sha((output / 'inputs.json').read_bytes())
        row['results'] = json.loads((output / 'results.json').read_text(encoding='utf-8'))
    return row, output


def reproduce(repo, revision=None):
    with tempfile.TemporaryDirectory(prefix='qualified-audit-output-') as temporary:
        # macOS's /var alias is correctly refused by output admission.
        temporary = Path(temporary).resolve()
        root = temporary / 'cohort'
        cohort(repo, root, revision)
        before = inventory(root)
        rows = {}
        cases = [
            ('ordinary', 'audit-report', None),
            ('ascii_240', 'a' * 240, None),
            ('unicode_240_bytes', '가' * 80, None),
            ('shared_prefix_one', 's' * 224 + '-first-output-01', None),
            ('shared_prefix_two', 's' * 224 + '-second-output02', None),
            ('occupied_directory', 'd' * 240, 'directory'),
            ('occupied_file', 'f' * 240, 'file'),
        ]
        for index, (label, name, occupied) in enumerate(cases):
            parent = temporary / ('shared-prefix' if label.startswith('shared_prefix') else str(index))
            rows[label], _ = observe(root, parent, name, occupied=occupied)
        if os.name == 'posix':
            for label, name in (('write_failure_cleanup', 'write-control'),
                                ('long_write_failure_cleanup', 'w' * 240)):
                failed, output = observe(root, temporary / label, name, limited=True)
                retry = invoke(root, output)
                failed['retry_exit'] = retry.returncode
                failed['retry_verified'] = subprocess.run(
                    [sys.executable, '-B', str(output / 'verify.py')],
                    capture_output=True, text=True, timeout=30).returncode == 0
                rows[label] = failed
        return {
            'adapter_sha256': before[ADAPTER], 'checker_sha256': before[CHECKER],
            'retained_payload': PAYLOAD,
            'retained_payload_sha256': before['research/retained-workflow/workflow.yml'],
            'inputs_unchanged': inventory(root) == before,
            'rows': rows,
            'scope': __doc__,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--revision')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = reproduce(args.repo.resolve(), args.revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
