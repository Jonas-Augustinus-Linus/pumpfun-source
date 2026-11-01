"""Actual current-reader admission for both maintained roadmap diagnostics."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

BASE = '6ba22e69c608ecfc90e6bece310557fec7c5786e'
READER_CHANGE = 'dd746bd9579d20a6b60e69467fc1c0c5627bdf2a'
READER = 'scripts/window_elf_reader.py'
OLD_READER = 'b00c2c491dce839aba97b19fd9007da5eaa99902968d88e8c44bb071bb0c9c1c'
CURRENT_READER = 'd3b57510531d7977110e73474cf89310b68bf6705d134ffb3bc759e18d30bedd'
ARCHIVE = 'research/tooling-roadmap-call-classification-20261029'
PROGRAMS = ('pump', 'pump_amm', 'mayhem')
DIAGNOSTICS = {
    'roadmap-stable-attribution': ('attribution-inputs.json',
                                  ('scripts/reconstruction_roadmap.py', READER)),
    'defined-dynamic-calls': ('dynamic-call-inputs.json',
                             ('scripts/reconstruction_roadmap.py', READER, ARCHIVE + '/proof.py')),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def execute(root, script, output):
    environment = dict(os.environ, PYTHONHASHSEED='1')
    return subprocess.run([sys.executable, '-B', str(root / script), '--repo', str(root),
                           '--output', str(output)], cwd=root, env=environment,
                          capture_output=True, text=True)


def packet(root, output, binding_file):
    verified = subprocess.run([sys.executable, '-B', str(output / 'verify.py')],
                              cwd=root, capture_output=True, text=True)
    require(verified.returncode == 0, verified.stdout + verified.stderr)
    files = {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()}
    require(set(files) == {p.name for p in output.iterdir()}, 'non-file report entry')
    manifest = json.loads(files['manifest.json'])
    require(set(manifest) == set(files) - {'manifest.json'}, 'incomplete manifest')
    require(all(sha(files[n]) == value for n, value in manifest.items()), 'manifest mismatch')
    bindings = json.loads(files[binding_file])
    for name, value in bindings.items():
        if name != 'adapter_sha256':
            require(sha((root / name).read_bytes()) == value, 'source/capture binding mismatch')
    summaries = {}
    for name in PROGRAMS:
        data = json.loads(files[name + '-details.json'])
        capture = root / f'evidence/original/{name}/deployed.so'
        require(data['deployed_sha256'] == sha(capture.read_bytes()), 'capture identity mismatch')
        windows = data['window_details']
        summaries[name] = {'windows': len(windows),
                           'calls': sum(w['calls'] for w in windows),
                           'external_calls': sum(sum(w['syscalls'].values()) for w in windows)}
    return {'semantic_files_sha256': {name: sha(raw) for name, raw in sorted(files.items())
                                      if name not in ('manifest.json', binding_file)},
            'bindings': bindings, 'summaries': summaries, 'generated_verifier_passed': True}


def reproduce(checkout, expect, revision=None, prior_reader=False):
    checkout = Path(checkout).resolve()
    helper_paths = {'scripts/reconstruction_roadmap.py', READER, 'scripts/deep_disassembly.py'}
    helper_paths.update(p.relative_to(checkout).as_posix()
                        for p in (checkout / ARCHIVE).rglob('*')
                        if p.is_file() and '__pycache__' not in p.parts)
    sources = {name: (checkout / name).read_bytes() for name in sorted(helper_paths)}
    require(sha(sources[READER].replace(b'\r\n', b'\n')) == CURRENT_READER,
            'proof expects the reviewed current reader')
    captures = {f'evidence/original/{name}/deployed.so':
                (checkout / f'evidence/original/{name}/deployed.so').read_bytes() for name in PROGRAMS}
    wrappers = {}
    for name in DIAGNOSTICS:
        path = f'reconstruction/diagnostics/{name}/generate.py'
        wrappers[path] = (subprocess.check_output(['git', 'show', f'{revision}:{path}'], cwd=checkout)
                          if revision else (checkout / path).read_bytes())
    old_sources = dict(sources)
    old_wrappers = {}
    if prior_reader:
        old_sources[READER] = subprocess.check_output(
            ['git', 'show', READER_CHANGE + '^:' + READER], cwd=checkout)
        require(sha(old_sources[READER]) == OLD_READER, 'prior reader identity mismatch')
        old_wrappers = {path: subprocess.check_output(['git', 'show', BASE + ':' + path], cwd=checkout)
                        for path in wrappers}
    result = {'wrapper_revision': revision, 'reader_change': READER_CHANGE,
              'source_sha256': {name: sha(raw) for name, raw in sources.items()},
              'wrapper_sha256': {name: sha(raw) for name, raw in wrappers.items()},
              'capture_sha256': {name: sha(raw) for name, raw in captures.items()},
              'rows': [], 'prior_reader_controls': [], 'negative_controls': []}
    with tempfile.TemporaryDirectory(prefix='roadmap-reader-admission-') as temporary:
        temporary = Path(temporary)

        def layout(root, helper_bytes, wrapper_bytes, form):
            payloads = {**helper_bytes, **wrapper_bytes, **captures}
            for name, raw in payloads.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name == READER:
                    raw = raw.replace(b'\r\n', b'\n')
                    if form == 'CRLF':
                        raw = raw.replace(b'\n', b'\r\n')
                path.write_bytes(raw)
            return {name: sha((root / name).read_bytes()) for name in payloads}

        semantics = {}
        for form in ('LF', 'CRLF'):
            root = temporary / form
            retained = layout(root, sources, wrappers, form)
            for name, (binding_file, admitted) in DIAGNOSTICS.items():
                script = f'reconstruction/diagnostics/{name}/generate.py'
                output = temporary / f'{form}-{name}'
                run = execute(root, script, output)
                row = {'diagnostic': name, 'reader_form': form, 'exit': run.returncode,
                       'published': output.exists()}
                if expect == 'base':
                    require(run.returncode != 0 and not output.exists(), 'baseline unexpectedly succeeds')
                    require('unreviewed' in run.stderr and
                            ('ELF reader' in run.stderr or READER in run.stderr), run.stderr)
                    row['reader_admission_refusal'] = True
                else:
                    require(run.returncode == 0, run.stdout + run.stderr)
                    row.update(packet(root, output, binding_file))
                    row['prior_reader_semantics_match'] = None
                    if name in semantics:
                        require(row['semantic_files_sha256'] == semantics[name], 'LF/CRLF semantic drift')
                    semantics[name] = row['semantic_files_sha256']
                    original_packet = {p.name: p.read_bytes() for p in output.iterdir()}
                    repeat = execute(root, script, output)
                    require(repeat.returncode != 0, 'existing packet accepted')
                    require(original_packet == {p.name: p.read_bytes() for p in output.iterdir()},
                            'existing packet changed')
                    result['negative_controls'].append({'diagnostic': name, 'reader_form': form,
                                                        'existing_packet_preserved': True})
                    for index, source in enumerate(admitted):
                        path = root / source
                        raw = path.read_bytes()
                        path.write_bytes(raw + b'\n# unreviewed proof control\n')
                        denied_output = temporary / f'{form}-{name}-denied-{index}'
                        denied = execute(root, script, denied_output)
                        require(denied.returncode != 0 and not denied_output.exists()
                                and 'unreviewed' in denied.stderr, 'changed source was admitted')
                        path.write_bytes(raw)
                        result['negative_controls'].append({'diagnostic': name, 'reader_form': form,
                                                            'source': source, 'changed_source_rejected': True})
                if prior_reader:
                    old_root = temporary / (form + '-prior-' + name)
                    old_retained = layout(old_root, old_sources, old_wrappers, form)
                    old_output = temporary / (form + '-prior-packet-' + name)
                    old_run = execute(old_root, script, old_output)
                    require(old_run.returncode == 0, old_run.stdout + old_run.stderr)
                    old_packet = packet(old_root, old_output, binding_file)
                    result['prior_reader_controls'].append({'diagnostic': name, 'reader_form': form,
                                                           'reviewed_reader_lf_sha256': sha(old_sources[READER]), **old_packet})
                    if expect == 'fixed':
                        require(old_packet['semantic_files_sha256'] == row['semantic_files_sha256'],
                                'prior-reader semantic report changed')
                        row['prior_reader_semantics_match'] = True
                    require(all(sha((old_root / p).read_bytes()) == h for p, h in old_retained.items()),
                            'prior-reader inputs changed')
                result['rows'].append(row)
            require(all(sha((root / p).read_bytes()) == h for p, h in retained.items()), 'private inputs changed')
    require(all((checkout / p).read_bytes() == raw for p, raw in {**sources, **captures}.items()),
            'repository inputs changed')
    result['inputs_preserved'] = True
    result['scope'] = ('Actual static roadmap CLIs and three retained captures. Prior reader control is optional '
                       'and needs Git history; CI does not. Same-host LF/CRLF only; no native Windows, compiler or VM execution.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--expect', choices=('base', 'fixed'), required=True)
    parser.add_argument('--revision', help='read the two wrappers from this exact Git revision')
    parser.add_argument('--prior-reader', action='store_true', help='compare against the previous admitted reader')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists() and not args.output.is_symlink(), 'choose a fresh output file')
    result = reproduce(args.checkout, args.expect, args.revision, args.prior_reader)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'rows': len(result['rows']), 'published': sum(r['published'] for r in result['rows']),
                      'prior_reader_controls': len(result['prior_reader_controls']),
                      'negative_controls': len(result['negative_controls'])}))


if __name__ == '__main__':
    main()
