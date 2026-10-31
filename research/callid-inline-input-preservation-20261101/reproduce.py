#!/usr/bin/env python3
"""Actual callid and inline parse-only CLIs on private retained input copies."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

LANE = Path('reconstruction/pump-main/lanes/callgraph-census')
ADAPTER = Path('reconstruction/diagnostics/census-portability/run.py')
ARCHIVE = Path('reconstruction/pump-main/lanes/v3-sell-payment-layout/candidate.so.gz')
FIXTURE = Path('reconstruction/harness/fixtures/inline-remarks-v144.json')
HARNESS = ('score.py', 'score_admission.py', 'llvm_tools.py', 'original_input.py',
           'instruction_stream.py', 'elf_symbols.py', 'win.py', 'coords.py',
           'fastbuild.py', 'build_process.py', 'source_inputs.py', 'link_order.py')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--checkout', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect', choices=('base', 'fixed'), required=True)
    ap.add_argument('--revision', help='read complete production source files from this Git revision')
    a = ap.parse_args()
    checkout = a.checkout.resolve()
    revision = a.revision or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, text=True).strip()
    def read(relative):
        if a.revision:
            return subprocess.check_output(['git', 'show', f'{a.revision}:{relative.as_posix()}'], cwd=checkout)
        return (checkout / relative).read_bytes()
    source_paths = [Path('reconstruction/harness') / n for n in HARNESS]
    source_paths += [LANE / n for n in ('census.py', 'callid_audit.py', 'capture_inline.py',
                                      'dataref_audit.py', 'blocksim.py', 'hotness.py')]
    source_paths += [ADAPTER]
    sources = {p: read(p) for p in source_paths}
    candidate = gzip.decompress(read(ARCHIVE))
    original = read(Path('evidence/original/pump/deployed.so'))
    inventory = read(Path('reconstruction/base/functions.tsv'))
    fixture = json.loads(read(FIXTURE))
    log = ('\n'.join(fixture['remarks']) + '\n').encode()
    result = {'revision': revision, 'expectation': a.expect,
              'source_sha256': {p.as_posix(): sha(b) for p,b in sources.items()},
              'candidate_sha256': sha(candidate), 'capture_sha256': sha(original),
              'compiler_remarks_sha256': sha(log), 'cases': [], 'controls': {}}
    with tempfile.TemporaryDirectory(prefix='callid-inline-preservation-') as temporary:
        root = Path(temporary)
        for path, content in sources.items():
            out = root / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(content)
        inputs = {
            root / 'candidate.so': candidate,
            root / 'evidence/original/pump/deployed.so': original,
            root / 'reconstruction/base/original.so': b'../../evidence/original/pump/deployed.so',
            root / 'reconstruction/base/functions.tsv': inventory,
            root / 'inline/build.log': log,
        }
        report = root / 'report.json'
        inline_report = root / 'inline/inline-remarks.json'
        alias = root / 'alias.json'
        def reset():
            for path in (report, inline_report, alias):
                if path.is_symlink() or path.exists():
                    path.unlink()
            for path, content in inputs.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        def invoke(tool, output=None, portable=False):
            command = [sys.executable, '-B', str(root / (ADAPTER if portable else LANE / tool))]
            if portable:
                command.append('callid')
            if tool == 'callid_audit.py':
                command += ['--cand', str(root / 'candidate.so'), '--json', str(output)]
            else:
                command += ['--parse-only', '--src', str(root / 'unused-src'), '--work', str(root / 'unused-work'),
                            '--out', str(root / 'inline'), '--caller', 'ToString']
            return subprocess.run(command, cwd=root, capture_output=True, text=True)
        # Production normal-output controls, repeated on the same stable input path.
        reset()
        for tool in ('callid_audit.py', 'capture_inline.py'):
            run = invoke(tool, report)
            assert run.returncode == 0, run.stderr
            path = report if tool == 'callid_audit.py' else inline_report
            expected = path.read_bytes()
            rerun = invoke(tool, report)
            assert rerun.returncode == 0 and path.read_bytes() == expected
            payload = json.loads(expected)
            if isinstance(payload, dict):
                payload.pop('candidate', None)  # only private absolute-path display metadata
            else:
                assert len(payload) == 2 and all(x['kind'] == 'missed' for x in payload)
            result['controls'][tool] = {'canonical_payload_sha256': sha(json.dumps(payload, sort_keys=True).encode()),
                                       'normal_replacement_preserved': True,
                                       'summary': {k: payload[k] for k in ('rounds','normalized_matched','bisimilar_matched')} if isinstance(payload, dict) else {'remarks':len(payload)}}
        assert all(p.read_bytes() == b for p,b in inputs.items())
        # The unchanged adapter must still execute the exact newly admitted callid source.
        portable = root / 'portable.json'
        run = invoke('callid_audit.py', portable, portable=True)
        assert run.returncode == 0, run.stderr
        assert portable.read_bytes() == report.read_bytes()
        result['controls']['portable_callid_matches_direct'] = True
        if a.expect == 'fixed':
            # Admission also runs before the build branch. The source/work paths
            # are absent, so this control cannot compile a candidate.
            reset()
            inline_report.symlink_to(root / 'inline/build.log')
            run = subprocess.run([sys.executable, '-B', str(root / LANE / 'capture_inline.py'),
                                  '--src', str(root / 'unused-src'), '--work', str(root / 'unused-work'),
                                  '--out', str(root / 'inline'), '--caller', 'ToString'],
                                 cwd=root, capture_output=True, text=True)
            assert run.returncode == 2 and 'report destination aliases an input' in run.stderr
            assert all(p.read_bytes() == b for p,b in inputs.items())
            assert not (root / 'unused-src').exists() and not (root / 'unused-work').exists()
            result['controls']['inline_build_entrypoint_rejected_before_build'] = True
        cases = [('candidate', root/'candidate.so', mode) for mode in ('same','symlink','hardlink')]
        cases += [('original-pointer', root/'reconstruction/base/original.so', 'same'),
                  ('resolved-capture', root/'evidence/original/pump/deployed.so', 'same'),
                  ('window-inventory', root/'reconstruction/base/functions.tsv', 'same')]
        cases += [('compiler-log', root/'inline/build.log', mode) for mode in ('symlink','hardlink')]
        for label, watched, mode in cases:
            reset()
            tool = 'capture_inline.py' if label == 'compiler-log' else 'callid_audit.py'
            output = inline_report if tool == 'capture_inline.py' else watched if mode == 'same' else alias
            if mode == 'symlink':
                output.symlink_to(watched)
            elif mode == 'hardlink':
                os.link(watched, output)
            before = {p: sha(p.read_bytes()) for p in inputs}
            run = invoke(tool, output)
            changed = [p.relative_to(root).as_posix() for p,h in before.items() if sha(p.read_bytes()) != h]
            if a.expect == 'base':
                assert run.returncode == 0 and changed == [watched.relative_to(root).as_posix()], (label, run.stderr, changed)
            else:
                assert run.returncode == 2 and not changed, (label, run.stderr, changed)
                assert 'report destination aliases an input' in run.stderr
            result['cases'].append({'tool':tool,'input':label,'alias':mode,'exit':run.returncode,
                                    'changed_inputs':changed,'before_sha256':before[watched],
                                    'after_sha256':sha(watched.read_bytes()),
                                    'diagnostic':run.stderr.replace(str(root),'OWNED').strip()})
    result['postconditions_passed'] = True
    result['limits'] = ['All destructive baseline effects occur only in disposable owned copies.',
                        'Input-alias admission at CLI entry only; no late-race or atomic-publication guarantee.',
                        'Compiler log uses retained authentic v1.44 remarks, not a new compiler run.',
                        'No program source changes, compiler flags, build, model or VM experiment.',
                        'Census input preservation is reserved to open #3849 and is unchanged.']
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'expectation':a.expect,'alias_cases':len(result['cases']),
                      'changed_inputs':sum(len(x['changed_inputs']) for x in result['cases']),
                      'portable_control':True,'normal_controls':2}))


if __name__ == '__main__':
    main()
