#!/usr/bin/env python3
"""Run the maintained wrapper and analyzer on unchanged captured ELFs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

WRAPPER = 'research/tooling-analysis-output-retention-20261029/generate.py'
HELPERS = ('scripts/analyze_program.py', 'scripts/window_elf_reader.py', 'scripts/deep_disassembly.py')
PROGRAMS = ('pump', 'pump_amm', 'pump_fees', 'mayhem')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(folder):
    return {p.name: sha(p.read_bytes()) for p in sorted(folder.iterdir())}


def invoke(root, script, program, output):
    return subprocess.run([sys.executable, '-B', str(root / script), '--program', program,
                           '--output', str(output)], cwd=root, capture_output=True, text=True)


def verify(folder):
    run = subprocess.run([sys.executable, '-B', str(folder / 'verify.py')], capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr


def copied(root, destination, form, evidence=True):
    for name in (*HELPERS, WRAPPER):
        out = destination / name
        out.parent.mkdir(parents=True, exist_ok=True)
        data = (root / name).read_bytes()
        if name in HELPERS and form == 'crlf':
            data = data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        out.write_bytes(data)
    if evidence:
        (destination / 'evidence').symlink_to(root / 'evidence', target_is_directory=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--checkout', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expect', choices=('base', 'fixed'), required=True)
    a = p.parse_args()
    root = a.checkout.resolve()
    captures = {n: sha((root / f'evidence/original/{n}/deployed.so').read_bytes()) for n in PROGRAMS}
    report = {'expectation': a.expect, 'base': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
              'helper_sha256': {n: sha((root/n).read_bytes()) for n in HELPERS},
              'wrapper_sha256': sha((root/WRAPPER).read_bytes()), 'records': [], 'negative_controls': []}
    with tempfile.TemporaryDirectory(prefix='analysis-wrapper-review-') as directory:
        temporary = Path(directory)
        crlf = temporary / 'crlf-source'
        copied(root, crlf, 'crlf')
        for name in PROGRAMS:
            direct = temporary / ('direct-' + name)
            run = invoke(root, 'scripts/analyze_program.py', name, direct)
            assert run.returncode == 0, run.stderr
            verify(direct)
            expected = digest(direct)
            assert len(expected) == 8
            summary = json.loads((direct / 'summary.json').read_text())
            for form, source in [('lf', root), ('crlf', crlf)]:
                output = temporary / (form + '-' + name)
                run = invoke(source, WRAPPER, name, output)
                row = {'program': name, 'helper_form': form, 'capture_sha256': captures[name],
                       'wrapper_exit': run.returncode, 'published': output.exists(),
                       'direct_artifact_sha256': expected, 'windows': summary['total_windows'],
                       'total_relocations': summary['total_relocations'],
                       'text_window_relocations': summary['text_window_relocations']}
                if a.expect == 'base':
                    assert run.returncode == 1 and not output.exists()
                    assert 'Unreviewed analysis helper: scripts/analyze_program.py' in run.stderr
                    row['diagnostic'] = run.stderr.strip()
                else:
                    assert run.returncode == 0, run.stderr
                    verify(output)
                    assert digest(output) == expected
                    row['all_eight_files_identical_to_direct'] = True
                    # An existing successful Mayhem/Pump/etc packet is not adopted by a second request.
                    again = invoke(source, WRAPPER, 'pump_fees' if name != 'pump_fees' else 'mayhem', output)
                    assert again.returncode == 1 and digest(output) == expected
                    row['existing_packet_preserved'] = True
                report['records'].append(row)
        # Each otherwise admitted helper is changed independently; no source can authorize itself.
        if a.expect == 'fixed':
            for form in ('lf', 'crlf'):
                copy = temporary / ('drift-' + form)
                copied(root, copy, form)
                for helper in HELPERS:
                    path = copy / helper
                    before = path.read_bytes()
                    path.write_bytes(before + b'\n# unreviewed drift\n')
                    output = temporary / ('reject-' + form)
                    run = invoke(copy, WRAPPER, 'mayhem', output)
                    assert run.returncode == 1 and not output.exists()
                    assert 'Unreviewed analysis helper: ' + helper in run.stderr
                    assert not list(temporary.glob('.' + output.name + '-stage-*'))
                    path.write_bytes(before)
                    report['negative_controls'].append({'form': form, 'helper': helper, 'changed_source_rejected': True})
            missing = temporary / 'missing-capture-source'
            copied(root, missing, 'lf', evidence=False)
            output = temporary / 'missing-capture-output'
            run = invoke(missing, WRAPPER, 'mayhem', output)
            assert run.returncode == 1 and not output.exists()
            assert 'Unreviewed' not in run.stderr
            assert not list(temporary.glob('.' + output.name + '-stage-*'))
            report['negative_controls'].append({'missing_capture_failed_without_publication_or_staging': True})
    assert captures == {n: sha((root / f'evidence/original/{n}/deployed.so').read_bytes()) for n in PROGRAMS}
    report['postconditions_passed'] = True
    report['scope'] = 'Four genuine unchanged captures, actual static CLIs. CRLF uses owned source copies on the same host; no Windows execution claim. No compiler or new VM experiment.'
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'expectation': a.expect, 'actual_wrapper_cases': len(report['records']),
                      'published': sum(x['published'] for x in report['records']), 'controls': len(report['negative_controls'])}))


if __name__ == '__main__':
    main()
