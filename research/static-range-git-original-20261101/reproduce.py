#!/usr/bin/env python3
"""Run static range CLIs in genuine sparse Git checkouts of retained Pump input."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

H = Path('reconstruction/harness')
POINTER = Path('reconstruction/base/original.so')
CAPTURE = Path('evidence/original/pump/deployed.so')
LINK = b'../../evidence/original/pump/deployed.so'
TOOLS = ('control_flow', 'stack_access')
START, SIZE = '0x14f4e0', '13224'  # The maintained CONTROL_FLOW.md example.


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args, input=None):
    return subprocess.run(['git', *map(str, args)], input=input, text=True,
                          capture_output=True, check=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--revision', help='use exact committed sources instead of working source bytes')
    parser.add_argument('--expect', choices=('base', 'fixed'), required=True)
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    revision = args.revision or git('-C', checkout, 'rev-parse', 'HEAD')
    sources = {H / (name + '.py'): (
        subprocess.check_output(['git', '-C', str(checkout), 'show', f'{revision}:{H.as_posix()}/{name}.py'])
        if args.revision else (checkout / H / (name + '.py')).read_bytes()) for name in TOOLS}
    result = {'revision': revision, 'expectation': args.expect,
              'git_version': git('--version'),
              'source_sha256': {p.as_posix(): sha(b) for p, b in sources.items()},
              'checkouts': [], 'controls': {}}
    with tempfile.TemporaryDirectory(prefix='static-range-git-') as temporary:
        parent = Path(temporary)
        # Probe host support before requesting a native-link checkout. The
        # materialized Git checkout and its regression always run on every host.
        native = parent / 'link-capability'
        try:
            native.symlink_to(parent, target_is_directory=True)
            native.unlink()
            modes = (False, True)
        except OSError as error:
            modes = (False,)
            result['native_link_skip'] = type(error).__name__
        direct_hashes = {}
        for native_links in modes:
            root = parent / ('native' if native_links else 'materialized')
            git('clone', '--shared', '--no-checkout', '--quiet', checkout, root)
            git('-C', root, 'config', 'core.symlinks', str(native_links).lower())
            git('-C', root, 'sparse-checkout', 'init', '--no-cone')
            git('-C', root, 'sparse-checkout', 'set', '--no-cone', '--stdin', input=(
                '/reconstruction/harness/*\n/reconstruction/base/original.so\n'
                '/evidence/original/pump/deployed.so\n'))
            git('-C', root, 'checkout', '--quiet', '--detach', revision)
            for path, data in sources.items():
                (root / path).write_bytes(data)
            pointer, capture = root / POINTER, root / CAPTURE
            captured = capture.read_bytes()
            assert pointer.is_symlink() == native_links
            assert pointer.read_bytes() == (captured if native_links else LINK)
            receipt = {'core_symlinks': native_links,
                       'pointer_git_mode': git('-C', root, 'ls-files', '-s', POINTER.as_posix()),
                       'capture_sha256': sha(captured), 'cases': []}

            def invoke(tool, left, right=None, output=None):
                command = [sys.executable, '-B', str(root / H / (tool + '.py'))]
                if tool == 'control_flow':
                    command += [str(left), '--start', START, '--size', SIZE]
                    if output is not None:
                        command += ['--json', str(output)]
                else:
                    command += ['--original', str(left), '--original-start', START,
                                '--original-bytes', SIZE, '--candidate', str(right or capture),
                                '--candidate-start', START, '--candidate-bytes', SIZE]
                return subprocess.run(command, capture_output=True, text=True, cwd=root)

            for tool in TOOLS:
                run = invoke(tool, capture)
                assert run.returncode == 0, run.stderr
                digest = sha(run.stdout.encode())
                if tool in direct_hashes:
                    assert direct_hashes[tool] == digest
                direct_hashes[tool] = digest
                receipt['cases'].append({'tool': tool, 'input': 'direct-capture',
                                         'exit': run.returncode, 'stdout_sha256': digest})
            cases = [('control_flow', 'canonical-pointer', pointer, None),
                     ('stack_access', 'original-pointer', pointer, capture),
                     ('stack_access', 'candidate-pointer', capture, pointer),
                     ('stack_access', 'both-pointers', pointer, pointer)]
            for tool, label, left, right in cases:
                run = invoke(tool, left, right)
                expected = 0 if native_links or args.expect == 'fixed' else 2
                assert run.returncode == expected, (label, run.stderr)
                if expected == 0:
                    assert sha(run.stdout.encode()) == direct_hashes[tool]
                else:
                    assert 'expected ELF64' in run.stderr and not run.stdout
                receipt['cases'].append({'tool': tool, 'input': label, 'exit': run.returncode,
                                         'stdout_sha256': sha(run.stdout.encode()),
                                         'diagnostic': run.stderr.replace(str(root), 'CHECKOUT').strip()})
            assert capture.read_bytes() == captured
            result['checkouts'].append(receipt)
            if native_links:
                continue
            # A copied, dereferenced original remains a normal ELF input.
            pointer.write_bytes(captured)
            for tool in TOOLS:
                run = invoke(tool, pointer)
                assert run.returncode == 0 and sha(run.stdout.encode()) == direct_hashes[tool]
            result['controls']['regular_original_copy'] = True
            # The resolver admits only the canonical Git payload, never a new
            # arbitrary text-path convention, including a newline variation.
            for payload in (LINK + b'\n', b'../elsewhere.so', LINK.replace(b'pump', b'fees')):
                pointer.write_bytes(payload)
                for tool in TOOLS:
                    run = invoke(tool, pointer)
                    assert run.returncode == 2 and 'expected ELF64' in run.stderr
                    assert pointer.read_bytes() == payload and capture.read_bytes() == captured
            result['controls']['arbitrary_text_rejected'] = 6
            pointer.write_bytes(LINK)
            # Existing exclusive report publication must preserve the pointer,
            # its resolved ELF, and an unrelated prior report after resolution.
            old = root / 'prior.json'
            old.write_bytes(b'previous diagnostic\n')
            for output in (pointer, capture, old):
                prior = output.read_bytes()
                run = invoke('control_flow', pointer if args.expect == 'fixed' else capture,
                             output=output)
                assert run.returncode == 2 and 'cannot create diagnostic report' in run.stderr
                assert output.read_bytes() == prior and capture.read_bytes() == captured
                assert pointer.read_bytes() == LINK
            result['controls']['occupied_report_inputs_preserved'] = 3
            # Missing canonical target stays a failure and publishes no report.
            capture.unlink()
            output = root / 'missing.json'
            run = invoke('control_flow', pointer, output=output)
            assert run.returncode == 2 and not output.exists() and pointer.read_bytes() == LINK
            if args.expect == 'fixed':
                assert 'captured original symlink target missing' in run.stderr
            result['controls']['missing_capture_rejected'] = True
    result['direct_stdout_sha256'] = direct_hashes
    result['postconditions_passed'] = True
    result['limits'] = ['Actual Git core.symlinks=false checkout; not a native Windows execution claim.',
                        'No program execution, compiler build, candidate modification or decoding-policy change.']
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'expectation': args.expect, 'checkouts': len(result['checkouts']),
                      'cases': sum(len(r['cases']) for r in result['checkouts']),
                      'controls': result['controls']}))


if __name__ == '__main__':
    main()
