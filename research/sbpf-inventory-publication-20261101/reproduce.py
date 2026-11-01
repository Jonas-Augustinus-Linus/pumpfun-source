#!/usr/bin/env python3
"""Actual inventory CLI publication probe; no patched functions or fake tool."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def packet(path):
    if not (path / 'manifest.json').is_file():
        return None
    manifest = json.loads((path / 'manifest.json').read_text())
    canonical = dict(manifest)
    canonical.pop('generator_sha256')
    return {
        'programs': [{key: row[key] for key in ('name', 'instruction_count',
                     'input_sha256', 'text_bytes', 'covered_text_bytes', 'diagnostics_bytes')}
                    for row in manifest['programs']],
        'tool_revision': manifest['tool_revision'],
        'tool_sha256': manifest['tool_sha256'],
        'generator_sha256': manifest['generator_sha256'],
        'semantic_manifest_sha256': digest(json.dumps(canonical, sort_keys=True).encode()),
        'payload_sha256': {file.name: digest(file.read_bytes()) for file in sorted(path.iterdir())
                           if file.name != 'manifest.json'},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository', type=Path)
    parser.add_argument('--tool-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--revision', help='read exact tracked scripts from this Git revision')
    parser.add_argument('--expect', choices=('before', 'fixed'), required=True)
    parser.add_argument('--compare', type=Path, help='prior result whose normal payloads must match')
    args = parser.parse_args()
    root, source = args.repository.resolve(), args.tool_source.resolve()
    script = root / 'scripts/sbpf_disassembly_inventory.py'
    inputs = sorted((root / 'evidence').glob('**/deployed.so'))
    before = {str(p.relative_to(root)): digest(p.read_bytes()) for p in inputs}
    executable = source / 'target/release/sbpf'
    assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'],
        text=True).strip() == '422a6316cbb1ac60b07b60a555bfbcb8e557bcef'
    assert digest((source / 'Cargo.lock').read_bytes()) == (
        '998462a5c5cac8433f7039ea7727e0b80ab7e7f43ffd4b4f9c23599bfd5c2a1c')
    binary_before = digest(executable.read_bytes())
    rows = []
    with tempfile.TemporaryDirectory(prefix='inventory-publication-proof-') as temporary:
        temp = Path(temporary)
        # Each CLI reads unchanged script bytes and genuine captures from this
        # private cohort. Even the input/output-alias controls target owned copies.
        cohort = temp / 'cohort'
        source_bytes = {}
        for name in ('sbpf_disassembly_inventory.py', 'analyze.py',
                     'deep_disassembly.py', 'window_elf_reader.py'):
            relative = 'scripts/' + name
            data = subprocess.check_output(['git', '-C', str(root), 'show',
                args.revision + ':' + relative]) if args.revision else (root / relative).read_bytes()
            destination = cohort / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            source_bytes[relative] = data
        for path in inputs:
            destination = cohort / path.relative_to(root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(path.read_bytes())
        script = cohort / 'scripts/sbpf_disassembly_inventory.py'
        for case in ('normal', 'parent-link', 'dangling-link', 'populated-link',
                     'existing-empty', 'existing-full', 'existing-file', 'late-empty',
                     'capture-output', 'capture-output-link'):
            work = temp / case
            work.mkdir()
            target, output = work / 'target', work / 'inventory'
            inode = None
            preserved = None
            if case == 'dangling-link':
                output.symlink_to(target)
            elif case == 'populated-link':
                target.mkdir()
                (target / 'keep.txt').write_bytes(b'pre-existing output\n')
                output.symlink_to(target)
            elif case == 'parent-link':
                target.mkdir()
                (work / 'parent').symlink_to(target, target_is_directory=True)
                output = work / 'parent/inventory'
            elif case == 'existing-empty':
                output.mkdir(mode=0o750)
                inode = output.stat().st_ino
            elif case == 'existing-full':
                output.mkdir()
                (output / 'keep.txt').write_bytes(b'pre-existing output\n')
                inode = output.stat().st_ino
            elif case == 'existing-file':
                output.write_bytes(b'pre-existing output\n')
            elif case in ('capture-output', 'capture-output-link'):
                capture = cohort / 'evidence/original/pump_fees/deployed.so'
                if case == 'capture-output':
                    output = capture
                else:
                    output.symlink_to(capture)
            if case in ('populated-link', 'existing-full'):
                preserved = (output / 'keep.txt').read_bytes()
            elif case == 'existing-file':
                preserved = output.read_bytes()
            process = subprocess.Popen([sys.executable, '-B', str(script), '--tool-source',
                str(source), '--output', str(output)], cwd=cohort, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            inserted = False
            if case == 'late-empty':
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and process.poll() is None:
                    if list(work.glob('.inventory.*')):
                        output.mkdir(mode=0o750)
                        inode = output.stat().st_ino
                        inserted = True
                        break
                    time.sleep(0.001)
                if not inserted:
                    process.kill()
                    raise AssertionError('could not observe real staging boundary')
            stdout, stderr = process.communicate(timeout=120)
            published = target if case in ('dangling-link', 'populated-link') else output
            rows.append({'case': case, 'exit': process.returncode,
                'error_kind': stderr.decode().splitlines()[-1].split(':')[0] if stderr else None,
                'stdout_manifest': bool(stdout), 'leaf_is_symlink': output.is_symlink(),
                'late_destination_inserted': inserted,
                'existing_directory_preserved': inode == output.stat().st_ino
                    if inode is not None and output.exists() else None,
                'existing_bytes_preserved': (output.read_bytes() == preserved if output.is_file()
                    else (output / 'keep.txt').read_bytes() == preserved)
                    if preserved is not None else None,
                'directory_entries': sorted(p.name for p in published.iterdir())
                    if published.is_dir() else [],
                'staging_entries': sorted(p.name for p in work.glob('.inventory.*')),
                'packet': packet(published)})
        cohort_preserved = all((cohort / path).read_bytes() == data
                               for path, data in source_bytes.items())
        cohort_preserved &= all(digest((cohort / path).read_bytes()) == value
                                for path, value in before.items())
        generator_digest = digest(script.read_bytes())
    after = {str(p.relative_to(root)): digest(p.read_bytes()) for p in inputs}
    result = {'base_revision': subprocess.check_output(['git', '-C', str(root), 'rev-parse',
              args.revision or 'HEAD'], text=True).strip(), 'generator_sha256': generator_digest,
              'tool_sha256': binary_before, 'capture_files': len(before),
              'capture_bytes_unchanged': before == after,
              'private_cohort_bytes_unchanged': cohort_preserved,
              'tool_bytes_unchanged': binary_before == digest(executable.read_bytes()),
              'cases': rows}
    assert result['capture_bytes_unchanged'] and result['tool_bytes_unchanged'] and cohort_preserved
    by_case = {row['case']: row for row in rows}
    success = {'normal', 'parent-link'}
    if args.expect == 'before':
        success |= {'dangling-link', 'late-empty'}
    for row in rows:
        assert (row['exit'] == 0) == (row['case'] in success), row['case']
        assert not row['staging_entries'], row['case']
        assert row['existing_bytes_preserved'] is not False, row['case']
        if row['packet']:
            assert len(row['packet']['programs']) == 9
            assert len(row['packet']['payload_sha256']) == 27
            assert all(p['text_bytes'] == p['covered_text_bytes'] and not p['diagnostics_bytes']
                       for p in row['packet']['programs'])
    assert by_case['dangling-link']['leaf_is_symlink']
    assert by_case['populated-link']['leaf_is_symlink']
    assert by_case['late-empty']['late_destination_inserted']
    assert by_case['late-empty']['existing_directory_preserved'] == (args.expect == 'fixed')
    for case in ('existing-empty', 'existing-full'):
        assert by_case[case]['existing_directory_preserved']
    normal = by_case['normal']['packet']
    for case in success:
        assert by_case[case]['packet'] == normal
    if args.compare:
        previous = json.loads(args.compare.read_text())
        old = next(row['packet'] for row in previous['cases'] if row['case'] == 'normal')
        assert previous['tool_sha256'] == result['tool_sha256']
        assert old['payload_sha256'] == normal['payload_sha256']
        assert old['semantic_manifest_sha256'] == normal['semantic_manifest_sha256']
        assert old['programs'] == normal['programs']
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'cases'}))
    print(json.dumps([{k:v for k,v in row.items() if k not in ('packet','directory_entries')}
                      for row in rows], indent=2))


if __name__ == '__main__':
    main()
