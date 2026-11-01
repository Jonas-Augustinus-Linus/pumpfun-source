"""Actual dispatch CLI publication proof using retained captures and IDLs."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=ROOT)
    parser.add_argument('--revision', help='read the two product sources from this Git revision')
    parser.add_argument('--expect', choices=('base', 'fixed'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('dispatch_publication', ROOT / 'tests/test_recover_dispatch_publication.py')
    proof = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proof)
    rows = [proof.run_case(case, args.checkout, args.revision) for case in proof.CASES]
    failures = {row['case'] for row in rows if not row['inputs_preserved']}
    if args.expect == 'base':
        if failures != {'linked-capture', 'linked-idl', 'hardlinked-capture', 'hardlinked-idl'}:
            raise AssertionError(rows)
        if not next(row for row in rows if row['case'] == 'dangling')['unintended_target_created']:
            raise AssertionError(rows)
    else:
        if failures or any(row['unintended_target_created'] for row in rows):
            raise AssertionError(rows)
    for row in rows:
        expected_exit = 0 if row['case'] in ('fresh', 'regular', 'hardlinked-capture', 'hardlinked-idl') else 1
        if args.expect == 'base' and row['case'] in ('linked-capture', 'linked-idl', 'dangling'):
            expected_exit = 0
        if row['exit'] != expected_exit or row['temporary_entries']:
            raise AssertionError(row)
        if row['exit'] == 0 and row['report_sha256'] != proof.REPORT_SHA256:
            raise AssertionError(row)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump({'expect': args.expect, 'revision': args.revision, 'rows': rows,
                   'scope': 'Static product CLI runs in isolated copies. No compiler, VM or program execution.'}, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'cases': len(rows), 'input_changes': len(failures), 'expect': args.expect}))


if __name__ == '__main__':
    main()
