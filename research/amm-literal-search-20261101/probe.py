#!/usr/bin/env python3
"""Exercise real AMM note recording and read-only literal searches in scratch ledgers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASE = '599891304e83e853ec723dc1417550bef4e1c074'
SOURCES = ('scripts/amm_sell/attempts.py', 'scripts/amm_sell/sell_score.py',
           'scripts/amm_sell/ledger_io.py', 'scripts/window_elf_reader.py')
SLASH = chr(92)
PATH = SLASH.join(('C:', 'work', 'trial', 'report.json'))
NESTED_PATH = SLASH.join(('C:', 'evidence', 'report.json'))
NOTES = [
    ('quoted-note', 'Reuse the "parent" report after checking hashes.', None),
    ('unicode-note', '비교 결과: Δ layout café unchanged', None),
    ('path-note', 'Archive path ' + PATH + ' remains unchanged', None),
    ('phrase-note', 'Compare the parent report', None),
    ('gap-note', 'Compare the parent summary report', None),
    ('nested-note', 'Nested review metadata',
     {'notes': '결과 "stable"', 'path': NESTED_PATH}),
]
QUERIES = [
    ('quoted', '"parent"', ['quoted-note']),
    ('korean', '비교 결과', ['unicode-note']),
    ('unicode-case', 'δ LAYOUT CAFÉ', ['unicode-note']),
    ('backslash', PATH, ['path-note']),
    ('nested-literal', '결과 "stable"', ['nested-note']),
    ('nested-backslash', NESTED_PATH, ['nested-note']),
    ('ascii-case', 'REUSE THE', ['quoted-note']),
    ('contiguous-multiword', 'parent report', ['phrase-note']),
    ('negative', 'parent missing', []),
    ('serialized-metadata', '"lane": "quoted-note"', ['quoted-note']),
    ('escaped-quote', SLASH + '"parent' + SLASH + '"', ['quoted-note']),
    ('escaped-unicode', SLASH + 'uacb0' + SLASH + 'uacfc',
     ['unicode-note', 'nested-note']),
    ('escaped-backslash', PATH.replace(SLASH, SLASH + SLASH), ['path-note']),
    ('ordered-matches', 'REPORT',
     ['quoted-note', 'path-note', 'phrase-note', 'gap-note', 'nested-note']),
    ('all-rows', '', [note[0] for note in NOTES]),
]


def invoke(tool, ledger_root, *arguments):
    return subprocess.run(
        [sys.executable, '-B', str(tool), *arguments],
        env=dict(os.environ, AMM_SELL_SWARM=str(ledger_root), PYTHONUTF8='1'),
        capture_output=True, text=True, encoding='utf-8', timeout=30)


def record_notes(tool, ledger_root):
    """Let the actual supported recorder create every production row."""
    ledger_root.mkdir()
    for lane, text, data in NOTES:
        arguments = ['note', '--lane', lane, '--approach', 'literal-text',
                     '--kind', 'finding', '--text', text]
        if data is not None:
            arguments.extend(['--data', json.dumps(data, ensure_ascii=False)])
        result = invoke(tool, ledger_root, *arguments)
        if result.returncode or result.stderr:
            raise RuntimeError('note recorder failed: ' + result.stdout + result.stderr)
    ledger = ledger_root / 'ATTEMPTS.jsonl'
    rows = [json.loads(line) for line in ledger.read_bytes().splitlines()]
    if len(rows) != len(NOTES):
        raise RuntimeError('note recorder did not retain all six rows')
    for row, (lane, text, data) in zip(rows, NOTES):
        if (row['schema'], row['lane'], row['text'], row['data']) != (
                'amm-sell-note-v1', lane, text, data):
            raise RuntimeError('note recorder changed accepted note content')
    return ledger


def search_notes(tool, ledger_root):
    ledger = ledger_root / 'ATTEMPTS.jsonl'
    before = ledger.read_bytes()
    results = []
    for name, query, expected in QUERIES:
        result = invoke(tool, ledger_root, 'grep', query)
        if ledger.read_bytes() != before:
            raise RuntimeError('read-only search changed the ledger')
        lanes = [line.split('] ', 1)[1].split('/', 1)[0]
                 for line in result.stdout.splitlines()]
        results.append({'name': name, 'query': query, 'expected_lanes': expected,
                        'actual_lanes': lanes, 'returncode': result.returncode,
                        'stderr': result.stderr, 'stdout': result.stdout})
    return results


def stage_sources(root, destination, revision=None):
    hashes = {}
    for relative in SOURCES:
        raw = (subprocess.check_output(['git', '-C', str(root), 'show', revision + ':' + relative])
               if revision else (root / relative).read_bytes())
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        hashes[relative] = hashlib.sha256(raw).hexdigest()
    return hashes


def retained_controls(root, scratch, tools):
    """Compare unchanged saved ledgers through both complete query CLIs."""
    seen_source = root / 'scripts/amm_sell/lanes/provenance-rebuild/best_sell.rs'
    seen_bytes = seen_source.read_bytes()
    commands = [('summary',), ('best',), ('approaches',), ('grep', 'sell'),
                ('grep', ''), ('seen', str(seen_source))]
    rows = []
    for index, source in enumerate(sorted((root / 'scripts/amm_sell/lanes').glob('*/attempts.jsonl'))):
        folder = scratch / ('retained-' + str(index))
        folder.mkdir()
        raw = source.read_bytes()
        ledger = folder / 'ATTEMPTS.jsonl'
        ledger.write_bytes(raw)
        results = []
        for arguments in commands:
            before, after = [invoke(tool, folder, *arguments) for tool in tools]
            if (before.returncode or before.stderr or
                    (before.returncode, before.stdout, before.stderr) !=
                    (after.returncode, after.stdout, after.stderr)):
                raise RuntimeError('retained query changed or failed: ' + str(source) + repr(arguments))
            if ledger.read_bytes() != raw or source.read_bytes() != raw:
                raise RuntimeError('retained query changed ledger bytes')
            results.append({'arguments': list(arguments) if arguments[0] != 'seen' else
                            ['seen', str(seen_source.relative_to(root))],
                            'stdout_sha256': hashlib.sha256(before.stdout.encode()).hexdigest()})
        rows.append({'path': str(source.relative_to(root)), 'rows': len(raw.splitlines()),
                     'sha256': hashlib.sha256(raw).hexdigest(), 'commands': results})
    if seen_source.read_bytes() != seen_bytes:
        raise RuntimeError('seen query changed the source it hashed')
    return {'ledger_count': len(rows), 'row_count': sum(row['rows'] for row in rows),
            'query_calls_per_revision': len(rows) * len(commands),
            'all_outputs_identical': True, 'all_inputs_preserved': True,
            'seen_source_sha256': hashlib.sha256(seen_bytes).hexdigest(),
            'ledgers': rows}


def compare(root, base):
    if os.name == 'nt':
        raise RuntimeError('the existing note recorder requires POSIX fcntl')
    with tempfile.TemporaryDirectory(prefix='amm-literal-search-') as temporary:
        scratch = Path(temporary)
        baseline, current = scratch / 'baseline', scratch / 'current'
        hashes = {'base': stage_sources(root, baseline, base),
                  'current': stage_sources(root, current)}
        ledger_root = scratch / 'notes'
        ledger = record_notes(baseline / SOURCES[0], ledger_root)
        before = ledger.read_bytes()
        queries = {name: search_notes(folder / SOURCES[0], ledger_root)
                   for name, folder in [('base', baseline), ('current', current)]}
        if ledger.read_bytes() != before:
            raise RuntimeError('comparison changed the recorded ledger')
        return {'schema': 'amm-literal-search-v1', 'base_revision': base,
                'source_sha256': hashes, 'producer': 'actual base note CLI',
                'recorded_notes': len(NOTES), 'query_calls_per_revision': len(QUERIES),
                'same_ledger_bytes_for_both_revisions': True,
                'ledger_bytes_unchanged_after_queries': True,
                'queries': queries,
                'retained_controls': retained_controls(
                    root, scratch, [baseline / SOURCES[0], current / SOURCES[0]])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default=BASE)
    parser.add_argument('--repo', type=Path, default=ROOT)
    arguments = parser.parse_args()
    print(json.dumps(compare(arguments.repo.resolve(), arguments.base),
                     indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
