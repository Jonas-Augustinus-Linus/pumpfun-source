#!/usr/bin/env python3
"""Exercise saved-receipt CLI comparisons only; never execute a VM or fixture."""
import argparse
import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
BASE = '9bd38c7d5a4684b647ab59fc8942ed56e990e3b3'
HISTORY = 'b4448f7bc202063a711565b543ae4b49770def90'
MAYHEM = 'MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e'
MODES = ('buy', 'sell', 'buy_v2', 'sell_v2', 'buy_pump_swap', 'sell_pump_swap')
MALFORMED = ('original_rent_bool', 'candidate_rent_bool', 'candidate_exec_int',
             'candidate_lamports_float', 'both_rollback_rent_bool', 'payer_rent_bool')
METADATA_VARIANT = 'metadata_stack_height_float'
CONTROLS = ('lamports_changed', 'data_changed', 'signature_changed', 'wrong_image',
            'bad_harness', 'output_alias', 'optimized')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decoded(raw):
    return gzip.decompress(raw) if raw.startswith(b'\x1f\x8b') else raw


def git_bytes(repo, revision, path):
    return subprocess.check_output(['git', '-C', str(repo), 'show', revision + ':' + path])


def put(root, name, raw):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def verify_fixture_sources(repo):
    """Recheck the bounded extracts against their complete historical Git bytes."""
    provenance = json.loads((HERE / 'fixtures/provenance.json').read_bytes())
    archive = git_bytes(repo, HISTORY, 'repro/mayhem/twentyfour/test-snapshot.tar.gz')
    assert sha(archive) == provenance['historical_test_archive_sha256']
    for mode, record in provenance['source_receipts'].items():
        raw = git_bytes(repo, HISTORY, record['path'])
        assert sha(raw) == record['sha256']
        source = json.loads(decoded(raw))
        subset_raw = (HERE / 'fixtures' / (mode + '.json.gz')).read_bytes()
        assert sha(subset_raw) == record['extract_sha256']
        subset = json.loads(decoded(subset_raw))
        assert source['case_count'] == record['case_count']
        for selected, index in zip(subset['cases'], record['selected_indices'], strict=True):
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            assert canonical(selected) == canonical(source['cases'][index])
            assert sha(canonical(selected)) == record['selected_case_sha256'][str(index)]
    image = git_bytes(repo, HISTORY, provenance['candidate']['path'])
    assert sha(image) == provenance['candidate']['sha256']
    assert image == gzip.decompress((HERE / 'fixtures/historical-candidate.so.gz').read_bytes())


def prepare(repo, output, mode, revision=None, full=False):
    root = output / mode / 'cohort'
    root.mkdir(parents=True)
    script = 'scripts/verify_mayhem_' + (mode if 'pump_swap' not in mode else 'pump_swap') + '.py'
    for name in (script, 'scripts/pump_differential_output.py', 'scripts/mayhem_receipt_comparison.py'):
        if revision:
            check = subprocess.run(['git', '-C', str(repo), 'cat-file', '-e', revision + ':' + name],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode:
                continue
            raw = git_bytes(repo, revision, name)
        elif (repo / name).is_file():
            raw = (repo / name).read_bytes()
        else:
            continue
        put(root, name, raw)
    put(root, 'evidence/original/mayhem/deployed.so',
        (repo / 'evidence/original/mayhem/deployed.so').read_bytes())
    wrong = put(root, 'wrong-image.so', (repo / 'evidence/original/pump_fees/deployed.so').read_bytes())
    support_path = HERE / 'fixtures/historical-support.tar.gz'
    provenance = json.loads((HERE / 'fixtures/provenance.json').read_bytes())
    if sha(support_path.read_bytes()) != provenance['support_archive_sha256']:
        raise ValueError('historical support archive differs from its provenance')
    support = tarfile.open(support_path)
    if mode in ('buy', 'sell'):
        raw = (git_bytes(repo, HISTORY, 'repro/mayhem/twentyfour/' + mode + '-differential.json.gz')
               if full else (HERE / 'fixtures' / (mode + '.json.gz')).read_bytes())
        image = gzip.decompress((HERE / 'fixtures/historical-candidate.so.gz').read_bytes())
    else:
        with tarfile.open(repo / 'research/mayhem-v2-compressed-receipts/receipts/after-reports.tar.gz') as archive:
            raw = archive.extractfile(mode + '/report.json').read()
        image = (repo / 'evidence/original/mayhem/deployed.so').read_bytes()
    report = json.loads(decoded(raw))
    assert sha(image) == report['candidate_sha256']
    candidate = put(root, 'candidate.so', image)
    admitted = {}
    for name, digest in report['harness_sha256'].items():
        current = (repo / name).read_bytes() if (repo / name).is_file() else None
        if current is not None and sha(current) == digest:
            source = current
        else:
            member = name if mode in ('buy', 'sell') else 'v2/' + name
            source = support.extractfile(member).read()
        assert sha(source) == digest, name
        put(root, name, source)
        admitted[name] = digest
    support.close()
    return root, script, candidate, wrong, raw, report, admitted


def mutate(report, variant):
    from solders.transaction import Transaction
    report = copy.deepcopy(report)
    pair = report['cases'][0]
    # All preserved rejection controls have a complete signed transaction.
    rejected = next(row for row in report['cases'] if row['original']['error'] is not None)
    payer = str(Transaction.from_bytes(base64.b64decode(pair['candidate']['transaction_base64'])).message.account_keys[0])
    key = next(key for key, account in pair['candidate']['after'].items()
               if key not in (payer, MAYHEM) and account is not None
               and account['executable'] is False and account['rent_epoch'] == 0)
    target = pair['candidate']['after'][key]
    if variant in ('original_rent_bool', 'candidate_rent_bool'):
        side = variant.split('_')[0]
        pair[side]['after'][key]['rent_epoch'] = False
    elif variant == 'candidate_exec_int':
        target['executable'] = 0
    elif variant == 'candidate_lamports_float':
        target['lamports'] = float(target['lamports'])
    elif variant == 'both_rollback_rent_bool':
        payer = str(Transaction.from_bytes(base64.b64decode(rejected['candidate']['transaction_base64'])).message.account_keys[0])
        key = next(key for key, account in rejected['candidate']['after'].items()
                   if key not in (payer, MAYHEM) and account is not None
                   and account['rent_epoch'] == 0)
        for side in ('original', 'candidate'):
            rejected[side]['after'][key]['rent_epoch'] = False
    elif variant == 'payer_rent_bool':
        for side in ('original', 'candidate'):
            pair[side]['after'][payer]['rent_epoch'] = False
    elif variant == 'lamports_changed':
        target['lamports'] += 1
    elif variant == 'data_changed':
        for side in ('original', 'candidate'):
            pair[side]['after'][key]['data_base64'] = base64.b64encode(b'changed-data').decode()
    elif variant == 'signature_changed':
        wire = bytearray(base64.b64decode(pair['original']['transaction_base64']))
        wire[1] ^= 1
        tx = Transaction.from_bytes(bytes(wire))
        assert not all(tx.verify_with_results())
        for side in ('original', 'candidate'):
            pair[side]['transaction_base64'] = base64.b64encode(wire).decode()
            pair[side]['signature'] = str(tx.signatures[0])
            pair[side]['metadata']['signature'] = str(tx.signatures[0])
    elif variant == METADATA_VARIANT:
        entry = next(item for group in pair['candidate']['metadata']['inner_instructions']
                     for item in group if type(item.get('stackHeight')) is int)
        entry['stackHeight'] = float(entry['stackHeight'])
    return report


def run(repo, output, revision=None, full=False):
    output.mkdir(parents=True, exist_ok=False)
    if full:
        verify_fixture_sources(repo)
    rows = []
    for mode in MODES:
        root, script, candidate, wrong, raw, report, admitted = prepare(repo, output, mode, revision, full)
        variants = ('unchanged',) if full else ('unchanged', *MALFORMED, *CONTROLS)
        if not full and mode in ('buy', 'sell'):
            variants += (METADATA_VARIANT,)
        for encoding in (('source',) if full else ('plain', 'gzip')):
            for variant in variants:
                folder = output / mode / (encoding + '-' + variant)
                folder.mkdir()
                input_bytes = (raw if full else json.dumps(mutate(report, variant), separators=(',', ':')).encode())
                if not full and encoding == 'gzip':
                    input_bytes = gzip.compress(input_bytes, mtime=0)
                suffix = '.json.gz' if input_bytes.startswith(b'\x1f\x8b') else '.json'
                receipt = put(folder, 'receipt' + suffix, input_bytes)
                destination = receipt if variant == 'output_alias' else folder / 'verified.json'
                command = [sys.executable, '-B', *(['-O'] if variant == 'optimized' else []),
                           str(root / script), '--receipts', str(receipt), '--candidate',
                           str(wrong if variant == 'wrong_image' else candidate), '--output', str(destination)]
                changed_path = root / next(iter(admitted))
                saved = changed_path.read_bytes()
                if variant == 'bad_harness':
                    changed_path.write_bytes(saved + b'\n# changed bound source\n')
                environment = dict(os.environ)
                environment.pop('PYTHONOPTIMIZE', None)
                try:
                    process = subprocess.run(command, cwd=root, env=environment, capture_output=True,
                                             text=True, timeout=60)
                finally:
                    if variant == 'bad_harness':
                        changed_path.write_bytes(saved)
                put(folder, 'run.log', (process.stdout + process.stderr).encode())
                published = destination.exists() and destination != receipt
                result = json.loads(destination.read_bytes()) if published else None
                rows.append({'mode': mode, 'encoding': encoding, 'variant': variant,
                             'returncode': process.returncode, 'published': published,
                             'input_sha256': sha(input_bytes), 'input_preserved': receipt.read_bytes() == input_bytes,
                             'staging_leftovers': [p.name for p in folder.iterdir() if p.name.startswith('.')],
                             'result': result, 'harness_sources_rechecked': all(sha((root / n).read_bytes()) == h for n, h in admitted.items())})
        print(mode, 'retained cases', report['case_count'], flush=True)
    summary = {'base': BASE, 'verifier_revision': revision or 'working tree', 'full_corpus': full,
               'VM_executions': 0, 'rows': rows}
    (output / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--revision')
    parser.add_argument('--full-corpus', action='store_true', help='Requires the named historical Git objects; reads all882 legacy cases')
    args = parser.parse_args()
    run(args.repo.resolve(), args.output.resolve(), args.revision, args.full_corpus)
