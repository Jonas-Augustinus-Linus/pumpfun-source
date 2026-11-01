"""Verify source, both ELF inventories, exact panic records, and saved runtime evidence."""
from pathlib import Path
import argparse, base64, difflib, gzip, hashlib, io, json, re, sys, tarfile, tempfile

sys.dont_write_bytecode = True
if not __debug__:
    raise SystemExit('Run verification without -O; assertions are required.')
P = Path(__file__).resolve().parent
R = next(p for p in P.parents if (p / 'evidence/original/pump_amm/deployed.so').is_file())
sys.path.insert(0, str(P / 'support'))
from measure import measure
from location_audit import audit
sha = lambda b: hashlib.sha256(b).hexdigest()
doc = lambda p: json.loads(p.read_bytes())


def source(path):
    with tarfile.open(fileobj=io.BytesIO(path.read_bytes()), mode='r:gz') as archive:
        result = {}
        for member in archive.getmembers():
            assert member.isfile() and not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
            assert member.name not in result
            result[member.name] = archive.extractfile(member).read()
        return result


def verify(signatures=False):
    manifest = doc(P / 'MANIFEST.json')
    files = {str(f.relative_to(P)): f for f in P.rglob('*') if f.is_file() and '__pycache__' not in f.parts}
    assert set(files) == set(manifest) | {'MANIFEST.json'}
    assert all(not files[n].is_symlink() and sha(files[n].read_bytes()) == h for n, h in manifest.items())
    result, upstream = doc(P / 'RESULT.json'), doc(P / 'UPSTREAM.json')
    assert result['whole_elf_equal'] is False and result['goal_complete'] is False
    assert result['counts'] == {'normalized': 783, 'raw': 236, 'unmatched': 2, 'total': 785}
    assert all(result[k] == [] for k in ['normalized_gains', 'normalized_losses', 'raw_gains', 'raw_losses'])
    assert upstream['upstream_pr'] == 548 and upstream['head'] == '59576b0d2d7496b75f49abbae36ec4974f4839b1'
    assert sha((P / 'UPSTREAM-source.tar.gz').read_bytes()) == upstream['archive_sha256']
    trees, records, rows = {}, {}, {}
    original = R / 'evidence/original/pump_amm/deployed.so'
    original_sha = sha(original.read_bytes())
    with tempfile.TemporaryDirectory(prefix='amm-location-verify-') as temporary:
        for label in ['control', 'candidate']:
            folder = P / label
            trees[label] = source(folder / 'source.tar.gz')
            record = records[label] = doc(folder / 'attempt.json')
            assert record['returncode'] == record['clean_returncode'] == 0
            assert record['source_unchanged'] and record['tools_unchanged'] and record['target_libraries_unchanged']
            assert record['source_sha256'] == record['source_after_sha256'] == {k: sha(v) for k, v in trees[label].items()}
            log = gzip.decompress((folder / 'build.log.gz').read_bytes()).decode()
            assert 'Compiling native-transfer-fee ' in log and 'Compiling pump-amm-recovered ' in log
            candidate = gzip.decompress((folder / 'candidate.so.gz').read_bytes())
            symbols = gzip.decompress((folder / 'unstripped.so.gz').read_bytes())
            score = doc(folder / 'score.json')
            assert sha(candidate) == score['candidate_sha256'] and sha(symbols) == score['unstripped_sha256']
            if label == 'control':
                assert sha(candidate) == upstream['candidate_sha256'] and sha(symbols) == upstream['symbols_sha256']
            else:
                assert sha(candidate) == result['candidate_sha256'] and sha(symbols) == result['unstripped_sha256']
            path = Path(temporary) / (label + '.so')
            path.write_bytes(symbols)
            measured = measure(original, path)
            assert measured == score['rows'] and len(measured) == 785
            assert sum(bool(r['match']) for r in measured) == 783 and sum(r['raw'] for r in measured) == 236
            rows[label] = measured
            locations = audit(original, path)
            assert len(locations['mismatches']) == (5 if label == 'control' else 0)
    assert trees['control'] == source(P / 'UPSTREAM-source.tar.gz')
    for field in ['tool_sha256', 'target_libraries_sha256', 'source_wrapper_sha256']:
        assert records['control'][field] == records['candidate'][field]
    for field in ['match', 'raw']:
        assert {r['original'] for r in rows['control'] if r[field]} == {r['original'] for r in rows['candidate'] if r[field]}
    assert set(trees['control']) == set(trees['candidate'])
    changed = [p for p in sorted(trees['control']) if trees['control'][p] != trees['candidate'][p]]
    relative = 'programs/pump-amm/src/state/volume_accumulator.rs'
    assert changed == [relative]
    before, after = (trees[n][relative].decode() for n in ['control', 'candidate'])
    tokens = lambda s: re.sub(r'\s+', '', re.sub(r'^\s*//.*$', '', s, flags=re.M))
    assert tokens(before) == tokens(after)
    assert re.findall(r'"(?:\\.|[^"\\])*"', before) == re.findall(r'"(?:\\.|[^"\\])*"', after)
    for line in [251, 263, 291, 292, 313, 327, 329, 331, 352]:
        assert before.splitlines()[line - 1] == after.splitlines()[line - 1]
    assert ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='a/' + relative, tofile='b/' + relative)) == (P / 'source.patch').read_text()
    runtime = source(P / 'runtime.tar.gz')
    read = lambda name: json.loads(gzip.decompress(runtime[name]) if name.endswith('.gz') else runtime[name])
    summary, progress, inputs = (read(n) for n in ['summary.json', 'progress.json', 'inputs.json'])
    candidate_sha = result['candidate_sha256']
    assert summary['candidate_sha256'] == inputs['candidate_sha256'] == candidate_sha
    assert summary['original_sha256'] == original_sha and summary['inputs_unchanged'] and not summary['mismatches']
    assert summary['suites'] == len(progress) == len({row['suite'] for row in progress}) == 25
    assert summary['replay_driver_sha256'] == sha((P / 'recorded-replay-driver.py').read_bytes())
    assert summary['observer_sha256'] == sha((P / 'input-snapshots/repro/pump_amm/owner6048-v144/runtime/observe_suite.py').read_bytes())
    assert all(sha((P / 'input-snapshots' / name).read_bytes()) == h for name, h in summary['harness_sha256'].items())
    if signatures:
        from solders.transaction import Transaction
    cases = transactions = count_signatures = log_differences = 0
    for row in progress:
        name = row['suite']
        assert row['returncode'] == 0 and not row['mismatches']
        receipt = runtime[name + '.json']
        sidecar = runtime[name + '-transactions.json.gz']
        assert sha(receipt) == row['receipt_sha256'] and sha(sidecar) == row['sidecar_sha256']
        report, observed = json.loads(receipt), json.loads(gzip.decompress(sidecar))
        assert report['candidate_sha256'] == candidate_sha and report['original_sha256'] == original_sha and not report['mismatches']
        assert report['case_count'] == len(report['cases']) == row['case_count']
        for case in report['cases']:
            left, right = case['original'], case['candidate']
            assert {k: v for k, v in left.items() if k != 'logs'} == {k: v for k, v in right.items() if k != 'logs'}, name
            log_differences += left.get('logs') != right.get('logs')
            if 'match' in case:
                assert case['match'] is True
            assert all(not case.get(k) for k in ['diff', 'mismatched_fields', 'mismatches'])
        assert observed['transaction_count'] == len(observed['transactions']) == row['transactions']
        assert observed['observer_sha256'] == summary['observer_sha256']
        script = Path(row['command'][3]).name
        assert observed['script_sha256'] == summary['harness_sha256']['scripts/' + script]
        local_signatures = 0
        for record in observed['transactions']:
            raw = base64.b64decode(record['transaction_base64'], validate=True)
            assert sha(raw) == record['transaction_sha256'] and record['all_signatures_verified'] is True
            assert record['amm_program_sha256'] in [candidate_sha, original_sha]
            if signatures:
                verified = Transaction.from_bytes(raw).verify_with_results()
                assert verified and all(verified) and len(verified) == record['signature_count']
            local_signatures += record['signature_count']
        assert local_signatures == observed['signature_count'] == row['signatures']
        cases += row['case_count']; transactions += row['transactions']; count_signatures += local_signatures
    assert (cases, transactions, count_signatures) == (17462, 35074, 35418)
    assert (summary['cases'], summary['transactions'], summary['signatures']) == (cases, transactions, count_signatures)
    print(json.dumps({'verified': True, 'normalized': 783, 'raw': 236, 'locations_equal': 9,
        'cases': cases, 'transactions': transactions, 'signatures': count_signatures,
        'raw_log_differences': log_differences, 'whole_elf_equal': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--signatures', action='store_true')
    verify(parser.parse_args().signatures)
