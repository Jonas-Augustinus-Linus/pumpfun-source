"""Verify source/build/body bindings and retained signed AMM comparisons."""
from collections import Counter
from io import BytesIO
from pathlib import Path, PurePosixPath
import base64
import difflib
import gzip
import hashlib
import importlib.util
import json
import tarfile
import tomllib

if not __debug__:
    raise SystemExit('Verification requires Python without -O')

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
AMM = 'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA'
ORIGINAL = '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
RUSTC = 'c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
CARGO = 'd28444578306fe5a4f40524331411340123004e9e6556322fcabdbe351fe265d'
STRIP = '12415dc01e08e4f606a1a4eac8c197d560c7883161d266312c821bf5db7bf8be'
DEPOSIT = 'programs/pump-amm/src/instructions/liquidity/deposit.rs'
LIB = 'programs/pump-amm/src/lib.rs'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def document(path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == '.gz' else raw)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def archive(path):
    result = {}
    with tarfile.open(fileobj=BytesIO(path.read_bytes()), mode='r:gz') as stream:
        for member in stream.getmembers():
            name = PurePosixPath(member.name)
            assert not name.is_absolute() and '..' not in name.parts and str(name) == member.name
            if member.isdir():
                continue
            assert member.isfile() and member.name not in result, member.name
            result[member.name] = stream.extractfile(member).read()
    return result


def source_changes(sources):
    parent, control, proposal = (sources[n] for n in ('parent', 'control', 'proposal'))
    assert {n for n in parent if parent[n] != control[n]} == {DEPOSIT, LIB}
    assert {n for n in control if control[n] != proposal[n]} == {DEPOSIT}
    lib = parent[LIB].decode()
    assert lib.count('pub use instructions::admin;') == 1
    assert control[LIB].decode() == lib.replace('pub use instructions::admin;', 'pub use instructions::{admin, liquidity};')
    old = parent[DEPOSIT].decode()
    before = ('    let base_reserve = a.pool_base_token_account.amount;\n'
              '    let user_quote_token_reserves = a.user_quote_token_account.amount;\n'
              '    let user_base_token_reserves = a.user_base_token_account.amount;')
    after = ('    let user_base_token_reserves = a.user_base_token_account.amount;\n'
             '    let user_quote_token_reserves = a.user_quote_token_account.amount;\n'
             '    let base_reserve = a.pool_base_token_account.amount;')
    assert old.count(before) == 1
    expected = old.replace(before, after)
    for mint in ('base', 'quote'):
        before = f'*a.{mint}_mint.to_account_info().owner == anchor_spl::token::ID'
        after = f'a.{mint}_mint.to_account_info().owner == a.token_program.key'
        assert expected.count(before) == 1
        expected = expected.replace(before, after)
    assert control[DEPOSIT].decode() == expected
    lines = expected.splitlines(keepends=True)
    assert lines[158].strip() == '' and 'i128::try_from(change)' in lines[159]
    lines[158] = '        let current_virtual = a.pool.virtual_quote_reserves;\n'
    lines[160] = '        a.pool.virtual_quote_reserves = current_virtual.checked_add(change)\n'
    assert proposal[DEPOSIT].decode() == ''.join(lines)
    assert 'i128::try_from(change)' in lines[159] and 'error!(PumpAmmError::Overflow)' in lines[161]
    for filename, left, right in (('context.patch', parent, control), ('source.patch', control, proposal)):
        patch = ''.join(''.join(difflib.unified_diff(left[n].decode().splitlines(keepends=True),
                                                   right[n].decode().splitlines(keepends=True),
                                                   fromfile='a/' + n, tofile='b/' + n))
                        for n in sorted(left) if left[n] != right[n])
        assert (HERE / filename).read_text() == patch, filename


def transactions(data, allowed, script_hash=None):
    from solders.transaction import Transaction
    tx = json.loads(gzip.decompress(data))
    if script_hash is not None:
        assert tx['script_sha256'] == script_hash
    known = tx['program_file_sha256']
    for path, row in known.items():
        assert path == row['path']
        if '/evidence/' in path:
            local = ROOT / ('evidence/' + path.split('/evidence/', 1)[1])
            assert digest(local.read_bytes()) == row['sha256']
        else:
            assert row['sha256'] in allowed
    observed, signatures, hashes = Counter(), 0, Counter()
    assert tx['transaction_count'] == len(tx['transactions'])
    for index, row in enumerate(tx['transactions']):
        assert row['sequence'] == index and row['all_signatures_verified'] is True
        raw = base64.b64decode(row['transaction_base64'], validate=True)
        assert digest(raw) == row['transaction_sha256']
        parsed = Transaction.from_bytes(raw)
        checks = parsed.verify_with_results()
        assert checks and all(checks) and len(checks) == row['signature_count']
        assert bytes(parsed) == raw
        signatures += len(checks)
        for image in row['loaded_programs'].values():
            assert known[image['path']] == image
        amm = row['loaded_programs'][AMM]['sha256']
        assert amm == row['amm_program_sha256'] and amm in allowed
        assert len(row['logs_sha256']) == 64
        observed[amm] += 1
        hashes[(amm, row['logs_sha256'])] += 1
    assert signatures == tx['signature_count']
    return len(tx['transactions']), signatures, observed, hashes


def runtime(evidence, images):
    final = digest(images['proposal']['candidate'])
    control = digest(images['control']['candidate'])
    files = archive(HERE / 'runtime.tar.gz')
    summary = json.loads(files['summary.json'])
    assert summary['candidate_sha256'] == final and summary['cases'] == 17462 and summary['mismatches'] == []
    base = ROOT / 'repro/pump_amm/pool-serialization-thirty-seven'
    commands = {r['suite']: r['command'] for r in document(base / 'replay-commands.json')['commands']}
    counts = document(base / 'summary.json')['suites']
    assert len(summary['suites']) == len(commands) == 25 and sum(counts.values()) == 17462
    assert {r['suite'] for r in summary['suites']} == set(commands)
    expected_members = {'summary.json'} | {n + suffix for n in commands for suffix in ('.json.gz', '-transactions.json.gz', '.log')}
    assert set(files) == expected_members
    for path, value in summary['inputs'].items():
        if path.endswith('/candidate.so'):
            assert value == final
        else:
            names = [n for n in evidence['harnesses'] if path.endswith('/' + n)]
            assert len(names) == 1 and evidence['harnesses'][names[0]] == value, path
    total_transactions = total_signatures = 0
    for row in summary['suites']:
        name = row['suite']
        raw = gzip.decompress(files[name + '.json.gz'])
        receipt = json.loads(raw)
        assert digest(raw) == row['receipt_sha256'] and digest(files[name + '-transactions.json.gz']) == row['sidecar_sha256']
        assert receipt['candidate_sha256'] == final and receipt['original_sha256'] == ORIGINAL
        assert row['case_count'] == receipt['case_count'] == len(receipt['cases']) == counts[name]
        assert receipt['mismatches'] == []
        expected_logs = Counter()
        for case in receipt['cases']:
            if 'match' in case:
                assert case['match'] is True
            for field in ('diff', 'mismatched_fields'):
                if field in case:
                    assert case[field] == []
            for side, sha in (('original', ORIGINAL), ('candidate', final)):
                result = case.get(side)
                if isinstance(result, dict) and isinstance(result.get('logs'), list):
                    expected_logs[(sha, digest(json.dumps(result['logs'], separators=(',', ':')).encode()))] += 1
        observer = json.loads(gzip.decompress(files[name + '-transactions.json.gz']))
        assert observer['observer_sha256'] == evidence['harnesses']['repro/pump_amm/owner6048-v144/runtime/observe_suite.py']
        script = commands[name][1]
        n, signatures, seen, logs = transactions(files[name + '-transactions.json.gz'], {ORIGINAL, final}, evidence['harnesses'][script])
        assert not expected_logs - logs
        assert n == row['transactions'] == 2 * counts[name] + (150 if name == 'boost' else 0)
        assert signatures == row['signatures'] and seen[ORIGINAL] >= counts[name] and seen[final] >= counts[name]
        actual_command = row['command']
        assert actual_command[3].endswith('/' + script)
        total_transactions += n
        total_signatures += signatures
    assert (total_transactions, total_signatures) == (35074, 35418)
    focused = module('deposit_focused_contract', HERE / 'focused.py')
    report = document(HERE / 'focused.json.gz')
    assert report['candidate_sha256'] == final and report['control_sha256'] == control and report['original_sha256'] == ORIGINAL
    assert report['mismatches'] == [] and len(report['cases']) == 12
    assert [r['case'] for r in report['cases']] == focused.cases()
    expected_logs = Counter()
    for row in report['cases']:
        a, b, c = (row[k] for k in ('original', 'control', 'candidate'))
        assert row['match'] and focused.observed(a) == focused.observed(c)
        assert row['control_exact'] and b == c
        assert row['raw_logs_equal'] == (a['logs'] == c['logs'])
        line = row['case']['error_line']
        assert a['error'] is None if line is None else a['error'] is not None and any(f'deposit.rs:{line}.' in log for log in a['logs'])
        for sha, result in ((ORIGINAL, a), (control, b), (final, c)):
            expected_logs[(sha, digest(json.dumps(result['logs'], separators=(',', ':')).encode()))] += 1
    n, sigs, seen, logs = transactions((HERE / 'focused-transactions.json.gz').read_bytes(), {ORIGINAL, control, final}, digest((HERE / 'focused.py').read_bytes()))
    assert n == sigs == 36 and seen == Counter({ORIGINAL: 12, control: 12, final: 12}) and logs == expected_logs
    return dict(cases=17462, transactions=total_transactions, signatures=total_signatures, focused_triples=12)


def main():
    evidence = document(HERE / 'evidence.json')
    assert evidence['schema'] == 1 and evidence['original_sha256'] == ORIGINAL
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file() and p.name != 'evidence.json' and '__pycache__' not in p.parts}
    assert set(evidence['files']) == actual
    for name, expected in evidence['files'].items():
        assert digest((HERE / name).read_bytes()) == expected, name
    for name, expected in evidence['harnesses'].items():
        assert digest((ROOT / name).read_bytes()) == expected, name
    sources = {}
    for name, spec in evidence['archives'].items():
        source = archive(HERE / spec['path'])
        assert len(source) == 52 and {n: digest(data) for n, data in source.items()} == spec['inputs']
        assert all(not n.endswith(('.so', '.o', '.a', '.bc')) for n in source)
        sources[name] = source
    assert set(sources) == {'parent', 'control', 'proposal'}
    source_changes(sources)
    locked = document(HERE / 'builds/locked-archives.json.gz')
    packages = tomllib.loads(sources['proposal']['Cargo.lock'].decode())['package']
    assert locked['count'] == 257
    assert locked['sha256'] == {f"{p['name']}-{p['version']}.crate": p['checksum'] for p in packages if p.get('source', '').startswith('registry+')}
    images = {}
    for name, spec in evidence['builds'].items():
        launch, result = document(HERE / spec['launch']), document(HERE / spec['result'])
        log = gzip.decompress((HERE / spec['log']).read_bytes())
        assert result['exit_code'] == 0 and result['compiled_root'] and result['source_unchanged']
        assert digest(log) == result['log_sha256'] and log.count(b'--crate-name pump_amm_recovered ') == 1
        source_name = 'proposal' if name == 'repeat' else name
        inputs = evidence['archives'][source_name]['inputs']
        assert launch['inputs'] == result['source_sha256'] == result['source_after_sha256'] == inputs
        assert launch['tool_sha256'] == {'rust/bin/rustc': RUSTC, 'rust/bin/cargo': CARGO}
        command = launch['command']
        assert '--network' in command and command[command.index('--network') + 1] == 'none'
        assert '--locked' in command and '--offline' in command and 'sbpf-solana-solana' in command
        assert not any('evidence/original/' in x for x in command)
        assert result['strip_sha256'] == STRIP and result['strip_command'][1] == '--strip-all'
        images[name] = {kind: gzip.decompress((HERE / spec[kind]).read_bytes()) for kind in ('candidate', 'symbols')}
        for kind, data in images[name].items():
            assert digest(data) == result[kind + '_sha256'] and len(data) == result[kind + '_bytes']
    assert digest(images['parent']['candidate']) == '4e58c47139798d743c325c8ee9c3a98f4fd7cc4ceba2d6a5763e66899c4efd25'
    assert digest(images['parent']['symbols']) == '5d7209406468232971e9df2ac5c749457da0b4cfe5cbfb9dc331346ac0541763'
    analysis = module('deposit_analysis', HERE / 'analysis.py')
    comparison = analysis.recompute(images=images)
    assert comparison == document(HERE / 'comparison.json')
    result = runtime(evidence, images)
    print('PASS: 7128-byte normalized deposit; 726 -> 727, no lost matches; 53/55 immediate callees; ' +
          f"{result['cases']} suite cases, {result['focused_triples']} signed triples")


if __name__ == '__main__':
    main()
