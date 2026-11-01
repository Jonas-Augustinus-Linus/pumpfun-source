"""Authenticate saved boundary replays without executing the compiler or VM."""
from pathlib import Path, PurePosixPath
import argparse, base64, gzip, hashlib, importlib.util, json, sys
if not __debug__:
    raise RuntimeError('Assertions required; Python -O is unsupported')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT = ROOT / 'repro/pump_amm/source-abi-recovery-20261027/followup/resize-order'
ORIGINAL = '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
OLD = 'e995d6a8211dcd3d05c07cdcb1a7147ec4f4e2b2a81b56c268fd1a3d76a01ce1'
CURRENT = '3fcae02128464717b29a0b3842fbba993d5d0befb4362c4094c8af8e32a8589d'
LATEST = 'be10ca1a530ef9c62be5c94a5183f339e5d7661dce588a9458767e20a5e488f6'
BAD = [6, 7, 12, 13, 24, 25, 30, 31, 60, 61, 66, 67, 78, 79, 84, 85]
from solders.transaction import Transaction
from solders.rent import Rent


def digest(b):
    return hashlib.sha256(b).hexdigest()


def sha(p):
    return digest(p.read_bytes())


def load(p):
    b = p.read_bytes()
    return json.loads(gzip.decompress(b) if p.suffix == '.gz' else b)


def module(name, p):
    spec = importlib.util.spec_from_file_location(name, p)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def suite(packet, label, matrix, candidate, bad, reports=None):
    public = module('public_resize', PARENT / 'verify.py')
    clean = module('boundary_clean', packet / 'cleaner.py').clean
    roster = module('boundary_probe', packet / 'probe.py').cases(matrix)
    reports = Path(reports) if reports is not None else packet / 'results'
    r = load(reports / label / 'report.json.gz')
    observed = load(reports / label / 'transactions.json.gz')
    command = load(reports / label / 'command.json')
    count = 858 if matrix == 'lengths' else 108
    assert len(roster) == count == r['case_count'] == len(r['cases'])
    assert len({json.dumps(c, sort_keys=True) for c in roster}) == count
    assert r['matrix'] == matrix and r['solders'] == '0.27.1'
    assert r['candidate_sha256'] == candidate and r['original_sha256'] == ORIGINAL
    assert r['producer_sha256'] == observed['script_sha256'] == sha(packet / 'probe.py')
    assert r['core_sha256'] == sha(packet / 'producer.py')
    assert observed['observer_sha256'] == sha(packet / 'observer.py')
    assert command['exit_code'] == 0 and command['argv'][1] == '-B'
    assert command['argv'][command['argv'].index('--matrix') + 1] == matrix
    assert r['runtime_reads_before'] == r['runtime_reads_after'] == load(packet / 'runtime-inputs.json')[label]
    for rel, h in r['runtime_reads_before'].items():
        assert sha(ROOT / rel) == h, ('runtime source', rel)
    assert len(observed['transactions']) == observed['transaction_count'] == count * 2
    failures = []
    signatures = successes = 0
    calls = {'original': 0, 'candidate': 0}
    families = {}
    states = set()
    for i, row in enumerate(r['cases']):
        c = row['case']
        assert c == roster[i], ('case roster', label, i)
        a, b = row['original'], row['candidate']
        fields = {'error', 'logs', 'events', 'inner', 'return_data', 'before', 'after',
            'transaction_base64', 'pool_key', 'payer_key', 'direct_amm_system_calls', 'amm_invocations'}
        assert set(a) == set(b) == fields
        assert a['before'] == b['before'] and a['transaction_base64'] == b['transaction_base64']
        # Different fixture states may share a signed message; include both in the identity.
        states.add(digest(json.dumps([a['before'], a['transaction_base64']], sort_keys=True).encode()))
        aa, bb = clean(a), clean(b)
        diff = sorted(k for k in aa if aa[k] != bb[k])
        assert diff == row['mismatched_fields']
        if diff:
            failures.append(i)
            assert candidate == OLD and c['family'].startswith('sweep')
            assert a['direct_amm_system_calls'] == 1 and b['direct_amm_system_calls'] == 0
        successes += a['error'] is None
        families[c['family']] = families.get(c['family'], 0) + 1
        for j, side in enumerate(['original', 'candidate']):
            q = row[side]
            t = observed['transactions'][2*i + j]
            assert t['sequence'] == 2*i + j
            raw = base64.b64decode(t['transaction_base64'], validate=True)
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and t['all_signatures_verified'] is True
            assert len(checks) == t['signature_count'] == (2 if c['family'] == 'admin_cto' else 1)
            signatures += len(checks)
            assert digest(raw) == t['transaction_sha256']
            assert t['transaction_base64'] == q['transaction_base64']
            wanted = ORIGINAL if side == 'original' else candidate
            assert t['amm_program_sha256'] == t['loaded_programs'][public.AMM]['sha256'] == wanted
            for pid, record in t['loaded_programs'].items():
                assert pid in public.BINS
                assert record['sha256'] == (wanted if pid == public.AMM else public.BINS[pid][1])
                assert observed['program_file_sha256'][record['path']] == record
            assert t['error'] == q['error']
            assert t['logs_sha256'] == digest(json.dumps(q['logs'], separators=(',', ':')).encode())
            assert public.counts(q['logs']) == (q['direct_amm_system_calls'], q['amm_invocations'])
            assert q['events'] == [line for line in q['logs'] if line.startswith('Program data:')]
            calls[side] += q['direct_amm_system_calls']
            keys = set(map(str, tx.message.account_keys))
            assert set(q['before']) == set(q['after']) and not set(q['before']) - keys
            assert keys - set(q['before']) <= set(t['loaded_programs']) | {public.SYSTEM, public.CU}
            assert q['pool_key'] in keys and q['payer_key'] == str(tx.message.account_keys[0])
            pool = q['before'][q['pool_key']]
            assert pool['owner'] == public.AMM
            assert len(bytes.fromhex(pool['data_hex'])) == c['pool_length'], ('actual pool length', label, i)
            assert pool['lamports'] == c['pool_lamports']
            assert q['before'][q['payer_key']]['lamports'] == c['payer_lamports']
            if q['error']:
                assert pool == q['after'][q['pool_key']], ('failure rollback', label, i)
            for state in ['before', 'after']:
                for account in q[state].values():
                    assert account is None or set(account) == {'data_hex', 'owner', 'lamports'}
            if c['family'] == 'admin_cto':
                assert len(tx.message.instructions) == 2
                first = tx.message.instructions[0]
                assert str(tx.message.account_keys[first.program_id_index]) == public.CU
                assert bytes(first.data) == bytes.fromhex('02c05c1500')
            else:
                assert len(tx.message.instructions) == 1
    assert failures == bad and r['mismatch_count'] == len(bad)
    assert signatures == observed['signature_count']
    assert len(families) == (11 if matrix == 'lengths' else 2)
    assert len(states) == count, ('distinct input states', label, len(states))
    if matrix == 'rent':
        assert successes == 20 and calls == {'original': 24, 'candidate': 8 if candidate == OLD else 24}
    return dict(cases=count, mismatches=len(bad), mismatch_indices=failures,
        verified_signatures=signatures, original_successes=successes,
        direct_amm_system_cpis=calls, distinct_message_state_pairs=len(states), families=families)


def verify(packet=HERE, reports=None):
    packet = Path(packet).resolve()
    paths = list(packet.rglob('*'))
    manifest = load(packet / 'manifest.json')
    assert not any(p.is_symlink() for p in paths)
    assert all(p.is_file() or p.is_dir() for p in paths)
    assert {p.relative_to(packet).as_posix() for p in paths if p.is_file()} == set(manifest) | {'manifest.json'}, 'packet inventory'
    for rel, h in manifest.items():
        p = PurePosixPath(rel)
        assert not p.is_absolute() and '..' not in p.parts and str(p) == rel
        assert sha(packet / rel) == h, ('packet hash', rel)
    for rel, h in load(packet / 'repository-references.json').items():
        assert sha(ROOT / rel) == h, ('repository reference', rel)
    assert sha(ROOT / 'evidence/original/pump_amm/deployed.so') == ORIGINAL
    assert sha(ROOT / 'repro/pump_amm/source-abi-recovery-20261027/results/build/candidate.so') == OLD
    assert sha(ROOT / 'repro/pump_amm/transfer-abi-recovery-20261027/results/build/candidate.so') == CURRENT
    assert sha(ROOT / 'repro/pump_amm/quote-guard-recovery-20261027/results/build/candidate.so') == LATEST
    assert (packet / 'observer.py').read_bytes() == (PARENT / 'observer.py').read_bytes()
    assert (packet / 'cleaner.py').read_bytes() == (ROOT / 'repro/pump_amm/diagnostic-parity-20261027/compare_direct.py').read_bytes()
    source = (PARENT / 'expanded160/producer.py').read_bytes()
    old = b"  if c.get('pool_length')is not None:del data[c['pool_length']:]"
    new = b"  if c.get('pool_length')is not None:\n   size=c['pool_length'];data[:]=data[:size]+bytes(max(0,size-len(data)))"
    assert source.count(old) == 1
    assert (packet / 'producer.py').read_bytes() == source.replace(old, new)
    assert Rent.default().minimum_balance(287) == 2888400
    result = {}
    for label, matrix, candidate, bad in [('old640-rent', 'rent', OLD, BAD),
            ('selected642-rent', 'rent', CURRENT, []), ('selected642-lengths', 'lengths', CURRENT, []),
            ('selected643-rent', 'rent', LATEST, []), ('selected643-lengths', 'lengths', LATEST, [])]:
        result[label] = suite(packet, label, matrix, candidate, bad, reports)
    assert result == load(packet / 'summary.json')
    return dict(verified=True, suites=result, new_source_recovery=False,
        executes_compiler_or_runtime=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packet', type=Path, default=HERE)
    p.add_argument('--reports', type=Path, help='Check fresh replay.py output against the sealed packet')
    a = p.parse_args()
    print(json.dumps(verify(a.packet, a.reports), indent=2))
