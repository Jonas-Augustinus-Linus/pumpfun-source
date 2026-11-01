"""Verify the Metaplex Token Metadata whole-artifact reconstruction without compiling or running a VM.

Run from the repository root:
    work/test-env/bin/python -B research/claude-deps-metaplex-20261027/verify.py
(solders is needed only for the transaction-signature checks of the runtime outputs).
"""
from pathlib import Path
import base64, gzip, hashlib, json, sys, tarfile

if not __debug__:
    raise RuntimeError('verification requires assertions; do not use Python -O')
sys.dont_write_bytecode = True

p = Path(__file__).resolve().parent
root = p.parents[1]
h = lambda b: hashlib.sha256(b).hexdigest()

# 1. packet manifest
manifest = json.loads((p / 'manifest.json').read_text())
paths = list(p.rglob('*'))
assert not any(f.is_symlink() for f in paths), 'packet includes a symlink'
assert all(f.is_file() or f.is_dir() for f in paths), 'packet includes a special file'
assert {f.relative_to(p).as_posix() for f in paths if f.is_file() and f != p / 'manifest.json'} == set(manifest), 'packet file inventory differs'
for name, digest in manifest.items():
    assert h((p / name).read_bytes()) == digest, name

# 2. sources: snapshot == recorded patched hashes; utilize.rs copy; frontier-only difference
inputs = json.loads((p / 'patch-source-inputs.json').read_text())
assert inputs['upstream_commit'] == '17e99434af5ead3e989c08f32af33609821d0bc0' and len(inputs['patched']) == 18
with tarfile.open(p / 'source-snapshot.tar.gz') as tf:
    snap = {m.name: tf.extractfile(m).read() for m in tf if m.isfile()}
assert {n: h(b) for n, b in snap.items()} == inputs['patched']
REL = 'programs/token-metadata/program/src/processor/uses/utilize.rs'
assert snap[REL] == (p / 'source/utilize.rs').read_bytes()
frontier = json.loads((root / 'repro/pump/metaplex-owned-uses-20261026/patch-source-inputs.json').read_text())['patched']
assert [n for n in inputs['patched'] if inputs['patched'][n] != frontier[n]] == [REL]
full = json.loads((p / 'source-manifest.json').read_text())
front_full = json.loads((root / 'repro/pump/metaplex-owned-uses-20261026/source-manifest.json').read_text())
assert len(full) == 812 and [n for n in full if full[n] != front_full[n]] == [REL] and full[REL] == h(snap[REL])

# 3. artifact identity: raw prefix, zero tail, padded allocation image
orig_path = root / 'evidence/dependencies/token_metadata/deployed.so'
o = orig_path.read_bytes()
c = (p / 'candidate.so').read_bytes()
assert h(o) == '31f0a627dba051a938de650464e55cc5397a4be0fd496929c1f9cf02fe5e9011'
assert h(c) == '99ee61a5159e15a359b01298b52c9f9f912eb19e47bdfe83987c16de52a4b1ff' and len(c) == 707448
assert o[:len(c)] == c, 'raw ELF is not the captured prefix'
assert len(o) - len(c) == 86543 and not any(o[len(c):]), 'captured tail is not zero-only'
img = (p / 'allocation-image.so').read_bytes()
assert img == c + bytes(86543) and img == o

# 4. every inferred function window (repository reader)
sys.path.insert(0, str(root / 'repro/pump_fees/framework-matching'))
from elf_reader import Elf  # noqa: E402
eo, ec = Elf(orig_path), Elf(p / 'candidate.so')
assert eo.entries == ec.entries and len(eo.entries) == 1251
bounds = list(zip(eo.entries, eo.entries[1:] + [eo.hi]))
assert all(eo.b[a:z] == ec.b[a:z] for a, z in bounds)
assert sorted(eo.relocations.items()) == sorted(ec.relocations.items())

# 5. two independent builds of the same source produced the same bytes
builds = [json.loads((p / d / 'result.json').read_text()) for d in ['build-1', 'build-2']]
assert all(b['returncode'] == 0 and b['all_planned_source_hashes_unchanged_after_build'] for b in builds)
assert {b['candidate_sha256'] for b in builds} == {h(c)}
assert len({b['compiler_output_sha256'] for b in builds}) == 1
assert {b['build_tree'] for b in builds} == {'1', '2'}
for d in ['build-1', 'build-2']:
    m = json.loads((p / d / 'source-manifest.json').read_text())
    assert m == full
cmp_ = json.loads((p / 'build-1/comparison.json').read_text())
assert cmp_['whole_file_equal'] and cmp_['differing_payload_positions'] == 0 and cmp_['raw_equal_windows'] == 1251

# 6. runtime differential outputs (original vs candidate)
try:
    from solders.transaction import VersionedTransaction
except ImportError:
    raise RuntimeError('solders is required to verify retained transaction signatures')
cases = transactions = 0
for name in ['edition', 'uses', 'burn', 'context', 'validation']:
    data = json.loads(gzip.decompress((p / (name + '-validation.json.gz')).read_bytes()))
    assert data['candidate_sha256'] == h(c) and not data['mismatches'] and data['case_count'] == len(data['cases'])
    for row in data['cases']:
        left, right = row['original'], row['candidate']
        key = 'inner_instructions' if 'inner_instructions' in left else 'inner'
        assert left['error'] == right['error'] and left['after'] == right['after'] and left[key] == right[key]
        for result in [left, right]:
            if VersionedTransaction:
                assert all(VersionedTransaction.from_bytes(base64.b64decode(result['transaction_base64'])).verify_with_results())
            transactions += 1
        cases += 1
data = json.loads(gzip.decompress((p / 'utilize-validation.json.gz').read_bytes()))
assert data['binary_sha256']['candidate'] == h(c) and data['binary_sha256']['original'] == h(o)
for row in data['cases']:
    left, right = row['results']['original'], row['results']['candidate']
    assert all(left[k] == right[k] for k in ['error', 'after', 'inner']) and not row['mismatches']
    assert (left['error'] is None) == row['case']['success']
    for result in [left, right]:
        if VersionedTransaction:
            assert all(VersionedTransaction.from_bytes(base64.b64decode(result['transaction_base64'])).verify_with_results())
        transactions += 1
    cases += 1
assert cases == 147 and transactions == 294
print(json.dumps({'raw_equal_function_windows': 1251, 'total_windows': 1251, 'raw_elf_sha256': h(c),
                  'allocation_image_sha256': h(img), 'whole_allocation_equal': True, 'zero_padding_bytes': 86543,
                  'runtime_cases': cases, 'verified_transactions': transactions,
                  'signatures_checked': VersionedTransaction is not None}, indent=2))
