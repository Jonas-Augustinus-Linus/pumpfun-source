"""Audit the source recovery and its frozen local execution evidence."""
from pathlib import Path
import difflib, gzip, hashlib, json, runpy, tarfile
if not __debug__:
    raise SystemExit('Run without -O')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sha = lambda b: hashlib.sha256(b).hexdigest()
def read(name):
    raw = (HERE / name).read_bytes()
    return gzip.decompress(raw) if name.endswith('.gz') else raw
def record(name):
    return json.loads(read(name))

paths = list(HERE.rglob('*'))
assert not any(p.is_symlink() for p in paths), 'packet symlink'
assert all(p.is_file() or p.is_dir() for p in paths), 'packet special file'
manifest = record('MANIFEST.json')
assert set(manifest['files']) == {p.relative_to(HERE).as_posix() for p in paths if p.is_file() and p != HERE / 'MANIFEST.json'}, 'packet file inventory'
for name, digest in manifest['files'].items():
    assert sha((HERE / name).read_bytes()) == digest, name
for name, digest in manifest['repository_inputs'].items():
    assert sha((ROOT / name).read_bytes()) == digest, name
with tarfile.open(HERE / 'rejected.tar.gz') as archive:
    members = archive.getmembers()
    assert all(m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in members)
    assert len({m.name for m in members}) == len(members)
    assert {m.name: sha(archive.extractfile(m).read()) for m in members} == record('rejected-index.json')
materialize = runpy.run_path(str(HERE / 'materialize.py'))
sources = {k: materialize['source_files'](k) for k in ['baseline', 'candidate']}
before, after = sources.values()
source = 'programs/pump-amm/src/curve/fees.rs'
assert len(before) == len(after) == 54 and before.keys() == after.keys()
assert [n for n in before if before[n] != after[n]] == [source]
assert before[source].split(b'pub fn select_and_apply_v2(')[0] == after[source].split(b'fn select_v2_fees(')[0]
assert after[source].splitlines()[183].strip() == b'require!(fee_config_len >= 2512, PumpAmmError::FeeConfigTooShort);'
assert b'#[inline' not in after[source]
assert after[source] == read('proposed/fees.rs')
assert ''.join(difflib.unified_diff(before[source].decode().splitlines(True), after[source].decode().splitlines(True), fromfile='a/' + source, tofile='b/' + source)).encode() == read('source.patch')
hashes, launches = {}, {}
for label in ['baseline', 'candidate', 'repeat']:
    launch, result = record('builds/' + label + '/launch.json'), record('builds/' + label + '/result.json')
    launches[label] = launch
    assert launch['inputs'] == {n: sha(v) for n, v in sources['candidate' if label == 'repeat' else label].items()}
    assert result['returncode'] == 0 and result['source_unchanged'] and result['dependencies_unchanged'] and result['actual_root_invocations'] == 1
    assert sum(l.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in l for l in read('builds/' + label + '/build.log.gz').decode().splitlines()) == 1
    cmd = launch['command']
    assert cmd[cmd.index('--network') + 1] == 'none' and '--locked' in cmd and '--offline' in cmd
    hashes[label] = {kind: sha(read('builds/' + label + '/' + kind + '.so.gz')) for kind in ['symbols', 'candidate']}
    assert all(result[kind + '_sha256'] == value for kind, value in hashes[label].items())
assert hashes['candidate'] == hashes['repeat']
assert hashes['baseline']['candidate'] == '988946f1170a92b68448bc21a251deba7c47698efeb5a4386b15c800c7c8cbd3'
assert hashes['candidate']['candidate'] == '7ab5045aa72dcf20bb98d4f13058e80809d6599c6c4163f5bb6643257a16b3b7'
assert all(launches[k]['dependencies_before'] == launches['baseline']['dependencies_before'] and launches[k]['tools'] == launches['baseline']['tools'] for k in ['candidate', 'repeat'])
assert len(launches['baseline']['dependencies_before']) == 396
for label in ['baseline', 'candidate']:
    result = record('compiler/' + label + '/result.json')
    assert result['returncode'] == 0 and result['dependencies_unchanged'] and result['normal_stripped_equal']
    assert result['candidate_sha256'] == hashes[label]['candidate'] == sha(read('compiler/' + label + '/candidate.so.gz'))
    assert result['symbols_sha256'] == sha(read('compiler/' + label + '/pump_amm_recovered.so.gz'))
controls = record('compiler/codegen-route-order/results.json')
assert controls[0]['normal_equal'] and controls[0]['positional_differences'] == 46
assert controls[1]['label'] == 'normal-after-exotic-flat' and controls[1]['positional_differences'] == 16
assert not any(c['equals_original_masking_call_and_data'] for c in controls)
runpy.run_path(str(HERE / 'analyze.py'), run_name='__main__')
runpy.run_path(str(HERE / 'audit_runtime.py'), run_name='__main__')
print('PASS: inventory,54source inputs,396dependencies,identical normal repeat,compiler qualification and signed replay')
