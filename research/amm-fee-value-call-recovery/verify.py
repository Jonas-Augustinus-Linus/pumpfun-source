"""Audit frozen source, normal builds, complete body/callees and signed local receipts.

This does not rerun compilation or program execution. See README for replay.
"""
from collections import Counter
import base64, difflib, gzip, hashlib, json, re, runpy, tarfile, tomllib
from pathlib import Path
from solders.transaction import Transaction
if not __debug__:
    raise SystemExit('Verification requires Python without -O')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
def sha(data): return hashlib.sha256(data).hexdigest()
def read(name):
    data = (HERE / name).read_bytes()
    return gzip.decompress(data) if name.endswith('.gz') else data
def record(name): return json.loads(read(name))
def verify_inventory(root, entries):
    paths = list(root.rglob('*'))
    assert not any(p.is_symlink() for p in paths), 'packet symlink'
    assert all(p.is_file() or p.is_dir() for p in paths), 'packet special file'
    assert set(entries) == {p.relative_to(root).as_posix() for p in paths
                            if p.is_file() and p != root / 'MANIFEST.json'}, 'packet inventory differs'
manifest = record('MANIFEST.json')
verify_inventory(HERE, manifest['files'])
for name, digest in manifest['files'].items(): assert sha((HERE / name).read_bytes()) == digest, name
for name, digest in manifest['repository_inputs'].items(): assert sha((ROOT / name).read_bytes()) == digest, name
assert all(manifest['repository_inputs'][name] == digest for name, digest in record('runtime/inputs.json').items())
materialize = runpy.run_path(str(HERE / 'materialize.py'))
sources = {k:materialize['source_files'](k) for k in ('baseline','candidate')}
before, after = sources.values()
source='programs/pump-amm/src/utils/transfer_fee.rs'
assert set(before)==set(after) and len(before)==54
assert [n for n in before if before[n]!=after[n]]==[source]
needle=b'pub fn calculate_fee(data: &TransferFeeData, amount: u64) -> Result<u64> {\n    match data {'
assert before[source].count(needle)==1
assert after[source]==before[source].replace(needle,needle.replace(b'match data',b'match *data'))
assert after[source]==read('proposed/transfer_fee.rs')
patch=''.join(difflib.unified_diff(before[source].decode().splitlines(True),after[source].decode().splitlines(True),fromfile='a/'+source,tofile='b/'+source))
assert patch.encode()==read('source.patch')
with tarfile.open(ROOT/'research/amm-native-transfer-fee-recovery/sources/candidate.tar.gz','r:gz') as tf:
    parent={m.name:tf.extractfile(m).read() for m in tf.getmembers()}
assert parent==before
assert before['Cargo.toml']==after['Cargo.toml'] and before['Cargo.lock']==after['Cargo.lock']
builds, images = {}, {}
for label in ('baseline','candidate','repeat'):
    launch = record('builds/'+label+'/launch.json'); result = record('builds/'+label+'/result.json')
    src = sources['candidate' if label=='repeat' else label]
    assert launch['inputs'] == {n:sha(b) for n,b in src.items()}
    assert result['returncode']==0 and result['source_unchanged'] and result['dependencies_unchanged']
    assert result['actual_root_invocations']==1
    log = read('builds/'+label+'/build.log.gz').decode()
    assert sum(l.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in l for l in log.splitlines()) == 1
    if label == 'repeat':
        assert sum(l.strip().startswith('Running `') and '--crate-name native_transfer_fee ' in l for l in log.splitlines()) == 1
    cmd = launch['command']
    assert cmd[cmd.index('--network')+1]=='none' and '--offline' in cmd and '--locked' in cmd
    assert not any('evidence/original' in part for part in cmd)
    images[label] = {kind:read('builds/'+label+'/'+kind+'.so.gz') for kind in ('symbols','candidate')}
    for kind,data in images[label].items(): assert sha(data)==result[kind+'_sha256']
    builds[label]=launch
for label in ('candidate','repeat'):
    assert builds[label]['tools']==builds['baseline']['tools']
    assert all(builds[label]['dependencies_before'][n]==v for n,v in builds['baseline']['dependencies_before'].items())
assert builds['candidate']['dependencies_before']==builds['repeat']['dependencies_before']==builds['baseline']['dependencies_before']
assert len(builds['baseline']['dependencies_before'])==396
assert images['candidate']==images['repeat']
assert sha(images['baseline']['candidate'])=='351d0d9adb40497790cd46fa992776cdeefa758041a1e50a6a29355525b4e471'
assert sha(images['candidate']['candidate'])=='f7c4850c6529bf40ffc490753b0a3470aed9b5d630023c8a7df5bd3992c6dee6'
static=runpy.run_path(str(HERE/'analyze.py'))
w=static['w']; original=static['blobs']['original']; originals=w.windows(original)
assert len(originals)==785 and sha(original)=='6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
matched={}
for label in ('baseline','candidate'):
    fs=w.windows(images[label]['symbols'])
    matched[label]=[Counter(f[k] for f in originals)&Counter(f[k] for f in fs) for k in ('signature','raw_sha256')]
assert [sum(c.values()) for c in matched['baseline']]==[732,148]
assert [sum(c.values()) for c in matched['candidate']]==[733,148]
body=static['out']['original']
assert body['address']==0x74648 and body['bytes']==696 and body['instructions']==80
assert matched['candidate'][0]-matched['baseline'][0]=={body['signature']:1}
assert not matched['baseline'][0]-matched['candidate'][0]
assert matched['baseline'][1]==matched['candidate'][1]
assert len(static['out']['direct_calls'])==5 and len(static['out']['typed_references'])==7
assert static['out']['direct_calls'][0]['original']['address']==0xf2d60
assert [len(v) for v in static['out']['incoming'].values()]==[1,2,2]
assert static['out']['source_records']==[dict(offset=552,filename=source,line=49,error=6023)]
for label,key in [('parent','baseline'),('value','candidate')]:
    result=record('compiler/'+label+'/result.json')
    assert result['returncode']==0 and result['normal_stripped_equal'] and result['dependencies_unchanged']
    assert result['candidate_sha256']==sha(images[key]['candidate'])
assert b'%fee = alloca [24 x i8]' not in read('compiler/parent/function.ll')
assert b'%fee = alloca [24 x i8]' in read('compiler/value/function.ll')
assert b'@llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(24) %fee' in read('compiler/value/function.ll')
assert b'_4 = (((*_1) as Some).0: native_transfer_fee::DecodedTransferFee);' in read('compiler/value/function.mir')
hashes=dict(original=sha(original),**{k:sha(images[k]['candidate']) for k in ('baseline','candidate')})
norm=lambda logs:[s for s in logs if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units',s)]
def audit(scope, triples, observed, expected_count, log_counts):
    assert observed['transaction_count'] == observed['signature_count'] == expected_count*3
    expected = Counter(); actual = Counter(); mismatches = Counter(); gains=losses=count=0
    for tx in observed['transactions']:
        assert tx['all_signatures_verified']
        signed = Transaction.from_bytes(base64.b64decode(tx['transaction_base64']))
        assert all(signed.verify_with_results())
        actual[(tx['amm_program_sha256'],tx['transaction_base64'],tx['logs_sha256'])] += 1
        for program in tx['loaded_programs'].values():
            if '/evidence/' in program['path']:
                name = 'evidence/' + program['path'].split('/evidence/',1)[1]
                assert manifest['repository_inputs'][name] == program['sha256']
    for triple in triples:
        o=triple['original']; count+=1
        for label,result in triple.items():
            assert {k:v for k,v in o.items() if k!='logs'} == {k:v for k,v in result.items() if k!='logs'}, (scope,count,label)
            expected[(hashes[label],result['transaction_base64'],sha(json.dumps(result['logs'],separators=(',',':')).encode()))] += 1
            mismatches[label] += norm(o['logs']) != norm(result['logs'])
        x,y=(norm(o['logs']) == norm(triple[k]['logs']) for k in ['baseline','candidate'])
        gains += not x and y; losses += x and not y
    assert count == expected_count and expected == actual and losses == 0
    assert (mismatches['baseline'],mismatches['candidate']) == log_counts
    assert gains == log_counts[0]-log_counts[1]
    print(scope,count,'case triples, non-compute log mismatches',log_counts)

for family,count,counts in [('liquidity',680,(0,0)),('buy',1011,(76,76)),('sell',575,(88,88))]:
    summary=record('runtime/'+family+'/summary.json')
    assert summary['artifact_sha256']==hashes and not any(summary['functional_mismatches'].values())
    assert summary['fresh_vm'] is False
    observed=record('runtime/'+family+'/observed.json.gz')
    assert observed['script_sha256']==sha(read('controllers/value_runtime.py'))
    with gzip.open(HERE/'runtime'/family/'triples.jsonl.gz','rt') as f:
        audit(family,(json.loads(line)['results'] for line in f),observed,count,counts)
focus=runpy.run_path(str(HERE/'focused_check.py'))
focus['verify'](hashes)
error_path=runpy.run_path(str(HERE/'error_path_check.py'))
error_path['verify'](hashes)
print('PASS:732 ->733/785 normalized;148raw retained;696B complete caller,5 actual direct callees,7 typed references;2266 cached+216 fresh+7 error-path triples.')
