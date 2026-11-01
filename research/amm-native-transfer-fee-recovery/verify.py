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
assert set(before) < set(after)
assert set(after)-set(before) == {'crates/native-transfer-fee/Cargo.toml','crates/native-transfer-fee/src/lib.rs'}
changed = sorted(n for n in after if before.get(n) != after[n])
assert changed == record('source-changes.json')
assert set(changed) == {'Cargo.toml','Cargo.lock','programs/pump-amm/Cargo.toml','programs/pump-amm/src/utils/transfer_fee.rs','crates/native-transfer-fee/Cargo.toml','crates/native-transfer-fee/src/lib.rs'}
patch = ''
for n in changed:
    assert after[n] == read('proposed/'+n)
    patch += ''.join(difflib.unified_diff(before.get(n,b'').decode().splitlines(True),after[n].decode().splitlines(True),fromfile='a/'+n if n in before else '/dev/null',tofile='b/'+n))
assert patch.encode() == read('source.patch')
with tarfile.open(ROOT/'research/amm-prepare-pool-recovery/sources/candidate.tar.gz','r:gz') as tf:
    parent = {m.name:tf.extractfile(m).read() for m in tf.getmembers()}
parent['programs/pump-amm/src/utils/transfer_fee.rs'] = (ROOT/'research/amm-mint-fee-reader-recovery/proposed/transfer_fee.rs').read_bytes()
assert parent == before, 'Measured base is prepare proposal + PR395 reader; NOT deposit composition'
packages = {k:tomllib.loads(v['Cargo.lock'].decode())['package'] for k,v in sources.items()}
assert [p for p in packages['baseline'] if p['name']!='pump-amm-recovered'] == [p for p in packages['candidate'] if p['name'] not in ('pump-amm-recovered','native-transfer-fee')]
for src in sources.values():
    assert tomllib.loads(src['Cargo.toml'].decode())['profile']['release'] == {'panic':'abort','lto':False,'codegen-units':1,'overflow-checks':True}
builds, images = {}, {}
for label in ('baseline','candidate','repeat'):
    launch = record('builds/'+label+'/launch.json'); result = record('builds/'+label+'/result.json')
    src = sources['candidate' if label=='repeat' else label]
    assert launch['inputs'] == {n:sha(b) for n,b in src.items()}
    assert result['returncode']==0 and result['source_unchanged'] and result['dependencies_unchanged']
    assert result['actual_root_invocations']==1
    log = read('builds/'+label+'/build.log.gz').decode()
    assert sum(l.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in l for l in log.splitlines()) == 1
    if label != 'baseline':
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
assert builds['candidate']['dependencies_before']==builds['baseline']['dependencies_before']
extra=set(builds['repeat']['dependencies_before'])-set(builds['baseline']['dependencies_before'])
assert len(extra)==3 and all('native_transfer_fee' in n for n in extra)
assert images['candidate']==images['repeat']
cli=record('builds/cli/hashes.json')
assert all(cli[k+'_sha256']==sha(images['candidate'][k]) for k in ('symbols','candidate'))
cli_log=read('builds/cli/build.log.gz').decode()
for crate in ('pump_amm_recovered','native_transfer_fee'):
    assert sum(l.strip().startswith('Running `') and '--crate-name '+crate+' ' in l for l in cli_log.splitlines())==1

assert sha(images['baseline']['candidate'])=='2c3618ad9cc351fa5f35c502fa9e7e3b2541fbdcca6bb467bf5b0a3f50135267'
assert sha(images['candidate']['candidate'])=='351d0d9adb40497790cd46fa992776cdeefa758041a1e50a6a29355525b4e471'
static=runpy.run_path(str(HERE/'analyze.py'))
w=static['w']; original=static['blobs']['original']; originals=w.windows(original)
assert len(originals)==785 and sha(original)=='6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
matched={}
for label in ('baseline','candidate'):
    fs=w.windows(images[label]['symbols'])
    matched[label]=[Counter(f[k] for f in originals)&Counter(f[k] for f in fs) for k in ('signature','raw_sha256')]
assert [sum(c.values()) for c in matched['baseline']]==[731,148]
assert [sum(c.values()) for c in matched['candidate']]==[732,148]
body=static['out']['original']
assert body['address']==0xf2d60 and body['bytes']==368 and body['instructions']==46
assert matched['candidate'][0]-matched['baseline'][0]=={body['signature']:1}
assert not matched['baseline'][0]-matched['candidate'][0]
assert matched['baseline'][1]==matched['candidate'][1]
assert len(static['out']['direct_calls'])==2
for call in static['out']['direct_calls']:
    assert call['original']['raw_sha256']==call['candidate']['raw_sha256']
assert not static['out']['typed_references'] and not static['out']['imports'] and not static['out']['literal_constants']
assert all(len(edges)==1 for edges in static['out']['incoming'].values())
assert static['out']['incoming']['original'][0]['caller']['address']==0x74648
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
    assert observed['script_sha256']==sha(read('controllers/fee_runtime.py'))
    with gzip.open(HERE/'runtime'/family/'triples.jsonl.gz','rt') as f:
        audit(family,(json.loads(line)['results'] for line in f),observed,count,counts)
focus=runpy.run_path(str(HERE/'focused_check.py'))
focus['verify'](hashes)
print('PASS: 731 -> 732/785 normalized; all148 raw retained; complete368B fee method and2 raw-identical direct callees;2266 cached+216 fresh case triples.')
