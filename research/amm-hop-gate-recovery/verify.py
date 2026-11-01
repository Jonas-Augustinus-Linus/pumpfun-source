"""Read-only audit of source, normal builds, compiler controls and signed replay."""
from pathlib import Path
import difflib,gzip,hashlib,json,runpy,tarfile
if not __debug__:raise SystemExit('Run without -O')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(name):
 b=(HERE/name).read_bytes();return gzip.decompress(b) if name.endswith('.gz') else b
def record(name):return json.loads(read(name))
paths=list(HERE.rglob('*'))
assert not any(p.is_symlink() for p in paths), 'packet symlink'
assert all(p.is_file() or p.is_dir() for p in paths), 'packet special file'
manifest=record('MANIFEST.json')
assert set(manifest['files'])=={p.relative_to(HERE).as_posix() for p in paths if p.is_file() and p!=HERE/'MANIFEST.json'}, 'packet file inventory'
for n,h in manifest['files'].items():assert sha((HERE/n).read_bytes())==h,n
for n,h in manifest['repository_inputs'].items():assert sha((ROOT/n).read_bytes())==h,n
with tarfile.open(HERE/'rejected.tar.gz') as archive:
 members=archive.getmembers();assert all(m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in members)
 assert len({m.name for m in members})==len(members)
 assert {m.name:sha(archive.extractfile(m).read()) for m in members}==record('rejected-index.json')
materialize=runpy.run_path(str(HERE/'materialize.py'));sources={k:materialize['source_files'](k) for k in ['baseline','candidate']};before,after=sources.values();source='programs/pump-amm/src/instructions/swap/multi_hop_swap.rs'
assert len(before)==len(after)==54 and before.keys()==after.keys()
assert [n for n in before if before[n]!=after[n]]==[source]
assert before[source].count(b'\n')==after[source].count(b'\n')
assert after[source]==read('proposed/multi_hop_swap.rs')
assert ''.join(difflib.unified_diff(before[source].decode().splitlines(True),after[source].decode().splitlines(True),fromfile='a/'+source,tofile='b/'+source)).encode()==read('source.patch')
assert b'Ok(ref fees) => Ok(context.gates.apply(fees))' in after[source]
assert b'fn apply(self, fees: &crate::curve::fees::AppliedFees)' in after[source]
image_hashes={};launches={}
for k in ['baseline','candidate','repeat']:
 launch=record('builds/'+k+'/launch.json');result=record('builds/'+k+'/result.json');launches[k]=launch
 assert launch['inputs']=={n:sha(v) for n,v in sources['candidate' if k=='repeat' else k].items()}
 assert result['returncode']==0 and result['source_unchanged'] and result['dependencies_unchanged'] and result['actual_root_invocations']==1
 assert sum(l.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in l for l in read('builds/'+k+'/build.log.gz').decode().splitlines())==1
 cmd=launch['command'];assert cmd[cmd.index('--network')+1]=='none' and '--locked' in cmd and '--offline' in cmd
 image_hashes[k]={kind:sha(read('builds/'+k+'/'+kind+'.so.gz')) for kind in ['symbols','candidate']}
 assert all(result[kind+'_sha256']==value for kind,value in image_hashes[k].items())
assert image_hashes['candidate']==image_hashes['repeat']
assert image_hashes['baseline']['candidate']=='d7eb57fc57f18b0f6690206d785db576e7c4cd233cca7bdb9c625b443b541ef6'
assert image_hashes['candidate']['candidate']=='8538bc26ce126d63bf9fbdf0547780e1f893ac2655689a4c4b08c3ef435b20b5'
assert all(launches[k]['dependencies_before']==launches['baseline']['dependencies_before'] and launches[k]['tools']==launches['baseline']['tools'] for k in ['candidate','repeat'])
assert len(launches['baseline']['dependencies_before'])==396
for label,normal in [('baseline','baseline'),('candidate','candidate')]:
 result=record('compiler/'+label+'/result.json');assert result['returncode']==0 and result['dependencies_unchanged'] and result['normal_stripped_equal']
 assert result['candidate_sha256']==image_hashes[normal]['candidate']
 assert sha(read('compiler/'+label+'/pump_amm_recovered.so.gz'))==result['symbols_sha256']
controls=record('compiler/codegen/results.json');assert len(controls)==6 and controls[0]['normal_equal']
assert [v['order'] for v in controls if v['equals_original_masking_only_call']]==['LCP','LPC']
runpy.run_path(str(HERE/'analyze.py'),run_name='__main__')
runpy.run_path(str(HERE/'audit_runtime.py'),run_name='__main__')
print('PASS: packet inventory,54source inputs,396dependencies,normal repeat,compiler qualification and signed runtime')
