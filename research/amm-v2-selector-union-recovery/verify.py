"""Verify the 759 -> 760 source composition and its retained local evidence."""
from pathlib import Path
import difflib,gzip,hashlib,json,runpy,tarfile
if not __debug__:raise SystemExit('Run without -O')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(name):
 raw=(HERE/name).read_bytes();return gzip.decompress(raw) if name.endswith('.gz') else raw
def record(name):return json.loads(read(name))
paths=list(HERE.rglob('*'))
assert not any(p.is_symlink() for p in paths),'packet symlink'
assert all(p.is_file() or p.is_dir() for p in paths),'packet special file'
manifest=record('MANIFEST.json')
assert set(manifest['files'])=={p.relative_to(HERE).as_posix() for p in paths if p.is_file() and p!=HERE/'MANIFEST.json'},'packet file inventory'
for name,digest in manifest['files'].items():assert sha((HERE/name).read_bytes())==digest,name
for name,digest in manifest['repository_inputs'].items():assert sha((ROOT/name).read_bytes())==digest,name
source_files=runpy.run_path(str(HERE/'materialize.py'))['source_files']
sources={k:source_files(k) for k in ['baseline','candidate','intermediate']};a,b=sources['baseline'],sources['candidate'];source='programs/pump-amm/src/curve/fees.rs';volume='programs/pump-amm/src/state/volume_accumulator.rs'
with tarfile.open(ROOT/'research/claude-amm-union2-20261028/sources/candidate.tar.gz') as archive:
 assert a=={m.name:archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
assert a.keys()==b.keys() and [n for n in a if a[n]!=b[n]]==[source,volume]
assert [n for n in a if a[n]!=sources['intermediate'][n]]==[source]
assert b[source]==sources['intermediate'][source]
old=b'            require!(current_timestamp<=self.end_time,PumpAmmError::SupplyUpdateForFinishedRange);'
new=b'            if current_timestamp>=self.start_time {require!(current_timestamp<=self.end_time,PumpAmmError::SupplyUpdateForFinishedRange);}'
assert a[volume].count(old)==1 and a[volume].replace(old,new)==b[volume]==read('proposed/volume_accumulator.rs')
assert a[source].split(b'pub fn select_and_apply_v2(')[0]==b[source].split(b'fn select_v2_fees(')[0]
assert b[source].splitlines()[183].strip()==b'require!(fee_config_len >= 2512, PumpAmmError::FeeConfigTooShort);'
assert b'#[inline' not in b[source] and b[source]==read('proposed/fees.rs')
assert ''.join(''.join(difflib.unified_diff(a[n].decode().splitlines(True),b[n].decode().splitlines(True),fromfile='a/'+n,tofile='b/'+n)) for n in [source,volume]).encode()==read('source.patch')
launches={};hashes={}
for label in ['baseline','candidate','repeat','intermediate','intermediate-repeat']:
 launch=record('builds/'+label+'/launch.json');result=record('builds/'+label+'/result.json');launches[label]=launch
 assert launch['controller_sha256'] in [sha(read('controllers/'+name)) for name in ['build.py','selector-build.py']]
 assert launch['inputs']=={n:sha(v) for n,v in sources[label.removesuffix('-repeat') if label!='repeat' else 'candidate'].items()}
 assert result['returncode']==0 and result['source_unchanged'] and not result['dependency_changes'] and result['actual_root_invocations']==1
 assert sum(l.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in l for l in read('builds/'+label+'/build.log.gz').decode().splitlines())==1
 cmd=launch['command'];assert cmd[cmd.index('--network')+1]=='none' and '--locked' in cmd and '--offline' in cmd
 hashes[label]={kind:sha(read('builds/'+label+'/'+kind+'.so.gz')) for kind in ['symbols','candidate']}
 assert all(result[kind+'_sha256']==digest for kind,digest in hashes[label].items())
assert hashes['candidate']==hashes['repeat']
assert hashes['intermediate']==hashes['intermediate-repeat']
assert hashes['baseline']['symbols']=='5c02eed71ea347a53365dd15727800e60cf894a08eba13ef785d594710b5f862'
assert hashes['intermediate']['candidate']=='663901e20359f3f0c9bcbb1fef199272e983fa7974cca6f3ec149ffb71537f56'
assert hashes['candidate']['candidate']=='e708c278cdda90f08f0aafb8739d857c69b5878bca78ab16d62af820ca3c7231'
assert all(launches[k]['dependencies_before']==launches['baseline']['dependencies_before'] and launches[k]['tools']==launches['baseline']['tools'] for k in ['candidate','repeat','intermediate','intermediate-repeat'])
assert len(launches['baseline']['dependencies_before'])==396
for script in ['analyze.py','audit_runtime.py','audit_all.py','audit_schedule.py']:runpy.run_path(str(HERE/script),run_name='__main__')
print('PASS: 57 source inputs,396 unchanged dependency artifacts,repeat-identical build and signed local execution')
