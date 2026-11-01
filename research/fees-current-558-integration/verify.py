"""Recompute source, artifact, window, call, Location and retained runtime bindings."""
from pathlib import Path
import gzip,hashlib,json,importlib.util,struct,re
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def read(p):
 p=Path(p)
 return p.read_bytes()if p.exists()else gzip.decompress(p.with_name(p.name+'.gz').read_bytes())
def load(p):return json.loads(read(p))
def sha(b):return hashlib.sha256(b).hexdigest()
def verify():
 pins=load(HERE/'manifest.json');paths=list(HERE.rglob('*'))
 assert not any(p.is_symlink()for p in paths)
 assert {str(p.relative_to(HERE))for p in paths if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}==set(pins)
 for n,h in pins.items():assert sha((HERE/n).read_bytes())==h,n
 for n,h in load(HERE/'inputs.json').items():assert sha((ROOT/n).read_bytes())==h,n
 P=ROOT/'research/fees-composed-frontier188/window_map.py';s=importlib.util.spec_from_file_location('w558',P);w=importlib.util.module_from_spec(s);s.loader.exec_module(w)
 o=(ROOT/'evidence/original/pump_fees/deployed.so').read_bytes();ow=w.windows(o);ob={v['address']:v for v in ow};rel=dict(w.m.relocations(o))
 sources={str(p.relative_to(HERE/'sources')).removesuffix('.gz'):sha(gzip.decompress(p.read_bytes()))for p in(HERE/'sources').rglob('*.gz')};assert len(sources)==42
 changed={'programs/pump-fees/src/lib.rs','programs/pump-fees/src/donation.rs','programs/pump-fees/src/instructions/admin/initialize_fee_config.rs'}
 parent=ROOT/'repro/pump_fees/distribution-helper-recovery/sources/candidate'
 before={str(p.relative_to(parent)).removesuffix('.gz'):sha(gzip.decompress(p.read_bytes())if p.suffix=='.gz'else p.read_bytes())for p in parent.rglob('*')if p.is_file()}
 assert {n for n in sources if sources[n]!=before[n]}==changed
 outputs={};reports={}
 def location(data,p):
  low,ptr,n,line,col=struct.unpack('<IIQII',w.m.at_address(data,p,24));assert low==0 and 0<n<=300 and 0<line<=100000 and 0<col<=300
  name=w.m.at_address(data,ptr,n);assert name.endswith(b'.rs');return name,line,col
 for label,counts in [('baseline',(556,409,118,29)),('candidate',(558,411,142,27)),('repeat',(558,411,142,27))]:
  launch=load(HERE/f'builds/{label}/launch.json');result=load(HERE/f'builds/{label}/result.json');assert launch['source_inputs']==(before if label=='baseline'else sources)
  assert result['exit_code']==0 and result['source_unchanged']and result['registry_unchanged']and result['root_invocations']==result['math_invocations']==1
  assert len(launch['registry_archives'])==252 and launch['fresh_dependency_target']==(label=='baseline')
  assert sha(read(HERE/f'builds/{label}/build.log'))==result['build_log_sha256']
  command=launch['command'];assert '--offline'in command and '--locked'in command and command[command.index('--network')+1]=='none'
  b=read(HERE/f'artifacts/{label}-symbols.so');c=read(HERE/f'artifacts/{label}-candidate.so');outputs[label]=c,b
  assert all(sha(data)==result['artifacts'][name]['sha256']and len(data)==result['artifacts'][name]['bytes']for data,name in [(b,'symbols.so'),(c,'candidate.so')])
  cw=w.windows(b);cb={v['address']:v for v in cw};cmp=w.compare(ow,cw);sigs={v['signature']for v in cw};raw={v['raw_sha256']for v in cw};covered={v['address']for v in ow if v['signature']in sigs};rawcovered={v['address']for v in ow if v['raw_sha256']in raw};assert(len(covered),len(cmp['unique_pairs']),len(rawcovered),len(cmp['unmatched_original']))==counts
  edges={};locations={}
  for pair in cmp['unique_pairs']:
   a,z=pair['original'],pair['candidate']
   for x,y in zip(w.m.instructions(o,a['address'],a['bytes']),w.m.instructions(b,z['address'],z['bytes'])):
    at=a['address']+x['offset'];info=rel.get(at,0)&0xffffffff;k=(a['address'],x['offset'])
    if info==8:
     try:left=location(o,x['lddw_value'])
     except(AssertionError,ValueError,StopIteration,struct.error):continue
     assert left==location(b,y['lddw_value']);locations[k]=left
    if 'call_target'in x and info!=10:edges[k]=ob[x['call_target']]['signature']==cb[y['call_target']]['signature']
  assert len(locations)==165
  reports[label]=covered,rawcovered,edges,locations
 a,b=reports['baseline'],reports['candidate'];assert b[0]-a[0]=={270136,295800}and not a[0]-b[0]and not a[1]-b[1]
 assert all(not v or b[2].get(k,False)for k,v in a[2].items())and sum(b[2].values())==3336 and a[3].items()<=b[3].items()
 assert outputs['candidate']==outputs['repeat']and sha(outputs['candidate'][0])=='23978b955abf7d482f604d73734e6aca69216a5a3c0d4b96e14bb503fef66708'
 full=load(HERE/'runtime/full.json');assert full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']and full['candidate_sha256']==sha(outputs['candidate'][0])
 for v in full['suites'].values():assert not v.get('mismatches',[])and not v.get('failures',[])and not v.get('mismatch_count',0)
 boundary=load(HERE/'runtime/boundary.json');assert boundary['case_count']==76 and not boundary['mismatches']['proposal']and len(boundary['mismatches']['control'])==15 and boundary['hashes']['proposal']==sha(outputs['candidate'][0])
 strict=load(HERE/'runtime/strict-crank.json');assert strict['case_count']==304 and len(strict['mismatches'])==304 and strict['candidate_sha256']==sha(outputs['candidate'][0])
 norm=lambda xs:[x for x in xs if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units',x)]
 for row in strict['cases']:
  x,y=row['original'],row['candidate'];assert all(x[k]==y[k]for k in x if k!='logs')and norm(x['logs'])==norm(y['logs'])
 print('PASS: 558 normalized;142 raw;27 unmatched;165 Locations;3336 equal calls;17331 suite cases;76 boundary cases;304 strict compute-log differences')
if __name__=='__main__':verify()
