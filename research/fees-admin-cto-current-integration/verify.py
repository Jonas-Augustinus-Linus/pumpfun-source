"""Recheck current-source composition, emitted windows and retained runtime evidence."""
from pathlib import Path
import argparse,difflib,gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(gzip.decompress(p.read_bytes())if p.suffix=='.gz'else p.read_bytes())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def sources():
 e=read(HERE/'experiment.json');base=module('admin_parent_source',ROOT/e['parent_packet']/'verify.py').sources()['origins'];out={}
 for label,row in e['variants'].items():
  data=dict(base)
  for n,p in row['overrides'].items():data[n]=(HERE/p).read_bytes()
  assert len(data)==42 and {n:sha(b)for n,b in data.items()}==row['input_sha256'];out[label]=data
 assert out['control']==base and out['origins']==out['repeat']
 proposal=ROOT/e['source_proposal'];changed={n for n in base if base[n]!=out['origins'][n]};assert changed=={'programs/pump-fees/src/lib.rs','programs/pump-fees/src/sharing_admin.rs','programs/pump-fees/src/instructions/fee_sharing/mod.rs','programs/pump-fees/src/instructions/fee_sharing/admin_cto_sharing_config.rs'}
 for n in changed-{'programs/pump-fees/src/lib.rs'}:assert out['origins'][n]==(proposal/'overrides'/n).read_bytes()
 n='programs/pump-fees/src/lib.rs';assert out['origins'][n]==base[n].replace(b'sharing_admin::admin_cto_sharing_config(ctx, new_admin)',b'include!("instructions/fee_sharing/admin_cto_sharing_config.rs")')
 patch=''.join(''.join(difflib.unified_diff(base[n].decode().splitlines(True),out['origins'][n].decode().splitlines(True),fromfile='a/'+n,tofile='b/'+n))for n in e['variants']['origins']['overrides']);assert patch==(HERE/'source.patch').read_text()
 return out
def verify():
 manifest=read(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert set(manifest)==actual
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 for n,h in read(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 sources();e=read(HERE/'experiment.json')
 for label,row in e['variants'].items():
  launch=read(HERE/f'builds/{label}-launch.json');result=read(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['inputs']==row['input_sha256']and result['source_unchanged']and result['compiled_root']and result['exit_code']==0
  assert sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
  assert '--offline'in launch['command']and '--locked'in launch['command']and sum(x.startswith('--remap-path-prefix=')for x in launch['command'])==3
  for k,v in row['files'].items():
   raw=gzip.decompress((HERE/v['path']).read_bytes());assert sha(raw)==v['sha256']==result[k+'_sha256']and len(raw)==v['bytes']
 for k in ['candidate','symbols']:assert e['variants']['origins']['files'][k]['sha256']==e['variants']['repeat']['files'][k]['sha256']
 report=module('admin_current_analysis',HERE/'analyze.py').analyze();assert report==read(HERE/'analysis.json.gz')
 for label,count in [('control',553),('origins',554),('repeat',554)]:
  r=report['variants'][label];assert len(r['normalized'])==count and len(r['raw'])==118 and not report['deltas'][label]['lost']and not report['deltas'][label]['raw_lost']
 assert report['deltas']['origins']['added']==[127776]and len(report['variants']['origins']['unique_pairs'])==407
 assert len(report['admin_cto']['calls'])==20 and all(x['equal']for x in report['admin_cto']['calls'])
 r=read(HERE/'runtime.json.gz');assert r['candidate_sha256']==e['variants']['origins']['files']['candidate']['sha256']and r['original_sha256']==sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes())
 assert r['case_count']==17331 and len(r['suites'])==18 and not r['mismatches']
 for suite in r['suites'].values():assert suite['candidate_sha256']==r['candidate_sha256']and suite['original_sha256']==r['original_sha256']and not suite.get('mismatches',suite.get('failures',[]))
 for n,h in read(HERE/'harness-sha256.json').items():assert sha((ROOT/n).read_bytes())==h,n
 print('PASS: four-file current-source integration; two identical native builds; 554 normalized/407 unique/31 unmatched; 20 business callees; 17331 comparisons; no lost matches')
if __name__=='__main__':verify()
