"""Verify non-promoted source controls and the exact residual copy proof."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def read(p):return json.loads(gzip.decompress(p.read_bytes())if p.suffix=='.gz'else p.read_bytes())
def sha(b):return hashlib.sha256(b).hexdigest()
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def sources():
 e=read(HERE/'experiment.json');base=module('cpi_control_parent',ROOT/e['parent_packet']/'verify.py').sources()['origins'];out={}
 for label,row in e['variants'].items():
  source=dict(base)
  for n,p in row['overrides'].items():source[n]=(HERE/p).read_bytes()
  assert len(source)==42 and {n:sha(b)for n,b in source.items()}==row['input_sha256'];out[label]=source
 assert out['control']==base
 return out
def verify():
 manifest=read(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert set(manifest)==actual
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 for n,h in read(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 sources();e=read(HERE/'experiment.json');assert e['accepted']is False and len(e['variants'])==13
 for label,row in e['variants'].items():
  launch=read(HERE/f'builds/{label}-launch.json');result=read(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['inputs']==row['input_sha256']and result['compiled_root']and result['exit_code']==0 and result['source_unchanged']and sha(log)==result['log_sha256']
  assert log.count(b'--crate-name pump_fees_candidate ')==1 and launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
  for k,v in row['files'].items():
   b=gzip.decompress((HERE/v['path']).read_bytes());assert sha(b)==v['sha256']==result[k+'_sha256']and len(b)==v['bytes']
 a=module('cpi_control_analysis',HERE/'analyze.py').analyze();assert a==read(HERE/'analysis.json.gz')
 for r in a['variants'].values():assert len(r['covered'])==553 and len(r['raw'])==118 and r['unmatched']==32 and not r['gained']and not r['lost']
 r=read(HERE/'runtime.json.gz');assert len(r['cases'])==417 and not r['mismatches']and all(x['match']for x in r['cases'])
 assert r['candidate_sha256']==e['variants'][e['runtime_variant']]['files']['candidate']['sha256']and r['original_sha256']==sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes())
 for n,h in read(HERE/'harness-sha256.json').items():assert sha((ROOT/n).read_bytes())==h,n
 print('PASS: 13 real source controls; no body gains/losses; two four-byte scheduling residuals; local copy proof; 417 bounded cases; candidate not promoted')
if __name__=='__main__':verify()
