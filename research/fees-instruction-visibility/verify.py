"""Verify the visibility-only recovery, actual outputs and bounded runtime evidence."""
from pathlib import Path
import argparse,difflib,gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(gzip.decompress(p.read_bytes())if p.suffix=='.gz'else p.read_bytes())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def sources():
 e=read(HERE/'experiment.json');parent=ROOT/e['parent_packet'];meta=read(parent/'experiment.json')['variants']['origins'];base={n:(parent/p).read_bytes()for n,p in meta['source_paths'].items()};assert {n:sha(b)for n,b in base.items()}==meta['input_sha256'];out={}
 for label,row in e['variants'].items():
  data=dict(base)
  for n,p in row['overrides'].items():data[n]=(HERE/p).read_bytes()
  assert {n:sha(b)for n,b in data.items()}==row['input_sha256'] and len(data)==42;out[label]=data
 path='programs/pump-fees/src/lib.rs';assert out['origins']==base|{path:base[path].replace(b'\nmod instructions;',b'\npub mod instructions;')}
 assert out['origins']==out['repeat']
 patch=''.join(difflib.unified_diff(base[path].decode().splitlines(True),out['origins'][path].decode().splitlines(True),fromfile='a/'+path,tofile='b/'+path));assert patch==(HERE/'visibility.patch').read_text()
 return out
def verify():
 manifest=read(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert set(manifest)==actual
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 for n,h in read(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 src=sources();e=read(HERE/'experiment.json')
 for label,row in e['variants'].items():
  launch=read(HERE/f'builds/{label}-launch.json');result=read(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['inputs']==row['input_sha256'] and result['source_unchanged'] and result['compiled_root'] and result['exit_code']==0
  assert sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
  assert '--offline'in launch['command'] and '--locked'in launch['command'] and 'sbpf-solana-solana'in launch['command'] and sum(x.startswith('--remap-path-prefix=')for x in launch['command'])==3
  for k,v in row['files'].items():
   raw=gzip.decompress((HERE/v['path']).read_bytes());assert sha(raw)==v['sha256']==result[k+'_sha256'] and len(raw)==v['bytes']
 for k in ['candidate','symbols']:assert e['variants']['origins']['files'][k]['sha256']==e['variants']['repeat']['files'][k]['sha256']
 report=module('visibility_analysis',HERE/'analyze.py').analyze();assert report==read(HERE/'analysis.json.gz')
 for label in src:
  r=report['variants'][label];expected=553 if label in ['origins','repeat','exported-authorizer']else 552
  assert len(r['normalized'])==expected and len(r['raw'])==118 and not report['deltas'][label]['lost'] and not report['deltas'][label]['raw_lost']
 assert report['deltas']['origins']['added']==[650064]and len(report['variants']['origins']['unique_pairs'])==406
 assert report['wrapper']['contract']['bump_store']==dict(opcode=0x6a,destination=10,source=0,displacement=-562,immediate=65535)
 r=read(HERE/'runtime.json.gz');assert r['candidate_sha256']==e['variants']['origins']['files']['candidate']['sha256']and r['original_sha256']==sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes())
 assert r['case_count']==17331 and len(r['suites'])==18 and not r['mismatches']
 for suite in r['suites'].values():assert suite['candidate_sha256']==r['candidate_sha256']and suite['original_sha256']==r['original_sha256']and not suite.get('mismatches',suite.get('failures',[]))
 harness=read(HERE/'harness-sha256.json');assert len(harness)==187
 for n,h in harness.items():assert sha((ROOT/n).read_bytes())==h,n
 print('PASS: one visibility declaration; two identical Rust builds; 553 normalized/406 unique/32 unmatched; six wrapper callees; 17331 bounded comparisons; no lost body matches')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--materialize',type=Path);p.add_argument('--variant',default='origins');args=p.parse_args();verify()
 if args.materialize:
  d=args.materialize;assert not d.exists()and not any(p.is_symlink()for p in d.parents);d.mkdir(parents=True)
  for name,b in sources()[args.variant].items():p=d/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
