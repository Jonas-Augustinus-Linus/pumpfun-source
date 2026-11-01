#!/usr/bin/env python3
"""Recompute residual research measurements without promoting any candidate."""
from pathlib import Path
from functools import lru_cache
from collections import Counter
import difflib,gzip,hashlib,importlib.util,json,tarfile
P=Path(__file__).resolve().parent;R=P.parents[1]
def require(value,message):
 if not value:raise ValueError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def archive(name):
 with tarfile.open(P/(name+'.tar.gz'))as t:return {m.name:t.extractfile(m).read()for m in t.getmembers()if m.isfile()}
def verify():
 manifest=json.loads((P/'manifest.json').read_text())
 for name,wanted in manifest['files'].items():require(sha((P/name).read_bytes())==wanted,'packet hash: '+name)
 for name,wanted in manifest['external_files'].items():require(sha((R/name).read_bytes())==wanted,'external hash: '+name)
 s=importlib.util.spec_from_file_location('residual_window_reader',R/'research/fees-composed-frontier188/window_map.py');w=importlib.util.module_from_spec(s);s.loader.exec_module(w);w.m.elf_layout=lru_cache(maxsize=4)(w.m.elf_layout);w.m.relocations=lru_cache(maxsize=4)(w.m.relocations)
 original=(R/'evidence/original/pump_fees/deployed.so').read_bytes();ow=w.windows(original);oc=Counter(r['signature']for r in ow);sources={x:archive('source-'+x)for x in ['create','crank']};vendor={n:sha(b)for n,b in archive('macro-vendor').items()};anchor={n:sha(b)for n,b in archive('crank-anchor').items()};index=json.loads((P/'index.json').read_text());reports={}
 def normalized(image,start,length):
  rel=dict(w.m.relocations(image));rows=[]
  for r in w.m.instructions(image,start,length):
   b=bytearray.fromhex(r['raw']);kind=rel.get(start+r['offset'],0)&0xffffffff
   if kind==10 or'call_target'in r:b[4:8]=bytes(4)
   elif kind==8:b[4:8]=b[12:16]=bytes(4)
   rows.append(bytes(b).hex())
  return rows
 def call_counts(image,windows,start,length):
  bounds={r['address']:r for r in windows};rel=dict(w.m.relocations(image));out=Counter()
  for row in w.m.instructions(image,start,length):
   if'call_target'in row and rel.get(start+row['offset'],0)&0xffffffff!=10:out[bounds[row['call_target']]['signature']]+=1
  return out
 for label in index['labels']:
  D=P/'builds'/label;kind=label.split('583')[0];start,length,name=(163920,13800,'19pump_fees_candidate23create_donation_fee_pda')if kind=='create'else(147944,15976,'19pump_fees_candidate22crank_donation_fee_pda');image=gzip.decompress((D/'symbols.so.gz').read_bytes());cut=gzip.decompress((D/'candidate.so.gz').read_bytes());result=json.loads((D/'result.json').read_text());launch=json.loads((D/'launch.json').read_text());measurement=json.loads((D/'measure.json').read_text());source=dict(sources[kind])
  if(D/'create.rs').exists():source['programs/pump-fees/src/instructions/fee_sharing/create_donation_fee_pda.rs']=(D/'create.rs').read_bytes()
  if(D/'lib.rs').exists():source['programs/pump-fees/src/lib.rs']=(D/'lib.rs').read_bytes()
  if label.endswith('formatter-constructor'):source['programs/pump-fees/src/lib.rs']=source['programs/pump-fees/src/lib.rs'].replace(b'feature(core_intrinsics, try_blocks)',b'feature(core_intrinsics, try_blocks, fmt_internals)')
  require({n:sha(b)for n,b in source.items()}==launch['source_inputs'],'source inputs: '+label);require(launch['vendor_inputs']==vendor,'macro inputs')
  if kind=='crank':require(launch['anchor_inputs']==anchor and result['anchor_unchanged'],'experimental Anchor inputs')
  require(result['returncode']==0 and result['source_unchanged']and result['vendor_unchanged'],'stable normal build');require(sha(image)==result['symbols_sha256']and sha(cut)==result['candidate_sha256'],'binary binding');require(w.m.section_data(image,'.text')==w.m.section_data(cut,'.text'),'strip text')
  cw=w.windows(image);cc=Counter(r['signature']for r in cw);require(sum(min(n,cc[k])for k,n in oc.items())==583,'583 original matches preserved');target=next(r for r in cw if r['name']and name in r['name']);a,b=normalized(original,start,length),normalized(image,target['address'],target['bytes']);left,right=call_counts(original,ow,start,length),call_counts(image,cw,target['address'],target['bytes']);expected=dict(candidate_bytes=target['bytes'],candidate_instructions=target['instructions'],normalized_exact=next(r for r in ow if r['address']==start)['signature']==target['signature'],same_offset_rows=sum(x==y for x,y in zip(a,b)),aligned_rows=sum(x.size for x in difflib.SequenceMatcher(None,a,b,autojunk=False).get_matching_blocks()),normalized_original_windows=583,candidate_windows=len(cw),missing_direct_targets=dict(left-right),extra_direct_targets=dict(right-left));require(expected==measurement,'independent measurement: '+label);require(not expected['normalized_exact'],'no recovered residual body claimed');reports[label]=expected
 require(index['new_accepted_matches']==0 and not index['runtime_executed']and not index['whole_elf_equal'],'research scope');return dict(normal_builds=len(reports),all_preserve_normalized=583,new_accepted_matches=0,runtime_executed=False,whole_elf_equal=False)
if __name__=='__main__':print(json.dumps(verify(),indent=2))
