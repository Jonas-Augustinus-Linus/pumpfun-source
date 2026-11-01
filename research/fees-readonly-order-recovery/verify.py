"""Verify native Rust declaration ordering and complete readonly payload equality."""
from pathlib import Path
from collections import Counter
from functools import lru_cache
import argparse,bisect,contextlib,difflib,gzip,hashlib,importlib.util,io,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
PARENT=ROOT/'research/fees-sharing-handler-recovery'
FILES=['programs/pump-fees/src/lib.rs','programs/pump-fees/src/instructions/mod.rs','programs/pump-fees/src/instructions/fee_sharing/mod.rs']
def read(p):
 return p.read_bytes()if p.is_file()else gzip.decompress(p.with_name(p.name+'.gz').read_bytes())
def load(p):return json.loads(read(p))
def sha(b):return hashlib.sha256(b).hexdigest()
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def recover_sources(parent,p2):
 sources=parent.source_inputs(p2);expected=dict(sources)
 s=expected[FILES[0]].decode();assert s.count('mod state;\npub mod instructions;')==1
 s=s.replace('mod state;\npub mod instructions;','pub mod instructions;\nmod state;')
 start=s.index('#[error_code]\npub enum FeeError');i=s.index('{',start)+1;depth=1
 while depth:
  if s[i]=='{':depth+=1
  elif s[i]=='}':depth-=1
  i+=1
 block=s[start:i];s=s[:start]+block.replace('#[error_code]','#[macro_export] macro_rules! define_fee_errors { () => { #[error_code]',1)+' }; }'+s[i:]
 assert s.count('\n\n#[program]')==1;s=s.replace('\n\n#[program]','\ncrate::define_fee_errors!();\n#[program]',1);expected[FILES[0]]=s.encode()
 s=expected[FILES[1]].decode();assert s.count('pub mod fee_sharing;\npub mod admin;')==1;expected[FILES[1]]=s.replace('pub mod fee_sharing;\npub mod admin;','pub mod admin;\npub mod fee_sharing;').encode()
 s=expected[FILES[2]].decode();assert s.count('pub mod update_fee_shares_v2;')==1;s=s.replace('pub mod update_fee_shares_v2;','');assert s.count('\n\nuse anchor_lang')==1;expected[FILES[2]]=s.replace('\n\nuse anchor_lang','\npub mod update_fee_shares_v2;\nuse anchor_lang',1).encode()
 assert sorted(str(p.relative_to(HERE/'overrides'))for p in (HERE/'overrides').rglob('*')if p.is_file())==sorted(FILES)
 patches=[]
 for name in FILES:
  assert expected[name].count(b'\n')==sources[name].count(b'\n')
  assert read(HERE/'overrides'/name)==expected[name]
  patches.extend(difflib.unified_diff(sources[name].decode().splitlines(True),expected[name].decode().splitlines(True),fromfile='parent/'+name,tofile='recovered/'+name))
 assert ''.join(patches).encode()==read(HERE/'source.patch')
 assert {n:sha(b)for n,b in expected.items()}==load(HERE/'source-inputs.json') and len(expected)==46
 return expected

def function_mapping(w,p2,before,after,old_map,new_map):
 old={f['address']:f for f in w.windows(before)};new={f['address']:f for f in w.windows(after)}
 rows=[p2.input_sections(t,'.text')for t in[old_map,new_map]]
 keyed=[{(p2.owner(r['owner']),r['section']):r for r in rr}for rr in rows]
 assert len(old)==len(new)==len(keyed[0])==len(keyed[1])==586
 remaining=set(keyed[1]);mapping={}
 short=lambda s:re.sub(r'17h[0-9a-f]+E$','',s)
 for k,r in keyed[0].items():
  if k in keyed[1]:q=k
  else:
   candidates=[t for t in remaining if t[0]==k[0]and short(t[1])==short(k[1])and new[keyed[1][t]['address']]['signature']==old[r['address']]['signature']]
   assert len(candidates)==1;q=candidates[0]
  remaining.remove(q);mapping[r['address']]=keyed[1][q]['address']
 assert not remaining
 rel=dict(w.m.relocations(before));calls=0
 for a,b in mapping.items():
  x,y=old[a],new[b];assert x['signature']==y['signature']
  for i,j in zip(w.m.instructions(before,a,x['bytes']),w.m.instructions(after,b,y['bytes'])):
   if 'call_target'in i and rel.get(a+i['offset'],0)&0xffffffff!=10:
    assert mapping[i['call_target']]==j['call_target'];calls+=1
 assert calls==4587
 return mapping

def text_data_closure(w,p2,before,after,old_map,new_map,mapping):
 """Bind actual relocation targets to whole emitted objects, including pool atoms.

 Equal bytes alone do not select a target: each observed pointer must retain its
 offset within a consistently mapped object. Relocated object fields extend the
 same graph. Unreferenced duplicate allocations are reported, not guessed.
 """
 def objects(image,link_map):
  reloc=dict(w.m.relocations(image));result=[]
  for section in ['.rodata','.data.rel.ro']:
   for row in p2.input_sections(link_map,section):
    match=re.fullmatch(r'\.rodata\.cst(\d+)',row['section'])if row['owner']=='<internal>'else None
    step=int(match[1])if match else row['size']
    assert step>0 and row['size']%step==0
    for address in range(row['address'],row['address']+row['size'],step):
     raw=w.m.at_address(image,address,step);normal=bytearray(raw);fields={}
     for at,kind in reloc.items():
      if address<=at<address+step:
       assert kind&0xffffffff==8 and at+8<=address+step
       low,target=struct.unpack_from('<II',raw,at-address);assert low==0
       fields[at-address]=target;normal[at-address:at-address+8]=bytes(8)
     result.append(dict(address=address,size=step,section=section,pool_width=int(match[1])if match else None,normal=bytes(normal),fields=fields))
  result.sort(key=lambda r:r['address'])
  assert all(a['address']+a['size']<=b['address']for a,b in zip(result,result[1:]))
  return result
 old,new=objects(before,old_map),objects(after,new_map)
 starts=[[r['address']for r in rows]for rows in [old,new]]
 def containing(rows,keys,address):
  i=bisect.bisect_right(keys,address)-1
  assert i>=0 and address<rows[i]['address']+rows[i]['size'],('text data pointer outside emitted objects',address)
  return rows[i],address-rows[i]['address']
 bound={};reverse={};queue=[];references=[]
 def bind(left,right,context):
  if left in mapping:
   assert mapping[left]==right,('text data pointer function target',context,left,right)
   return dict(kind='function',before_target=left,after_target=right)
  a,offset=containing(old,starts[0],left);b,other=containing(new,starts[1],right)
  assert offset==other,('text data pointer interior offset',context,left,right,offset,other)
  assert (a['section'],a['pool_width'],a['size'],a['normal'],a['fields'].keys())==(b['section'],b['pool_width'],b['size'],b['normal'],b['fields'].keys()),('text data pointer object contents',context,left,right)
  if a['address']in bound:assert bound[a['address']]==b['address'],('text data pointer inconsistent object',context,left,right)
  else:
   assert b['address']not in reverse,('text data pointer merged distinct objects',context,left,right)
   bound[a['address']]=b['address'];reverse[b['address']]=a['address'];queue.append((a,b))
  return dict(kind='readonly-object',before_target=left,after_target=right,before_object=a['address'],after_object=b['address'],object_bytes=a['size'],interior_offset=offset,pool_width=a['pool_width'],relocated_fields=len(a['fields']))
 old_windows={r['address']:r for r in w.windows(before)};rel=dict(w.m.relocations(before))
 for a,b in sorted(mapping.items()):
  for x,y in zip(w.m.instructions(before,a,old_windows[a]['bytes']),w.m.instructions(after,b,old_windows[a]['bytes'])):
   if rel.get(a+x['offset'],0)&0xffffffff!=8:continue
   assert x['opcode']==y['opcode']==0x18
   row=bind(x['lddw_value'],y['lddw_value'],(a,x['offset']))
   references.append(dict(before_function=a,after_function=b,offset=x['offset'],**row))
 field_count=0
 while queue:
  a,b=queue.pop()
  for offset,target in a['fields'].items():
   bind(target,b['fields'][offset],('object field',a['address'],offset));field_count+=1
 # All live object mappings above come from actual references, never the stored
 # rebinding receipt. Unused objects have no observed consumer in this closure.
 return dict(schema=2,scope='All type-8 text relocations and the complete recursively referenced emitted readonly objects; unused objects are not assigned identities.',functions=len(mapping),text_relocations=len(references),function_pointer_relocations=sum(r['kind']=='function'for r in references),readonly_pointer_relocations=sum(r['kind']=='readonly-object'for r in references),relocated_object_fields=field_count,object_bindings={str(a):b for a,b in sorted(bound.items())},unreferenced_before=[r['address']for r in old if r['address']not in bound],unreferenced_after=[r['address']for r in new if r['address']not in reverse],text_references=references)

def verify():
 actual={str(p.relative_to(HERE)):sha(p.read_bytes())for p in HERE.rglob('*')if p.is_file()and p!=HERE/'manifest.json'}
 assert not any(p.is_symlink()for p in HERE.rglob('*'));assert actual==load(HERE/'manifest.json')
 assert load(HERE/'parent.json')=={'path':str(PARENT.relative_to(ROOT)),'manifest_sha256':sha((PARENT/'manifest.json').read_bytes())}
 parent=module('readonly_parent',PARENT/'verify.py');p2=module('readonly_p2',ROOT/'research/fees-common-quote-data-order/verify.py');prior=module('readonly_prior',ROOT/'research/fees-qualified-linker-layout/verify.py');loc=module('readonly_locations',ROOT/'research/fees-sharing-slice-recovery/verify.py');w=module('readonly_windows',ROOT/'research/fees-composed-frontier188/window_map.py')
 with contextlib.redirect_stdout(io.StringIO()):parent.verify()
 w.m.elf_layout=lru_cache(maxsize=8)(w.m.elf_layout);w.m.relocations=lru_cache(maxsize=8)(w.m.relocations)
 sources=recover_sources(parent,p2)
 for n,h in load(HERE/'external-inputs.json').items():assert sha((ROOT/n).read_bytes())==h
 before=parent.read(PARENT/'builds/candidate/symbols.so');candidate=read(HERE/'builds/candidate/symbols.so');stripped=read(HERE/'builds/candidate/candidate.so');original=(ROOT/'evidence/original/pump_fees/deployed.so').read_bytes()
 assert candidate==read(HERE/'builds/repeat/symbols.so') and stripped==read(HERE/'builds/repeat/candidate.so')
 assert original!=stripped and original[:w.m.elf_layout(original)['elf_extent']]!=stripped
 assert w.m.elf_layout(stripped)['elf_extent']==len(stripped)
 assert struct.unpack_from('<H',stripped,56)[0]==struct.unpack_from('<H',candidate,56)[0]==4
 for role,label in [('candidate','data578-qualified'),('repeat','data578-qualified-repeat')]:
  folder=HERE/'builds'/role;launch,result=load(folder/'launch.json'),load(folder/'result.json');command=launch['command'];log=read(folder/'build.log')
  assert result['exit_code']==0 and result['source_unchanged']is True
  assert result['candidate_sha256']==sha(stripped) and result['symbols_sha256']==sha(candidate) and result['log_sha256']==sha(log)
  assert log.count(b'--crate-name pump_fees_candidate ')==1 and b'Finished `release`'in log
  assert launch['inputs']=={**{n:sha(b)for n,b in sources.items()},'ordered.ld':sha(read(HERE/'layout/ordered.ld')),'linker.sh':sha(read(folder/'linker.sh'))}
  assert command[:2]==['podman','exec']and'--locked'in command and'--offline'in command
  assert command[command.index('--target')+1]=='sbpf-solana-solana'
  assert command[command.index('--manifest-path')+1]=='/work/next633/'+label+'/programs/pump-fees/Cargo.toml'
  assert 'linker=/work/next633/'+label+'/linker.sh'in command
  expected=parent.read(PARENT/'builds/candidate/linker.sh').decode().replace('next622','next633').replace('sharing578-composed-order',label)
  assert read(folder/'linker.sh')==expected.encode()
 old_map=parent.read(PARENT/'builds/candidate/link.map').decode();new_map=read(HERE/'builds/candidate/link.map').decode()
 mapping=function_mapping(w,p2,before,candidate,old_map,new_map)
 closure=text_data_closure(w,p2,before,candidate,old_map,new_map,mapping)
 assert closure==load(HERE/'layout/rebinding.json')
 assert closure['text_relocations']==2212
 assert closure['relocated_object_fields']==379 and len(closure['object_bindings'])==990
 assert not closure['unreferenced_before']and not closure['unreferenced_after']
 # Only complete input-section selectors may change in the SDK-preserving layout.
 clean=lambda s:re.sub(r'\S+\("[^"\n]+"\)','@INPUT_SECTION@',s)
 assert clean(parent.read(PARENT/'layout/ordered.ld').decode())==clean(read(HERE/'layout/ordered.ld').decode())
 for name in ['.text','.rodata','.data.rel.ro']:
  emitted=p2.input_sections(new_map,name)
  assert len(p2.input_sections(old_map,name))==len(emitted)
  body=re.search(r'  '+re.escape(name)+r' : \{(.*?)\n  \}',read(HERE/'layout/ordered.ld').decode(),re.S).group(1)
  selectors=re.findall(r'(\S+)\("([^"\n]+)"\)',body)
  assert selectors==[('*'if r['owner']=='<internal>'else p2.owner(r['owner']),r['section'])for r in emitted]
 for section in [s for s in w.m.elf_layout(candidate)['sections']if s['flags']&2 and s['type']!=8]:
  assert w.m.section_data(candidate,section['name'])==w.m.section_data(stripped,section['name'])
 assert w.m.section_data(original,'.rodata')==w.m.section_data(candidate,'.rodata') and len(w.m.section_data(candidate,'.rodata'))==21079
 refs=p2.check_data(w,original,candidate,new_map);assert len(refs)==379
 oi=w.windows(original);ci=w.windows(candidate);pi=w.windows(before)
 for field,count in [('signature',578),('raw_sha256',198)]:
  a={f['address']for f in oi if f[field]in{g[field]for g in ci}};b={f['address']for f in oi if f[field]in{g[field]for g in pi}};assert a==b and len(a)==count
 counters=[]
 for image in [original,candidate]:
  c=Counter()
  for a,k in w.m.relocations(image):
   if k&0xffffffff!=8:continue
   try:c[loc.location(w,image,a)]+=1
   except(AssertionError,ValueError,StopIteration,struct.error,UnicodeDecodeError):pass
  counters.append(c)
 assert counters[0]==counters[1]and sum(counters[0].values())==105
 prior.check_runtime(load(HERE/'runtime.json'),parent.load(PARENT/'runtime.json'),sha(original),sha(stripped))
 execution=load(HERE/'runtime-execution.json');assert execution['jobs']==6 and execution['candidate_sha256']==sha(stripped)
 return dict(normalized_functions=578,raw_local_functions=198,all_compiled_functions_preserved=len(mapping),direct_calls_preserved=4587,text_relocations_checked=closure['text_relocations'],relocated_object_fields_checked=closure['relocated_object_fields'],global_source_records=105,readonly_bytes=21079,readonly_differing_bytes=0,data_pointer_targets_checked=379,runtime_cases=17331,runtime_suites=18,candidate_sha256=sha(stripped),symbols_sha256=sha(candidate),whole_elf_equal=False,whole_capture_equal=False)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--materialize',type=Path);a=p.parse_args();result=verify()
 if a.materialize:
  assert not a.materialize.exists();parent=module('materialize_parent',PARENT/'verify.py');p2=module('materialize_p2',ROOT/'research/fees-common-quote-data-order/verify.py')
  for name,data in {**recover_sources(parent,p2),'ordered.ld':read(HERE/'layout/ordered.ld'),'linker.sh':read(HERE/'builds/candidate/linker.sh')}.items():
   target=a.materialize/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
  (a.materialize/'linker.sh').chmod(0o755)
 print(json.dumps(result,indent=2))
