"""Verify artifact attribution, signed receipts and persistent donation state."""
from collections import Counter
from functools import lru_cache
from pathlib import Path
import base64,gzip,hashlib,importlib.util,json,tarfile
from solders.transaction import Transaction

P=Path(__file__).resolve().parent
R=P.parents[1]
LABELS=('crank583-archive-port','create583-emitter-port')
ORIGINAL='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
def require(ok,message):
 if not ok:raise ValueError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(gzip.decompress(path.read_bytes())if path.suffix=='.gz'else path.read_bytes())
def rows(path):return [json.loads(line)for line in gzip.decompress(path.read_bytes()).splitlines()]
def archive(name):
 with tarfile.open(P/'public'/name)as t:return {m.name:sha(t.extractfile(m).read())for m in t.getmembers()if m.isfile()}
@lru_cache(maxsize=1)
def ids():
 spec=importlib.util.spec_from_file_location('lifecycle_fixture',R/'scripts/fees_donation_create_differential.py');m=importlib.util.module_from_spec(spec)
 import sys
 sys.path.insert(0,str(R/'scripts'));spec.loader.exec_module(m)
 return str(m.PROGRAM),str(m.DONATION),str(m.PAYER.pubkey()),str(m.GLOBAL),str(m.AUTH.pubkey())
def program_logs(row):return [s for s in row['logs']if s.startswith(('Program log:','Program data:','Program return:'))]
def signed(row,wanted):
 raw=base64.b64decode(row['transaction_base64'],validate=True);tx=Transaction.from_bytes(raw)
 checks=tx.verify_with_results();require(checks and all(checks),'invalid transaction signature')
 require(row['signature_fields']==len(checks),'signature count')
 program=ids()[0];require(row['fees_sha256']==wanted and row['loaded_programs'][program]==wanted,'loaded Fees artifact')
 for key,h in row['loaded_programs'].items():
  if key==program:continue
  require(dependency_hashes().get(key)==h,'loaded dependency artifact')
 return len(checks)
@lru_cache(maxsize=1)
def dependency_hashes():
 names={'donation_relay':'RLAYHr9TRFcKB2ubYQhspcnXiaGpaVzNQvHytt47RZu','spl_token':'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA','associated_token':'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'}
 return {key:sha((R/f'evidence/dependencies/{name}/deployed.so').read_bytes())for name,key in names.items()}
def pair(a,b,candidate):
 signatures=signed(a,ORIGINAL)+signed(b,candidate)
 for key in ('transaction_base64','error','before','after','inner','return_data'):
  require(a[key]==b[key],'paired '+key)
 require(program_logs(a)==program_logs(b),'paired serialized program logs')
 return signatures
def bound(row,result):
 for key in ('transaction_base64','error','logs','inner'):
  require(row[key]==result[key],'receipt binding '+key)
 if 'return_data'in result:require(row['return_data']==result['return_data'],'receipt return binding')
def header(path,transcript,observer):
 h=read(path)
 require(h['observer_sha256']==sha(observer.read_bytes()),'observer input binding')
 require(h['transactions']==len(transcript),'observer transaction count')
 require(h['signature_fields']==sum(x['signature_fields']for x in transcript),'observer signature count')
 for n,wanted in h['input_reads'].items():require(sha((R/n).read_bytes())==wanted,'runtime input '+n)
 for i,x in enumerate(transcript):require(x['sequence']==i,'transcript sequence')

def native():
 public=P/'public';manifest=read(public/'manifest.json')
 for f in public.rglob('*'):
  if f.is_file()and f.name!='manifest.json':require(sha(f.read_bytes())==manifest['files'][f.relative_to(public).as_posix()],'public input '+str(f))
 for n,h in manifest['external_files'].items():require(sha((R/n).read_bytes())==h,'public external '+n)
 spec=importlib.util.spec_from_file_location('lifecycle_windows',R/'research/fees-composed-frontier188/window_map.py');w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
 w.m.elf_layout=lru_cache(maxsize=4)(w.m.elf_layout);w.m.relocations=lru_cache(maxsize=4)(w.m.relocations)
 original=(R/'evidence/original/pump_fees/deployed.so').read_bytes();require(sha(original)==ORIGINAL,'original capture')
 ow=w.windows(original);oc=Counter(x['signature']for x in ow);out={}
 for label in LABELS:
  d=public/'builds'/label;launch=read(d/'launch.json');result=read(d/'result.json');kind=label.split('583')[0]
  require(archive('source-'+kind+'.tar.gz')==launch['source_inputs'],'source archive')
  require(archive('macro-vendor.tar.gz')==launch['vendor_inputs'],'macro source archive')
  if kind=='crank':require(archive('crank-anchor.tar.gz')==launch['anchor_inputs']and result['anchor_unchanged'],'experimental Anchor source archive')
  require(result['returncode']==0 and result['source_unchanged']and result['vendor_unchanged'],'published native build receipt')
  image=gzip.decompress((d/'symbols.so.gz').read_bytes());cut=gzip.decompress((d/'candidate.so.gz').read_bytes())
  require(sha(image)==result['symbols_sha256']and sha(cut)==result['candidate_sha256'],'published native artifact')
  require(w.m.section_data(image,'.text')==w.m.section_data(cut,'.text'),'stripped text')
  cw=w.windows(image);cc=Counter(x['signature']for x in cw);count=sum(min(n,cc[k])for k,n in oc.items());require(count==583,'prior normalized windows')
  target=next(x for x in cw if x['name']and ('19pump_fees_candidate22crank_donation_fee_pda'if kind=='crank'else'19pump_fees_candidate23create_donation_fee_pda')in x['name'])
  original_body=next(x for x in ow if x['address']==(147944 if kind=='crank'else 163920))
  require(target['signature']!=original_body['signature'],'residual body remains unequal')
  require(target['bytes']==read(d/'measure.json')['candidate_bytes'],'correct business body boundary')
  wrapper=next(x for x in ow if x['address']==(656832 if kind=='crank'else 655904))
  wrappers=[x for x in cw if x['signature']==wrapper['signature']]
  called=[x['address']for x in wrappers if any(r.get('call_target')==target['address']for r in w.m.instructions(image,x['address'],x['bytes']))]
  require(called,'matched public wrapper actually calls selected body')
  out[label]=dict(candidate_sha256=sha(cut),normalized_windows=count,body_bytes=target['bytes'],original_body_bytes=original_body['bytes'],complete_body_equal=False,body_address=target['address'],calling_wrappers=called)
 return out

def verify_lifecycle(report,transcript,candidate):
 from lifecycle import cases
 require([x['case']for x in report['cases']]==cases(),'lifecycle cases')
 require(report['original_sha256']==ORIGINAL and report['candidate_sha256']==candidate,'lifecycle artifact binding')
 pos=0;signatures=0;raw_differences=0;failure_pairs=0;step_pairs=0
 program,donation,payer,global_key,authority=ids()
 for case in report['cases']:
  left=case['original'];right=case['candidate'];a=left['steps'];b=right['steps'];n=len(a)
  require(len(b)==n and case['match']and left['environment_edits']==right['environment_edits'],'sequence metadata')
  aa=transcript[pos:pos+n];bb=transcript[pos+n:pos+2*n];require(len(bb)==n,'complete sequence records');pos+=2*n
  mode=case['case']['mode'];names=['create','fund-first']
  if mode=='disabled':names+=['disable-crank']
  names+=['crank-first']
  if mode=='disabled':names+=['enable-crank']
  if mode in ['disabled','readonly','missing-whitelist']:names+=['crank-retry']
  names+=['fund-second','crank-same-time','crank-after-interval','crank-repeat-empty']
  require([x['name']for x in a]==names==[x['name']for x in b],'ordered lifecycle steps')
  for receipt,observations in [(left,aa),(right,bb)]:
   seen={}
   for step,row in zip(receipt['steps'],observations):
    bound(row,step['result'])
    for key in [donation,global_key,payer,authority]:
     if key in row['before']and key in seen:require(row['before'][key]==seen[key],'persistent account continuity')
     if key in row['after']:seen[key]=row['after'][key]
    expected_error=step['name']=='crank-first'and mode in ['disabled','readonly','missing-whitelist']
    require((row['error']is not None)==expected_error,'expected lifecycle outcome')
    if expected_error:
     for key,value in row['before'].items():
      if key!=payer:require(row['after'][key]==value,'failed transaction rollback')
    if step['name'].startswith('crank')and row['error']is None:
     require(row['after'][donation]['lamports']==2408160,'successful crank preserves donation rent')
    if step['name']=='fund-first':require(row['after'][donation]['lamports']-row['before'][donation]['lamports']==1000000,'first deposit')
    if step['name']=='fund-second':require(row['after'][donation]['lamports']-row['before'][donation]['lamports']==500000,'second deposit')
  for x,y in zip(aa,bb):
   signatures+=pair(x,y,candidate);step_pairs+=1;raw_differences+=x['logs']!=y['logs'];failure_pairs+=x['error']is not None
 require(pos==len(transcript)and not report['mismatches'],'complete lifecycle coverage')
 return dict(sequences=len(report['cases']),step_pairs=step_pairs,transactions=len(transcript),signature_fields=signatures,expected_failure_pairs=failure_pairs,raw_log_difference_pairs=raw_differences)

def verify():
 manifest=read(P/'manifest.json')
 for n,h in manifest['files'].items():require(sha((P/n).read_bytes())==h,'packet hash '+n)
 for n,h in manifest['external_files'].items():require(sha((R/n).read_bytes())==h,'external hash '+n)
 artifacts=native();out={}
 for label in LABELS:
  candidate=artifacts[label]['candidate_sha256'];focused={}
  for suite,count in [('create',356),('crank',357)]:
   d=P/'receipts/focused';name=label+'-'+suite;report=read(d/(name+'.json.gz'));observations=rows(d/(name+'-observed.jsonl.gz'))
   header(d/(name+'-observed.json.gz'),observations,P/'receipts/focused-observer.py')
   require(len(report['cases'])==count and len(observations)==2*count,'focused coverage')
   require(report['original_sha256']==ORIGINAL and report['candidate_sha256']==candidate,'focused artifact')
   signatures=0;raw_diffs=0
   for i,case in enumerate(report['cases']):
    x,y=observations[2*i:2*i+2];bound(x,case['original']);bound(y,case['candidate']);signatures+=pair(x,y,candidate);raw_diffs+=x['logs']!=y['logs'];require(case['match'],'canonical mismatch')
   require(not report['mismatches'],'canonical failures')
   focused[suite]=dict(cases=count,transactions=len(observations),signature_fields=signatures,raw_log_difference_pairs=raw_diffs)
  d=P/'receipts/lifecycle';transcript=rows(d/(label+'-observed.jsonl.gz'));header(d/(label+'-observed.json.gz'),transcript,P/'observer.py')
  out[label]=dict(native=artifacts[label],focused=focused,lifecycle=verify_lifecycle(read(d/(label+'.json.gz')),transcript,candidate))
 return out
if __name__=='__main__':print(json.dumps(verify(),indent=2))
