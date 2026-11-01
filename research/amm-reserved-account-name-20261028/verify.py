#!/usr/bin/env python3
"""Offline source/artifact/window/runtime verification; no compiler or network."""
from pathlib import Path
import argparse,base64,collections,difflib,gzip,hashlib,io,json,re,sys,tarfile,tempfile
sys.dont_write_bytecode=True
if not __debug__:raise SystemExit("Verification requires assertions; run without -O.")
P=Path(__file__).resolve().parent
R=next(p for p in P.parents if (p/'evidence/original/pump_amm/deployed.so').is_file())
sys.path.insert(0,str(P/'support'))
from elf_reader import Elf
from measure import measure
sha=lambda data:hashlib.sha256(data).hexdigest()
def read(path):
 b=path.read_bytes()
 return gzip.decompress(b)if path.suffix=='.gz' else b
def doc(path):return json.loads(read(path))
def source(path):
 with tarfile.open(fileobj=io.BytesIO(path.read_bytes()),mode='r:gz')as a:
  out={}
  for m in a.getmembers():
   if not m.isfile():continue
   assert not Path(m.name).is_absolute() and '..'not in Path(m.name).parts and m.name not in out
   out[m.name]=a.extractfile(m).read()
  return out

def verify(signatures=False,static_only=False):
 manifest=doc(P/'MANIFEST.json')
 files={str(p.relative_to(P)):p for p in P.rglob('*')if p.is_file()and p.name!='MANIFEST.json'and'__pycache__'not in p.parts}
 assert set(manifest)==set(files),'packet membership'
 for name,digest in manifest.items():assert not files[name].is_symlink()and sha(files[name].read_bytes())==digest,name
 for name,digest in doc(P/'repository-inputs.json').items():assert sha((P/'input-snapshots'/name).read_bytes())==digest,name
 original=R/'evidence/original/pump_amm/deployed.so'
 assert sha(original.read_bytes())=='6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
 initial=doc(P/'parent-measurement.json');old_norm={r[0]for r in initial['windows_detail']if r[2]};old_raw={r[0]for r in initial['windows_detail']if r[3]}
 trees={};images={};matched_sets={};raw_sets={}
 with tempfile.TemporaryDirectory(prefix='amm-scanner-verify-')as tmp:
  for label,counts in [('parent',(771,163)),('a',(772,163)),('b',(772,163))]:
   d=P/'builds'/label;r=doc(d/'attempt.json');trees[label]=source(d/'source.tar.gz')
   assert r['returncode']==0 and r['source_unchanged']and r['target_libraries_unchanged']
   assert r['target_libraries_sha256']==doc(P/'target-library-identities.json')
   assert r['builder_sha256']==sha((P/'recorded-controller.py').read_bytes())
   assert r['tool_sha256']['rustc']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
   assert r['tool_sha256']['cargo']=='d28444578306fe5a4f40524331411340123004e9e6556322fcabdbe351fe265d'
   assert {p:sha(b)for p,b in trees[label].items()}==r['source_sha256']
   assert '--locked'in r['command']and'--offline'in r['command']and'sbpf-solana-solana'in r['command']
   log=read(d/'build.log.gz');assert b'Compiling pump-amm-recovered'in log
   images[label]=tuple(read(d/(n+'.gz'))for n in ['candidate.so','unstripped.so'])
   result=doc(d/'score.json');assert sha(images[label][0])==result['candidate_sha256']and sha(images[label][1])==result['unstripped_sha256']
   assert (result['normalized'],result['raw'])==counts
   candidate=Path(tmp)/(label+'.so');candidate.write_bytes(images[label][1]);rows=measure(original,candidate)
   assert rows==result['rows']and (sum(bool(x['match'])for x in rows),sum(x['raw']for x in rows))==counts
   norm={x['original']for x in rows if x['match']};raw={x['original']for x in rows if x['raw']}
   assert not old_norm-norm and not old_raw-raw
   matched_sets[label]=norm;raw_sets[label]=raw
   assert norm-old_norm==({'0xf28b8','0xfb08','0x2288'}if label in ['a','b']else {'0xf28b8','0xfb08'})
   assert result['gains']==sorted(norm-old_norm)and result['losses']==sorted(old_norm-norm)
   if label!='parent':assert raw-old_raw=={'0xf28b8','0xf28a8','0x111360'}
  assert images['a']==images['b'],'repeat ELF equality'
  assert sha(images['parent'][0])=='c2a9b4573c7f236f9d5aa78aa211da499f0ae41b4f13f772fc4ca392c48c0173'
  assert sha(images['parent'][1])=='777449947fbb477c966b1d4d4eaed53b04c51cc08553b1b9daadde241c525437'
  assert trees['a']==trees['b']
  delta=[p for p in trees['a'].keys()|trees['parent'].keys()if trees['a'].get(p)!=trees['parent'].get(p)]
  assert delta==['programs/pump-amm/src/instructions/admin/set_reserved_fee_recipients.rs'],delta
  rel=delta[0];patch=''.join(difflib.unified_diff(trees['parent'][rel].decode().splitlines(True),trees['a'][rel].decode().splitlines(True),fromfile='a/'+rel,tofile='b/'+rel))
  assert patch==(P/'source.patch').read_text()
  assert matched_sets['a']-matched_sets['parent']=={'0x2288'}and matched_sets['parent']<=matched_sets['a']
  assert raw_sets['a']==raw_sets['parent']
  parent=Elf(Path(tmp)/'parent.so');candidate=Elf(Path(tmp)/'a.so');o=Elf(original)
  scanner=next(f for f in candidate.funcs if 'native_transfer_fee19supported_mint_data'in f['name'])
  raw=candidate.b[scanner['start']:scanner['start']+scanner['size']]
  assert scanner['size']==1192 and raw==o.b[0xf28b8:0xf2d60]
  assert sha(raw)=='cd1639db833841b5299e37ae8ba4d5978cc9ee8db1988ebfe8881cd6634c564d'
  assert not candidate.callsites(scanner['start'],scanner['size'])and not candidate.pattern(scanner['start'],scanner['size'])
  def companions(e):
   result={};by=collections.defaultdict(set)
   clean=lambda n:re.sub(r'17h[0-9a-f]{16}E$','',n)
   for f in e.funcs:by[f['start']].add(clean(f['name']))
   for f in e.funcs:
    if 'native_transfer_fee'not in f['name']or'supported_mint_data'in f['name']:continue
    calls=[]
    for c in e.callsites(f['start'],f['size']):calls.append((c['offset'],sorted(by[c['target']])))
    result[clean(f['name'])]=(f['size'],e.normalized[f['start']:f['start']+f['size']],calls,e.pattern(f['start'],f['size']))
   return result
  assert companions(parent)==companions(candidate)and len(companions(candidate))==3
  helper=next(f for f in candidate.funcs if 'collect_hop_fee_flags'in f['name'])
  assert helper['size']==704
  start=helper['start'];assert candidate.normalized[start:start+704]==o.normalized[0xfb08:0xfb08+704]
  assert candidate.b[start:start+700]==o.b[0xfb08:0xfb08+700]
  assert not candidate.pattern(start,704)
  old_calls=o.callsites(0xfb08,704);new_calls=candidate.callsites(start,704)
  assert len(old_calls)==len(new_calls)==1 and old_calls[0]['offset']==new_calls[0]['offset']==696
  target=new_calls[0]['target'];callee=next(f for f in candidate.funcs if f['start']==target and 'handle_error'in f['name'])
  original_target=old_calls[0]['target'];i=o.entries.index(original_target);n=o.entries[i+1]-original_target
  assert n==callee['size']and o.normalized[original_target:original_target+n]==candidate.normalized[target:target+n]
  incoming=[site for site,tgt in candidate.calls.items()if tgt==start]
  assert len(incoming)==1
  assert any(f['start']<=incoming[0]<f['start']+f['size']and '14multi_hop_swap'in f['name']for f in candidate.funcs)
  error_helper=next(f for f in candidate.funcs if 'attach_account_name'in f['name'])
  start=error_helper['start'];assert error_helper['size']==232
  assert candidate.normalized[start:start+232]==o.normalized[0x2288:0x2288+232]
  assert not candidate.pattern(start,232)
  old_calls=o.callsites(0x2288,232);new_calls=candidate.callsites(start,232)
  assert [c['offset']for c in old_calls]==[c['offset']for c in new_calls]==[72,128]
  for old_call,new_call in zip(old_calls,new_calls):
   target=new_call['target'];callee=next(f for f in candidate.funcs if f['start']==target and 'String'in f['name']and 'clone'in f['name'])
   original_target=old_call['target'];i=o.entries.index(original_target);n=o.entries[i+1]-original_target
   assert n==callee['size']and o.normalized[original_target:original_target+n]==candidate.normalized[target:target+n]
  incoming=[site for site,tgt in candidate.calls.items()if tgt==start]
  assert incoming and all(any(f['start']<=site<f['start']+f['size']and 'set_reserved_fee_recipients'in f['name']for f in candidate.funcs)for site in incoming)
 print('Static: 771 -> 772/785; raw 163 unchanged; no losses; error helper and both resolved String clones verified; repeat ELFs identical.')
 if static_only:return
 summary=doc(P/'runtime/summary.json');rows=doc(P/'runtime/progress.json');inputs=doc(P/'runtime/inputs.json')
 candidate_sha=sha(images['a'][0]);original_sha=sha(original.read_bytes())
 assert summary['candidate_sha256']==inputs['candidate_sha256']==candidate_sha
 assert summary['original_sha256']==original_sha and summary['suites']==25 and summary['cases']==17462 and not summary['mismatches']and summary['inputs_unchanged']
 assert summary['replay_driver_sha256']==sha((P/'runtime/recorded-replay-driver.py').read_bytes())
 assert summary['observer_sha256']==sha((P/'input-snapshots/repro/pump_amm/owner6048-v144/runtime/observe_suite.py').read_bytes())
 assert len(rows)==25 and len({x['suite']for x in rows})==25
 if signatures:from solders.transaction import Transaction
 cases=transactions=signature_count=log_differences=0
 for row in rows:
  assert row['returncode']==0 and not row['mismatches'];name=row['suite'];receipt=read(P/'runtime'/(name+'.json.gz'));sidecar=read(P/'runtime'/(name+'-transactions.json.gz'))
  assert sha(receipt)==row['receipt_sha256']and sha((P/'runtime'/(name+'-transactions.json.gz')).read_bytes())==row['sidecar_sha256']
  report=json.loads(receipt);tx=json.loads(sidecar)
  assert report['candidate_sha256']==candidate_sha and report['original_sha256']==original_sha and not report['mismatches']
  assert report['case_count']==len(report['cases'])==row['case_count']
  for case in report['cases']:
   left,right=case['original'],case['candidate'];assert isinstance(left,dict)and isinstance(right,dict)
   assert {k:v for k,v in left.items()if k!='logs'}=={k:v for k,v in right.items()if k!='logs'},(name,'observable state/error/event/CPI mismatch')
   log_differences+=left.get('logs')!=right.get('logs')
   if 'match'in case:assert case['match']is True
   for key in ['diff','mismatched_fields','mismatches']:
    if key in case:assert not case[key]
  script_name=Path(row['command'][3]).name
  assert tx['script_sha256']==summary['harness_sha256']['scripts/'+script_name]
  assert tx['observer_sha256']==summary['observer_sha256']
  assert tx['transaction_count']==len(tx['transactions'])==row['transactions']
  total_signatures=0
  for record in tx['transactions']:
   raw=base64.b64decode(record['transaction_base64'],validate=True);assert sha(raw)==record['transaction_sha256']
   assert record['all_signatures_verified']is True and record['amm_program_sha256']in [candidate_sha,original_sha]
   if signatures:
    transaction=Transaction.from_bytes(raw);checks=transaction.verify_with_results();assert checks and all(checks)and len(checks)==record['signature_count']
   total_signatures+=record['signature_count']
  assert total_signatures==tx['signature_count']==row['signatures']
  cases+=row['case_count'];transactions+=row['transactions'];signature_count+=total_signatures
 assert (cases,transactions,signature_count)==(17462,35074,35418)
 assert (summary['transactions'],summary['signatures'])==(transactions,signature_count)
 negative=doc(P/'negative/cases.json.gz');assert negative['candidate_sha256']==candidate_sha and len(negative['cases'])==5
 for row in negative['cases']:
  assert row['error_equal']and row['original']['error']==row['candidate']['error']
  for label,digest in [('original',original_sha),('candidate',candidate_sha)]:
   result=row[label];assert result['signature_verification']is True and result['sigverify_runtime_enabled']is True and result['executed_program_sha256']==digest
   if signatures:
    checks=Transaction.from_bytes(base64.b64decode(result['transaction_base64'],validate=True)).verify_with_results();assert checks and all(checks)
 print(f'Runtime: {cases} cases; {transactions} transactions; {signature_count} signatures; 0 compared mismatches. Raw ordered logs differ in {log_differences} cases.')
 focused=doc(P/'focused/cases.json.gz');assert focused['candidate_sha256']==candidate_sha and focused['original_sha256']==original_sha
 assert focused['producer_sha256']==sha((P/'focused/producer.py').read_bytes())
 for name,digest in focused['harness_sha256'].items():assert sha((P/'input-snapshots'/name).read_bytes())==digest
 assert focused['case_count']==len(focused['cases'])==16 and not focused['mismatches']
 assert {(c['kind'],c['index'])for c in focused['cases']}=={(kind,i)for kind in ['executable','rent']for i in range(8)}
 focused_signatures=0
 for case in focused['cases']:
  assert case['match']is True and not case['mismatched_fields']
  expected_error=2007 if case['kind']=='executable'else 2005
  assert case['expected_error']==expected_error
  for label in ['original','candidate']:
   result=case[label];assert f'Custom({expected_error})'in result['error']
   logs=[line for line in result['logs']if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units',line)]
   assert logs==result['compared_logs']and any(f"reserved_fee_recipients[{case['index']}]"in line for line in logs)
   raw=base64.b64decode(result['transaction_base64'],validate=True);assert sha(raw)==result['transaction_sha256']
   if signatures:
    checks=Transaction.from_bytes(raw).verify_with_results();assert checks and all(checks)and len(checks)==result['signature_count']
   focused_signatures+=result['signature_count']
  assert all(case['original'][key]==case['candidate'][key]for key in ['error','state_hex','events','compared_logs'])
 assert focused_signatures==focused['signature_count']==32 and focused['transaction_count']==32
 print('Focused account-name diagnostics: 16 pairs / 32 signed executions, all non-metered logs equal.')
 print('Five incentive error-order pairs pass. Whole ELF identity and exhaustive behavior remain open.')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--signatures',action='store_true');p.add_argument('--static-only',action='store_true');a=p.parse_args();verify(a.signatures,a.static_only)
