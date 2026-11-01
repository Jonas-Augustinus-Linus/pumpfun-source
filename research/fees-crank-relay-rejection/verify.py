"""Verify exact source/build bindings and complete crank parser recovery."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_text())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def receipt(n):return json.loads(gzip.decompress((HERE/f'receipts/{n}.json.gz').read_bytes()))
def check_relay(r,negative=False):
 fields=['error','before','after','inner','events'];assert r['fields']==fields and r['case_count']==len(r['cases'])==16
 import itertools
 expected=[dict(name=f'{key}-{executable}-{amount}-{ata}',key=key,executable=executable,amount=amount,ata=ata)for key,executable,amount,ata in itertools.product(['canonical','wrong'],[False,True],[0,1],[False,True])]
 assert [x['case']for x in r['cases']]==expected
 bad=[]
 for i,x in enumerate(r['cases']):
  c=x['case'];error=2007 if not c['executable']else 3007 if c['key']=='wrong'else None
  expected_error=lambda number:f'TransactionErrorInstructionError((1, Tagged(InstructionErrorCustom({number}))))'if number is not None else None
  assert x['original']['error']==expected_error(error)
  assert x['candidate']['error']==expected_error(2012 if negative and error==3007 else error)
  for side in ['original','candidate']:
   z=x[side];assert z['relay_account']['executable']==c['executable']
   assert z['relay_account']['key']==('RLAYHr9TRFcKB2ubYQhspcnXiaGpaVzNQvHytt47RZu'if c['key']=='canonical'else r['wrong_public_key'])
   assert z['events']==[l for l in z['logs']if l.startswith('Program data:')]
  assert x['original']['relay_account']==x['candidate']['relay_account']
  same=all(x['original'][k]==x['candidate'][k]for k in fields);assert same==x['match']
  if not same:bad.append(i)
 assert bad==r['mismatches']==([12,13,14,15]if negative else[])
 return bad

def main():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 harness=load(HERE/'harness-sha256.json');assert len(harness)==187 and set(harness)=={str(p.relative_to(ROOT))for p in (ROOT/'scripts').glob('*.py')}
 for n,h in harness.items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parentraw=(ROOT/e['parent']['packet']/'experiment.json').read_bytes();assert sha(parentraw)==e['parent']['experiment_sha256'];parent=json.loads(parentraw)['variants']['origins'];base=e['variants']['control'];assert base['input_sha256']==parent['input_sha256']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['files'][kind][k]for k in ['sha256','bytes'])
 for label,v in e['variants'].items():
  assert len(v['input_sha256'])==36 and set(v['source_paths'])==set(v['input_sha256'])
  for n,h in v['input_sha256'].items():assert sha((HERE/v['source_paths'][n]).read_bytes())==h,n
  for kind,d in v['files'].items():
   b=gzip.decompress((HERE/d['path']).read_bytes());assert len(b)==d['bytes']and sha(b)==d['sha256']
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['input_sha256']==result['input_sha256']==v['input_sha256']and result['source_unchanged']and result['exit_code']==result['strip_exit_code']==0
  assert b'-Zremap-cwd-prefix='in log
  assert log.count(b'--crate-name pump_fees_candidate ')==1 and b'Finished `release` profile'in log
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
  command=launch['command'];assert 'sbpf-solana-solana'in command and command.count('--remap-path-prefix=programs/pump-fees/src/../../../pump-fees-math/=pump-fees-math/')==1 and sum(x.startswith('--remap-path-prefix=')for x in command)==3
  assert v['strip_replay']['exit_code']==0 and v['strip_replay']['sha256']==v['files']['candidate']['sha256']
 name=e['source_edit']['path'];old=(HERE/base['source_paths'][name]).read_bytes();new=(HERE/e['variants']['origins']['source_paths'][name]).read_bytes();assert old.count(e['source_edit']['before'].encode())==1 and new==old.replace(e['source_edit']['before'].encode(),e['source_edit']['after'].encode())
 assert {n for n,h in base['input_sha256'].items()if e['variants']['origins']['input_sha256'][n]!=h}=={name}
 m=module('relay_analysis',HERE/'analyze.py');r=m.analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 assert len(r['symbol_artifact_delta'])==2 and [x[1:]for x in r['symbol_artifact_delta']]==[[220,191],[7,11]]
 assert r['delta']==dict(added_original_windows=[408640],lost_original_windows=[])and r['raw_delta']==dict(added_original_windows=[],lost_original_windows=[])
 for label,count,left in [('control',394,44),('origins',395,43)]:
  z=r['variants'][label];assert len(z['unique_pairs'])==count and len(z['unmatched_original'])==left and z['candidate_windows']==588 and z['unique_raw_pairs']==64 and not z['equals_original_capture']and not z['equals_original_elf_extent']
  assert len(r['direct_calls'][label])==98 and sum(x['original']['kind']=='local'for x in r['direct_calls'][label])==97 and all(x['equal']for x in r['direct_calls'][label])
 original=r['contracts']['original'];assert original==r['contracts']['origins']|dict(address_comparison_call=original['address_comparison_call'])
 assert original['address_error']==3007 and original['executable_error']==2007
 alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';number=0
 for c in 'RLAYHr9TRFcKB2ubYQhspcnXiaGpaVzNQvHytt47RZu':number=number*58+alphabet.index(c)
 assert original['relay_id']==number.to_bytes(32,'big').hex()
 assert r['contracts']['control']|dict(address_error=3007,address_comparison_call=original['address_comparison_call'])==original
 assert len(original['selected_data'])==35
 for item in original['selected_data']:assert bytes.fromhex(item['value']).decode()==m.RANGES[item['offset']]
 assert len(r['preserved_slice_contract']['locations'])==4 and len(r['preserved_common_locations'])==2 and r['preserved_buyback_origin']==dict(path='programs/pump-fees/src/instructions/buyback/mod.rs',line=12,error=4101)
 for label,v in e['variants'].items():
  candidate=v['files']['candidate']['sha256'];original=e['original_sha256'];full=receipt(label+'-full');assert full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']and full['candidate_sha256']==candidate and full['original_sha256']==original
  for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
  f=receipt(label+'-flags');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
  assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
  for name,count in [('precedence',24),('optional',32),('seeds',20),('logs',8),('mint',30)]:
   z=receipt(label+'-'+name);assert z['candidate_sha256']==candidate and z['original_sha256']==original and z['case_count']==len(z['cases'])==count and not z['mismatches']
   for x in z['cases']:assert x['match']and all(x['original'][k]==x['candidate'][k]for k in z['fields'])
  z=receipt(label+'-relay');assert z['candidate_sha256']==candidate and z['original_sha256']==original;check_relay(z,negative=label=='control')
 assert e['control_runtime_reused_from']==e['parent']['packet']and e['proposal_runtime_fresh']
 raw=module('relay_raw',HERE/'raw_compare.py').compare();assert raw==load(HERE/'raw-comparisons.json')and all(not x['capture_equal']and not x['elf_extent_equal']for x in raw.values())
 print('PASS: 10,872-byte parser; 97 local callees + one import; 35 literal ranges; 395 unique/43 unmatched; signed rejection fix and fresh regressions; 0/4 whole binaries')
if __name__=='__main__':main()
