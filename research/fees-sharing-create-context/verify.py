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

def expected_source(source,label):
 changes={'control':(False,[]),'global_inline':(True,[]),'events':(False,['event_authority','pump_event_authority']),'inline_event':(True,['event_authority']),'inline_pump_event':(True,['pump_event_authority']),'origins':(True,['event_authority','pump_event_authority'])};inline,fields=changes[label]
 if inline:
  before="pub global:Box<Account<'info,pump_global::Global>>";assert source.count(before)==1;source=source.replace(before,"pub global:Account<'info,pump_global::Global>")
 for field in fields:
  before=f"pub {field}:UncheckedAccount<'info>";assert source.count(before)==1;source=source.replace(before,f"pub {field}:AccountInfo<'info>")
 return source

def main():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 harness=load(HERE/'harness-sha256.json');assert len(harness)==187 and set(harness)=={str(p.relative_to(ROOT))for p in (ROOT/'scripts').glob('*.py')}
 for n,h in harness.items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parentraw=(HERE/'parent-experiment.json').read_bytes();assert sha(parentraw)==e['parent_experiment_sha256'];parent=load(HERE/'parent-experiment.json')['variants']['origins'];base=e['variants']['control'];assert base['input_sha256']==parent['input_sha256']and e['control_runtime_reused']and e['control_build_reused']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['files'][kind][k]for k in ['sha256','bytes'])
 name='programs/pump-fees/src/instructions/fee_sharing/create_fee_sharing_config.rs';old=(HERE/base['source_paths'][name]).read_text();program="pub program:Program<'info,crate::program::PumpFeesCandidate>"
 assert old.count(program)==1
 for label,v in e['variants'].items():
  assert len(v['input_sha256'])==36 and set(v['input_sha256'])==set(v['source_paths'])
  for n,h in v['input_sha256'].items():assert sha((HERE/v['source_paths'][n]).read_bytes())==h,n
  changed={n for n,h in base['input_sha256'].items()if v['input_sha256'][n]!=h};assert changed==({name}if label!='control'else set())
  source=(HERE/v['source_paths'][name]).read_text();assert source==expected_source(old,label)and source.count(program)==1
  for kind,d in v['files'].items():
   b=gzip.decompress((HERE/d['path']).read_bytes());assert len(b)==d['bytes']and sha(b)==d['sha256']
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes();assert launch['input_sha256']==result['input_sha256']==v['input_sha256']and result['exit_code']==result['strip_exit_code']==0 and result['source_unchanged'];assert log.count(b'--crate-name pump_fees_candidate ')==1 and b'-Zremap-cwd-prefix='in log and b'Finished `release` profile'in log
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']and sum(x.startswith('--remap-path-prefix=')for x in launch['command'])==3
  assert v['strip_replay']['exit_code']==0 and v['strip_replay']['sha256']==v['files']['candidate']['sha256']
 r=module('sharing_storage_analysis',HERE/'analyze.py').analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 for label,row in r['variants'].items():
  assert len(row['unique_pairs'])==(399 if label=='origins'else 396)and len(row['unmatched_original'])==(39 if label=='origins'else 42)and row['candidate_windows']==588 and row['unique_raw_pairs']==64 and not row['equals_original_capture']and not row['equals_original_elf_extent']
  if label!='control':assert r['deltas'][label]==dict(added=[445160,464168,639104]if label=='origins'else[],lost=[])and r['raw_deltas'][label]==dict(added=[],lost=[])
 details={d['original']['address']:d for d in r['details']};assert [(details[k]['original']['bytes'],len(details[k]['calls']))for k in [445160,464168,639104]]==[(11016,87),(3000,37),(1360,5)]
 assert all(c['equal']for k,d in details.items()if k!=639104 for c in d['calls'])and [(c['offset'],c['original']['target'])for c in details[639104]['calls']if not c['equal']]==[(440,177720)]
 for d in r['data_contracts'].values():assert d['original']==d['candidate']
 m=module('sharing_storage_data',HERE/'analyze.py');assert sum(len(v)for v in m.RANGES.values())==29
 for address,rows in r['data_contracts'].items():
  for row in rows['original']['literals']:assert bytes.fromhex(row['value']).decode()==m.RANGES[int(address)][row['offset']]
 assert r['data_contracts']['464168']['original']['owner_ids']==['0c35ffa9055a8e568da8f7bc075615274cf1c92ca41f40009c516aa414c27c70','0156e0f693665acf44db1568bf175baa5189cb97f5d2ff3b655d2bb6fd6d18b0','0c14defc825ec67694250818bb654065f4298d3156d571b4d4f8090c18e9a863']
 assert len(r['preserved_slice_contract']['locations'])==4 and len(r['preserved_common_locations'])==2 and r['preserved_relay']['address_error']==3007 and r['preserved_relay']['executable_error']==2007
 assert r['preserved_decoder']['owner_ids']==['00'*32,'0c35ffa9055a8e568da8f7bc075615274cf1c92ca41f40009c516aa414c27c70']and r['preserved_decoder']['message_record']['message']=='failed to fill whole buffer'
 for label in ['control','origins']:
  candidate=e['variants'][label]['files']['candidate']['sha256'];original='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e';full=receipt(label+'-full');assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
  for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
  f=receipt(label+'-flags');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
  assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
  for n,count in [('precedence',24),('optional',32),('seeds',20),('logs',8),('mint',30)]:
   z=receipt(label+'-'+n);assert z['candidate_sha256']==candidate and z['original_sha256']==original and z['case_count']==len(z['cases'])==count and not z['mismatches'];assert all(x['match']and all(x['original'][k]==x['candidate'][k]for k in z['fields'])for x in z['cases'])
  z=receipt(label+'-relay');assert z['candidate_sha256']==candidate and z['original_sha256']==original;check_relay(z)
 raw=module('sharing_raw',HERE/'raw_compare.py').compare();assert raw==load(HERE/'raw-comparisons.json')and all(not x['capture_equal']and not x['elf_extent_equal']for x in raw.values())
 print('PASS: 3 complete context bodies; 124 parser/exit call bindings, dispatch 4/5; 29 literals+3 owner IDs; 399 unique/39 unmatched; fresh scoped regressions; whole0/4')
if __name__=='__main__':main()
