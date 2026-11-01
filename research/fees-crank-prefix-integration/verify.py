"""Verify a new combined artifact without retagging either parent's receipts."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_text())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def receipt(label,name,e):
 path=e.get('runtime_receipts',{}).get(label,{}).get(name)
 return json.loads(gzip.decompress((ROOT/path if path else HERE/f'receipts/{label}-{name}.json.gz').read_bytes()))
def main():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}
 for n,h in manifest.items():assert sha((HERE/n).read_bytes())==h,n
 for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']['packet']/'experiment.json')['variants']['origins'];prior=load(ROOT/e['prior_relay']['packet']/'experiment.json')['variants']['origins'];base=e['variants']['control'];proposal=e['variants']['origins']
 assert sha((ROOT/e['parent']['packet']/'experiment.json').read_bytes())==e['parent']['experiment_sha256']and sha((ROOT/e['prior_relay']['packet']/'experiment.json').read_bytes())==e['prior_relay']['experiment_sha256']
 assert base['input_sha256']==parent['input_sha256']and base['source_paths']==parent['source_paths']and e['control_runtime_reused']and e['proposal_runtime_fresh']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['files'][kind][k]for k in ['sha256','bytes'])
 name='programs/pump-fees/src/donation.rs';assert {n for n,h in base['input_sha256'].items()if proposal['input_sha256'][n]!=h}=={name}
 for n,h in proposal['input_sha256'].items():assert h==(base['input_sha256'][n]if n!=name else prior['input_sha256'][n])
 assert {n for n,h in prior['input_sha256'].items()if proposal['input_sha256'][n]!=h}=={'programs/pump-fees/src/types.rs'}
 for label,v in e['variants'].items():
  assert len(v['input_sha256'])==36 and set(v['input_sha256'])==set(v['source_paths'])
  for n,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][n]).read_bytes())==h,n
  for k,d in v['files'].items():
   raw=gzip.decompress((HERE/d['path']).read_bytes());assert len(raw)==d['bytes']and sha(raw)==d['sha256']
 old=(ROOT/base['source_paths'][name]).read_bytes();new=(ROOT/proposal['source_paths'][name]).read_bytes();before=b'#[account(executable,address=RELAY)]pub donation_relay_program';after=b'#[account(executable,address=RELAY @ anchor_lang::error::ErrorCode::AccountOwnedByWrongProgram)]pub donation_relay_program';assert old.count(before)==1 and new==old.replace(before,after)
 launch=load(HERE/'builds/origins-launch.json');result=load(HERE/'builds/origins-result.json');log=(HERE/'builds/origins-build.log').read_bytes();assert launch['input_sha256']==result['input_sha256']==proposal['input_sha256']and result['exit_code']==result['strip_exit_code']==0 and result['source_unchanged'];assert log.count(b'--crate-name pump_fees_candidate ')==1 and b'-Zremap-cwd-prefix='in log and b'Finished `release` profile'in log
 assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']and sum(x.startswith('--remap-path-prefix=')for x in launch['command'])==3
 assert e['strip_replay']['exit_code']==0 and e['strip_replay']['sha256']==proposal['files']['candidate']['sha256']
 oldcheck=module('joint_receipts',ROOT/e['prior_relay']['packet']/'verify.py');harness=load(ROOT/e['prior_relay']['packet']/'harness-sha256.json');assert len(harness)==187 and set(harness)=={str(p.relative_to(ROOT))for p in (ROOT/'scripts').glob('*.py')}
 for n,h in harness.items():assert sha((ROOT/n).read_bytes())==h
 r=module('joint_analysis',HERE/'analyze.py').analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 assert r['union']==dict(control_unique=395,relay_unique=395,combined_unique=396,only_added_to_control=[408640],only_added_to_relay=[18384],lost_from_either=[])
 assert r['raw_delta']==dict(added=[],lost=[])and len(r['symbol_delta'])==2 and [x[1:]for x in r['symbol_delta']]==[[220,191],[7,11]]
 for label,count,left in [('control',395,43),('origins',396,42)]:
  row=r['variants'][label];assert len(row['unique_pairs'])==count and len(row['unmatched_original'])==left and row['candidate_windows']==588 and row['unique_raw_pairs']==64 and not row['equals_original_capture']and not row['equals_original_elf_extent']
  for address in [408640,18384,302032,257264,36072]:assert all(x['equal']for x in r['direct_calls'][label+':'+str(address)])
  assert len(r['direct_calls'][label+':408640'])==98 and len(r['direct_calls'][label+':18384'])==11
  data=r['decoder_data'][label];assert data['owner_constants']==['00'*32,'0c35ffa9055a8e568da8f7bc075615274cf1c92ca41f40009c516aa414c27c70'];record=data['message_record'];assert record['message']=='failed to fill whole buffer'and record['length']==27 and record['tail']==37 and record['relocation_info']==8
  candidate=e['variants'][label]['files']['candidate']['sha256'];original='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e';full=receipt(label,'full',e);assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
  for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
  f=receipt(label,'flags',e);assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
  assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
  for name,count in [('precedence',24),('optional',32),('seeds',20),('logs',8),('mint',30)]:
   z=receipt(label,name,e);assert z['candidate_sha256']==candidate and z['original_sha256']==original and z['case_count']==len(z['cases'])==count and not z['mismatches'];assert all(x['match']and all(x['original'][k]==x['candidate'][k]for k in z['fields'])for x in z['cases'])
  z=receipt(label,'relay',e);assert z['candidate_sha256']==candidate and z['original_sha256']==original;oldcheck.check_relay(z,negative=label=='control')
 actual=r['contracts']['origins'];wanted=r['contracts']['original'];assert actual|dict(address_comparison_call=wanted['address_comparison_call'])==wanted and actual['address_error']==3007 and actual['executable_error']==2007
 assert len(r['preserved_slice_contract']['locations'])==4 and len(r['preserved_common_locations'])==2
 raw=module('joint_raw',HERE/'raw_compare.py').compare();assert raw==load(HERE/'raw-comparisons.json')and all(not x['capture_equal']and not x['elf_extent_equal']for x in raw.values())
 print('PASS: combined 396 unique /42 unmatched; exact union of both parent body sets; parser and decoder call/data contracts; fresh scoped regressions; whole identity 0/4')
if __name__=='__main__':main()
