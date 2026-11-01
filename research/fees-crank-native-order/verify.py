"""Verify a bounded native-flow gain while requiring all raw-log failures to remain visible."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,difflib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(gzip.decompress(p.read_bytes())if p.suffix=='.gz'else p.read_bytes())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def summary_checks(label,r):
 assert r['cases']==304 and not r['nonlog_mismatch_indices']
 a=module('native_trace_domain',HERE/'analyze.py');traces=[i for i,c in enumerate(a.cases())if 'token_amount'not in c or(c['flags']==0 and((c.get('quote')=='So11111111111111111111111111111111111111112'and c['amount']>0)or c.get('token_amount',0)>0))];assert r['nonempty_inner_trace_indices']==traces and len(traces)==26
 expected=0 if label in ['control','messages']else 292
 assert r['raw_equal']==expected and len(r['application_log_mismatch_indices'])==(292 if label=='control'else 0)
 assert len(r['compute_only_mismatch_indices'])==(304 if label=='messages'else 12)
 if label in ['deferred','origins']:
  a=module('native_matrix_domain',HERE/'analyze.py');indices=[i for i,c in enumerate(a.cases())if c['flags']==0 and((c.get('quote')=='So11111111111111111111111111111111111111112'and(c['amount']>0 or c.get('token_amount',0)>0))or(c.get('quote')=='5842jNQd5C7pWXFxcDu3kQ5XtgqH5st25tf2ZBjYaKg8'and c.get('token_amount',0)>0))];assert r['raw_mismatch_indices']==r['compute_only_mismatch_indices']==indices and len(indices)==12
def main():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and'__pycache__'not in p.parts}
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parentraw=(HERE/'parent-experiment.json').read_bytes();assert sha(parentraw)==e['parent_experiment_sha256'];parent=json.loads(parentraw)['variants']['origins'];base=e['variants']['control'];assert base['input_sha256']==parent['input_sha256']and e['control_build_reused']and e['control_runtime_reused']and e['diagnostic_overlap_pr']==197
 assert all(base['files'][k][field]==parent['files'][k][field]for k in ['candidate','symbols']for field in ['sha256','bytes'])
 sources={};name='programs/pump-fees/src/donation.rs'
 for label,v in e['variants'].items():
  assert len(v['input_sha256'])==42 and v['input_sha256'].keys()==v['source_paths'].keys()
  for n,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][n]).read_bytes())==h,n
  sources[label]=(ROOT/v['source_paths'][name]).read_text()
  for k,d in v['files'].items():
   raw=gzip.decompress((HERE/d['path']).read_bytes());assert len(raw)==d['bytes']and sha(raw)==d['sha256']
  if label=='control':continue
  assert {n for n,h in v['input_sha256'].items()if h!=base['input_sha256'][n]}=={name}
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes();assert launch['input_sha256']==result['input_sha256']==v['input_sha256']and result['exit_code']==result['strip_exit_code']==0 and result['source_unchanged']
  assert log.count(b'--crate-name pump_fees_candidate ')==1 and b'Finished `release` profile'in log and b'-Zremap-cwd-prefix='in log
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and'sbpf-solana-solana'in launch['command']and sum(s.startswith('--remap-path-prefix=')for s in launch['command'])==3
  assert v['strip_replay']['exit_code']==0 and v['strip_replay']['sha256']==v['files']['candidate']['sha256']
 a=sources['control'];b=sources['messages'];assert a.replace('require!(ctx.accounts.fee_program_global.disable_flags & 8 == 0, FeeError::FeatureDeactivated);','if ctx.accounts.fee_program_global.disable_flags & 8 != 0 { msg!("CrankDonationFeePda is currently disabled"); return Err(FeeError::FeatureDeactivated.into()); }').replace('if amount==0{return Ok(());}','if amount==0{msg!("Nothing to donate");return Ok(());}')==b
 assert sources['origins']==sources['deferred'].replace('ok_or(error!(FeeError::ShareCalculationOverflow))?','ok_or(FeeError::ShareCalculationOverflow)?')
 for label,text in sources.items():
  before,rest=text.split('pub fn crank(',1);body,after=rest.split('pub fn create(',1);x,y=sources['control'].split('pub fn crank(',1);old,z=y.split('pub fn create(',1);assert before==x and after==z and body.count('\n')==old.count('\n')
 patch=''.join(difflib.unified_diff(sources['control'].splitlines(True),sources['origins'].splitlines(True),fromfile='a/'+name,tofile='b/'+name,n=0));assert patch==(HERE/'native-flow.patch').read_text()
 harness=load(ROOT/e['parent_packet']/'harness-sha256.json');assert len(harness)==187 and set(harness)=={str(p.relative_to(ROOT))for p in(ROOT/'scripts').glob('*.py')}
 for n,h in harness.items():assert sha((ROOT/n).read_bytes())==h
 analyzer=module('native_measured',HERE/'analyze.py');r=analyzer.analyze();assert r==load(HERE/'analysis.json.gz')and r['body_coverage_delta']==dict(added=[],lost=[])and r['raw_coverage_delta']==dict(added=[],lost=[])and r['direct_edges']==3249
 for label,v in r['variants'].items():
  assert len(v['unique_pairs'])==405 and len(v['unmatched_original'])==33 and v['candidate_windows']==591 and v['unique_raw_pairs']==64 and v['normalized']==552 and len(v['raw_originals'])==118 and not v['equals_original_capture']and not v['equals_original_elf_extent'];summary_checks(label,r['strict'][label]);assert r['open_business_edge'][label]['still_unequal']
  msg=r['details'][label]['messages'];assert all(len(x)>0 for x in msg.values())if label!='control'else all(not x for x in msg.values())
  assert r['open_business_edge'][label]['changed']==([]if label=='control'else[[656832,464]])
 assert r['decoder']['message']=='failed to fill whole buffer'and r['relay']['address_error']==3007 and len(r['slice_contract']['locations'])==4
 tool=load(HERE/'toolchain.json');assert tool['rustc']['sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and tool['strip']['sha256']=='673b3b86f0b1b8eadd755e29e2f66a7582248ef3bda7a267fbb370b733c1cb69'and tool['target']=='sbpf-solana-solana'
 signatures=load(HERE/'checks/signatures.json');assert signatures['solders']=='0.27.1'and signatures['transaction_records_verified']==2432 and len(signatures['unique_transaction_sha256'])==2 and signatures['receipt_sha256']=={label:sha((HERE/f'receipts/{label}-crank.json.gz').read_bytes())for label in e['variants']}
 original='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
 for label in ['control','deferred','origins']:
  candidate=e['variants'][label]['files']['candidate']['sha256'];p=ROOT/e['control_receipts']['full']if label=='control'else HERE/f'receipts/{label}-full.json.gz';f=load(p);assert f['original_sha256']==original and f['candidate_sha256']==candidate and f['case_count']==17331 and len(f['suites'])==18 and not f['mismatches'];assert all(s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))for s in f['suites'].values())
  p=ROOT/e['control_receipts']['flags']if label=='control'else HERE/f'receipts/{label}-flags.json.gz';f=load(p);assert f['original_sha256']==original and f['candidate_sha256']==candidate and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
 candidate=e['variants']['origins']['files']['candidate']['sha256']
 for name,count in [('precedence',24),('optional',32),('seeds',20),('logs',8),('mint',30),('relay',16)]:
  f=load(HERE/f'receipts/origins-{name}.json.gz');assert f['original_sha256']==original and f['candidate_sha256']==candidate and f['case_count']==len(f['cases'])==count and not f['mismatches']and all(x['match']and all(x['original'][k]==x['candidate'][k]for k in f['fields'])for x in f['cases'])
 f=load(HERE/'receipts/origins-social.json.gz');assert f['original_sha256']==original and f['candidate_sha256']==candidate and len(f['cases'])==157 and not f['mismatches']and all(x['match']and x['original']==x['candidate']for x in f['cases'])
 for label,v in e['variants'].items():
  f=load(HERE/f'receipts/{label}-crank.json.gz');assert f['original_sha256']==original and f['candidate_sha256']==v['files']['candidate']['sha256']
 raw=module('native_raw',HERE/'raw_compare.py').compare();assert raw==load(HERE/'raw-comparisons.json')and all(not x['capture_equal']and not x['elf_extent_equal']for x in raw.values())
 print('PASS:405pairs preserved;292/304 raw strict cases agree,12 compute-log failures retained;all application messages and nonlog fields agree;fresh regressions;whole0/4')
if __name__=='__main__':main()
