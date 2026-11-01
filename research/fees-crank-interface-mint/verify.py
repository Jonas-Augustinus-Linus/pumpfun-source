"""Verify mint-type recovery, exact source changes, body matches and bounded replay."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_text())
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def receipt(n):return json.loads(gzip.decompress((HERE/f'receipts/{n}.json.gz').read_bytes()))
def main():
 manifest=load(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert actual==set(manifest)
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json');base=e['variants']['control'];assert e['control_reused']
 assert base['input_sha256']==parent['variants']['origins']['input_sha256']and base['source_paths']==parent['variants']['origins']['source_paths']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['variants']['origins']['files'][kind][k]for k in ['sha256','bytes'])
 changed='programs/pump-fees/src/donation.rs';old=(ROOT/base['source_paths'][changed]).read_text();before="pub quote_mint:Account<'info,anchor_spl::token::Mint>";assert old.count(before)==1
 for label,v in e['variants'].items():
  assert len(v['input_sha256'])==35 and set(v['input_sha256'])==set(v['source_paths'])
  for n,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][n]).read_bytes())==h,n
  if label=='control':continue
  assert {n for n,h in base['input_sha256'].items()if v['input_sha256'][n]!=h}=={changed}
  after="pub quote_mint:Box<Account<'info,anchor_spl::token::Mint>>"if label=='legacy'else"pub quote_mint:Box<InterfaceAccount<'info,anchor_spl::token_interface::Mint>>"
  assert (ROOT/v['source_paths'][changed]).read_text()==old.replace(before,after)
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['inputs']==v['input_sha256']and result['source_unchanged']and result['exit_code']==0 and result['compiled_root']
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
  assert 'sbpf-solana-solana'in launch['command']and 'RUSTFLAGS=-Zremap-cwd-prefix='in launch['command']and log.count(b'--crate-name pump_fees_candidate ')==1 and sha(log)==result['log_sha256']
  for kind in ['candidate','symbols']:assert result[kind+'_sha256']==v['files'][kind]['sha256']
 a=module('crank_mint_analysis',HERE/'analyze.py');r=a.analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 assert r['delta']==dict(added_original_windows=[9880],lost_original_windows=[])
 assert r['unique_delta']==dict(added_original_windows=[640,9880,693080],lost_original_windows=[])
 assert r['raw_delta']==dict(added_original_windows=[],lost_original_windows=[])
 for name,u,left in [('control',372,64),('legacy',372,64),('origins',375,63)]:
  row=r['variants'][name];assert len(row['unique_pairs'])==u and len(row['unmatched_original'])==left and not row['equals_original_capture']and not row['equals_original_elf_extent']
 t=r['targets'][0];assert len(r['targets'])==1 and t['original']['bytes']==352 and not t['raw_equal']
 assert set(t['raw_difference_offsets'])<=set(range(28,32))|set(range(220,224))|set(range(324,328))
 assert len(t['calls'])==3 and all(c['equal']for c in t['calls'])
 assert all(len(x['recovered_target_calls'])==1 for x in r['callers'])and r['callers'][0]['window']['signature']!=r['callers'][1]['window']['signature']
 candidate=e['variants']['origins']['files']['candidate']['sha256'];original=sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes())
 full=receipt('origins-full');assert full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']and full['candidate_sha256']==candidate and full['original_sha256']==original
 for suite in full['suites'].values():assert suite['candidate_sha256']==candidate and suite['original_sha256']==original and not suite.get('mismatches',suite.get('failures',[]))
 flags=receipt('origins-flags');assert flags['candidate_sha256']==candidate and flags['original_sha256']==original and flags['case_count']==len(flags['cases'])==1542 and not flags['failures']and not flags['compute_differences']and all(x['original']==x['candidate']for x in flags['cases'])
 assert {(x['cap'],x['pool'],x['flag_hex'])for x in flags['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
 for name,path,fn in [('precedence','fees-exotic-growth-precedence/verify.py','check_boundary'),('optional','fees-optional-account-ownership/optional_cases.py','validate'),('seeds','fees-social-seed-vector/seed_cases.py','validate'),('logs','fees-extend-size-logs/log_cases.py','validate')]:
  row=receipt('origins-'+name);assert row['candidate_sha256']==candidate and row['original_sha256']==original;assert not getattr(module('check_'+name,ROOT/'research'/path),fn)(row)
 mint=module('mint_cases',HERE/'mint_cases.py')
 for label in ['control','legacy','origins']:
  row=receipt(label+'-mint');assert row['candidate_sha256']==e['variants'][label]['files']['candidate']['sha256']and row['original_sha256']==original
  assert mint.validate(row)==([]if label=='origins'else[5,6,7,8,9,20,21,22,23,24])
 print('PASS: boxed interface mint; one new body, two unique attributions; 375 pairs / 63 residuals; 30 mint cases and all regressions')
if __name__=='__main__':main()
