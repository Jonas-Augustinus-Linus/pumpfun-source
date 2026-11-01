"""Verify the common helper source controls, exact bodies, locations and replay."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_text())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def receipt(n):return json.loads(gzip.decompress((HERE/f'receipts/{n}.json.gz').read_bytes()))
def main():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json');base=e['variants']['control'];assert e['control_reused']and base['input_sha256']==parent['variants']['origins']['input_sha256']and base['source_paths']==parent['variants']['origins']['source_paths']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['variants']['origins']['files'][kind][k]for k in ['sha256','bytes'])
 common='programs/pump-fees/src/common/mod.rs';root='programs/pump-fees/src/lib.rs';sharing='programs/pump-fees/src/sharing_update.rs'
 oldroot=(ROOT/base['source_paths'][root]).read_text();oldshare=(ROOT/base['source_paths'][sharing]).read_text();a=oldshare.index('fn legacy_curve_quote_is_zero(');b=oldshare.index('\nfn authorize',a);block=oldshare[a:b];expected_share=(oldshare[:a]+'\n'*block.count('\n')+oldshare[b:]).replace('legacy_curve_quote_is_zero(','crate::common::legacy_curve_quote_is_zero(')
 expressions={'array':'Ok(Pubkey::new_from_array(bonding_curve.data.borrow()[83..115].try_into().unwrap()) == Pubkey::default())','tryfrom':'Ok(Pubkey::try_from(&bonding_curve.data.borrow()[83..115]).unwrap() == Pubkey::default())','origins':'Ok(Pubkey::try_from_slice(&bonding_curve.data.borrow()[83..115])? == Pubkey::default())'}
 for label,v in e['variants'].items():
  assert len(v['input_sha256'])==(35 if label=='control'else 36)and set(v['source_paths'])==set(v['input_sha256'])
  for n,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][n]).read_bytes())==h,n
  if label=='control':continue
  assert {n for n,h in v['input_sha256'].items()if base['input_sha256'].get(n)!=h}=={common,root,sharing}
  assert (ROOT/v['source_paths'][root]).read_text()==oldroot.replace('mod sharing_update;','mod sharing_update; mod common;')
  assert (ROOT/v['source_paths'][sharing]).read_text()==expected_share
  line=expressions[label];line=' '*(48-(line.index('borrow')+1))+line;lines=['use anchor_lang::prelude::*;']+['']*15+['#[inline(never)]',"pub fn legacy_curve_quote_is_zero(bonding_curve: &AccountInfo<'_>) -> Result<bool> {",'    if bonding_curve.data_len() < 115 { return Ok(true); }','',line,'}']
  assert (ROOT/v['source_paths'][common]).read_text()=='\n'.join(lines)+'\n'
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['inputs']==v['input_sha256']and result['compiled_root']and result['source_unchanged']and result['exit_code']==0 and sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']
  for kind in ['candidate','symbols']:assert result[kind+'_sha256']==v['files'][kind]['sha256']
 for kind in ['candidate','symbols']:assert e['variants']['array']['files'][kind]['sha256']==e['variants']['tryfrom']['files'][kind]['sha256']
 r=module('common_helper_analysis',HERE/'analyze.py').analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 assert r['delta']==dict(added_original_windows=[75880],lost_original_windows=[])
 for label,u,left in [('control',375,63),('array',375,63),('tryfrom',375,63),('origins',376,62)]:
  row=r['variants'][label];assert len(row['unique_pairs'])==u and len(row['unmatched_original'])==left and not row['equals_original_capture']and not row['equals_original_elf_extent']
 for label in ['array','tryfrom']:assert r['details'][label]['window']['bytes']==432 and not r['details'][label]['matches']
 d=r['details']['origins'];assert d['matches']and d['window']['bytes']==504 and len(d['calls'])==4 and all(c['equal']for c in d['calls'])and len(d['incoming_calls'])==2
 assert d['original_locations']==d['candidate_locations']==[dict(offset=136,path='programs/pump-fees/src/common/mod.rs',line=21,column=56),dict(offset=480,path='programs/pump-fees/src/common/mod.rs',line=21,column=48)]
 candidate=e['variants']['origins']['files']['candidate']['sha256'];original=sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes());full=receipt('origins-full');assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
 for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
 f=receipt('origins-flags');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
 assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
 for name,path,fn in [('precedence','fees-exotic-growth-precedence/verify.py','check_boundary'),('optional','fees-optional-account-ownership/optional_cases.py','validate'),('seeds','fees-social-seed-vector/seed_cases.py','validate'),('logs','fees-extend-size-logs/log_cases.py','validate'),('mint','fees-crank-interface-mint/mint_cases.py','validate')]:
  f=receipt('origins-'+name);assert f['candidate_sha256']==candidate and f['original_sha256']==original;assert not getattr(module('case_'+name,ROOT/'research'/path),fn)(f)
 print('PASS: complete 504-byte helper, four callee bindings, two exact locations; 376 unique / 62 unmatched; fresh regression passed')
if __name__=='__main__':main()
