"""Verify buyback context source, normalized bodies, data and finite replay."""
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
 changed='programs/pump-fees/src/buyback.rs';old=(ROOT/base['source_paths'][changed]).read_text();a=old.index('pub struct InitializeBuyback');b=old.index('#[derive(Accounts)]',a);part=old[a:b]
 for label,v in e['variants'].items():
  assert len(v['input_sha256'])==36 and set(v['source_paths'])==set(v['input_sha256'])
  for n,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][n]).read_bytes())==h,n
  if label=='control':continue
  assert {n for n,h in base['input_sha256'].items()if v['input_sha256'][n]!=h}=={changed}
  new=part.replace("buyback_vault:Account<'info,BuybackVault>","buyback_vault:Box<Account<'info,BuybackVault>>").replace("buyback_vault_ata:InterfaceAccount<'info,anchor_spl::token_interface::TokenAccount>","buyback_vault_ata:Box<InterfaceAccount<'info,anchor_spl::token_interface::TokenAccount>>")
  if label=='origins':new=new.replace("event_authority:UncheckedAccount<'info>","event_authority:AccountInfo<'info>").replace("program:UncheckedAccount<'info>","program:AccountInfo<'info>")
  assert (ROOT/v['source_paths'][changed]).read_text()==old[:a]+new+old[b:]
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['inputs']==v['input_sha256']and result['compiled_root']and result['source_unchanged']and result['exit_code']==0 and sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']
  for kind in ['candidate','symbols']:assert result[kind+'_sha256']==v['files'][kind]['sha256']
 r=module('buyback_context_analysis',HERE/'analyze.py').analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 assert r['deltas']==dict(boxes=dict(added_original_windows=[364568],lost_original_windows=[]),origins=dict(added_original_windows=[351128,364568,370080],lost_original_windows=[]))and r['raw_delta']==dict(added_original_windows=[],lost_original_windows=[])
 for label,u,left in [('control',376,62),('boxes',377,61),('origins',379,59)]:
  row=r['variants'][label];assert len(row['unique_pairs'])==u and len(row['unmatched_original'])==left and not row['equals_original_capture']and not row['equals_original_elf_extent']
 assert [(d['original']['address'],d['original']['bytes'],len(d['calls']))for d in r['details']]==[(351128,7184,58),(364568,5512,22),(370080,560,7)]
 bad=[c for d in r['details']for c in d['calls']if not c['equal']];assert len(bad)==1 and bad[0]['offset']==2992 and bad[0]['original_target']==358312
 assert r['exit_data']['original']==r['exit_data']['candidate']and r['exit_data']['original']['labels']==['buyback_vault','buyback_vault_ata']
 assert len(r['preserved_slice_contract']['locations'])==4 and len(r['preserved_common_locations'])==2
 candidate=e['variants']['origins']['files']['candidate']['sha256'];original=sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes());full=receipt('origins-full');assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
 for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
 f=receipt('origins-flags');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
 assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
 for name,path,fn in [('precedence','fees-exotic-growth-precedence/verify.py','check_boundary'),('optional','fees-optional-account-ownership/optional_cases.py','validate'),('seeds','fees-social-seed-vector/seed_cases.py','validate'),('logs','fees-extend-size-logs/log_cases.py','validate'),('mint','fees-crank-interface-mint/mint_cases.py','validate')]:
  f=receipt('origins-'+name);assert f['candidate_sha256']==candidate and f['original_sha256']==original;assert not getattr(module('buyback_'+name,ROOT/'research'/path),fn)(f)
 print('PASS: three complete bodies; 86/87 direct callee bodies match; preserved panic data; 379 unique / 59 unmatched; fresh regressions')
if __name__=='__main__':main()
