"""Verify owned-event layout, complete bodies, callees and retained regressions."""
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
 for n,h in manifest.items():assert sha((HERE/n).read_bytes())==h,n
 for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json')['variants']['origins'];base=e['variants']['control'];v=e['variants']['origins'];assert e['control_reused']and base['input_sha256']==parent['input_sha256']and base['source_paths']==parent['source_paths']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['files'][kind][k]for k in ['sha256','bytes'])
 for row in [base,v]:
  assert len(row['input_sha256'])==36 and set(row['source_paths'])==set(row['input_sha256'])
  for n,h in row['input_sha256'].items():assert sha((ROOT/row['source_paths'][n]).read_bytes())==h,n
 name='programs/pump-fees/src/donation.rs';assert {n for n,h in base['input_sha256'].items()if v['input_sha256'][n]!=h}=={name}
 old=(ROOT/base['source_paths'][name]).read_text();new=(ROOT/v['source_paths'][name]).read_text();before='#[account(seeds=[b"__event_authority"],bump)] pub event_authority:UncheckedAccount<\'info>,';after=before.replace('UncheckedAccount','AccountInfo');assert old.count(before)==1 and old.replace(before,after)==new
 launch=load(HERE/'builds/origins-launch.json');result=load(HERE/'builds/origins-result.json');log=(HERE/'builds/origins-build.log').read_bytes();assert launch['inputs']==v['input_sha256']and result['compiled_root']and result['source_unchanged']and result['exit_code']==0 and sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
 assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']
 for kind,d in v['files'].items():
  raw=gzip.decompress((HERE/d['path']).read_bytes());assert sha(raw)==d['sha256']==result[kind+'_sha256']and len(raw)==d['bytes']
 r=module('crank_event_analysis',HERE/'analyze.py').analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 assert r['deltas']==dict(added_original_windows=[424824,656832],lost_original_windows=[])and r['raw_delta']==dict(added_original_windows=[],lost_original_windows=[])
 for label,u,left in [('control',380,58),('origins',382,56)]:
  row=r['variants'][label];assert len(row['unique_pairs'])==u and len(row['unmatched_original'])==left and not row['equals_original_capture']and not row['equals_original_elf_extent']
 details={x['original']['address']:x for x in r['details']};assert {k:(v['original']['bytes'],len(v['calls']))for k,v in details.items()}=={424824:(952,12),656832:(840,4),351128:(7184,58),358312:(6256,17),364568:(5512,22),370080:(560,7)}
 assert all(c['equal']for addr,d in details.items()if addr!=656832 for c in d['calls'])
 assert [(c['offset'],c['original_target'])for c in details[656832]['calls']if not c['equal']]==[(160,408640),(464,147944)]
 assert r['exit_data']['original']==r['exit_data']['control']==r['exit_data']['origins']and r['exit_data']['original']['labels']==['donation_fee_pda','donation_fee_pda_ata','quote_mint']
 t=r['exit_tokens'];assert t['original']==t['origins']and len(t['original'])==len(t['control']);assert [(a,b)for a,b in zip(t['original'],t['control'])if a!=b]==[([121,1,8,664,0],[121,1,8,624,0]),([121,8,8,720,0],[121,8,8,680,0])]
 assert len(r['preserved_slice_contract']['locations'])==4 and len(r['preserved_common_locations'])==2 and r['preserved_buyback_origin']==dict(path='programs/pump-fees/src/instructions/buyback/mod.rs',line=12,error=4101)
 candidate=v['files']['candidate']['sha256'];original=sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes());full=receipt('origins-full');assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
 for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
 f=receipt('origins-flags');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
 assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
 for name,path,fn in [('precedence','fees-exotic-growth-precedence/verify.py','check_boundary'),('optional','fees-optional-account-ownership/optional_cases.py','validate'),('seeds','fees-social-seed-vector/seed_cases.py','validate'),('logs','fees-extend-size-logs/log_cases.py','validate'),('mint','fees-crank-interface-mint/mint_cases.py','validate')]:
  f=receipt('origins-'+name);assert f['candidate_sha256']==candidate and f['original_sha256']==original;assert not getattr(module('crank_event_'+name,ROOT/'research'/path),fn)(f)
 print('PASS: crank exit and wrapper; 12/12 exit callees; two explicit wrapper frontiers; 382 unique / 56 unmatched; fresh regressions')
if __name__=='__main__':main()
