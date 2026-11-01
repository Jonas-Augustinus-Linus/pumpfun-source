"""Verify buyback update ownership, complete bodies and retained regressions."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_text())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def receipt(n):return json.loads(gzip.decompress((HERE/f'receipts/{n}.json.gz').read_bytes()))
def changed_source(old,fields):
 start=old.index("pub struct UpdateBuyback<'info>");end=old.index('\n}',start);block=old[start:end]
 for field in fields:
  a=f"pub {field}:UncheckedAccount<'info>";assert block.count(a)==1;block=block.replace(a,f"pub {field}:AccountInfo<'info>")
 return old[:start]+block+old[end:]
def main():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}
 for n,h in manifest.items():assert sha((HERE/n).read_bytes())==h,n
 for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json')['variants']['origins'];base=e['variants']['control'];assert e['control_reused']and base['input_sha256']==parent['input_sha256']and base['source_paths']==parent['source_paths']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['files'][kind][k]for k in ['sha256','bytes'])
 name='programs/pump-fees/src/buyback.rs';old=(ROOT/base['source_paths'][name]).read_text();changes={'event':['event_authority'],'program':['program'],'origins':['event_authority','program']}
 for label,row in e['variants'].items():
  assert len(row['input_sha256'])==36 and set(row['source_paths'])==set(row['input_sha256'])
  for n,h in row['input_sha256'].items():assert sha((ROOT/row['source_paths'][n]).read_bytes())==h,n
  for kind,d in row['files'].items():
   raw=gzip.decompress((HERE/d['path']).read_bytes());assert sha(raw)==d['sha256']and len(raw)==d['bytes']
  if label=='control':continue
  assert {n for n,h in base['input_sha256'].items()if row['input_sha256'][n]!=h}=={name}and (ROOT/row['source_paths'][name]).read_text()==changed_source(old,changes[label])
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes();assert launch['inputs']==row['input_sha256']and result['compiled_root']and result['source_unchanged']and result['exit_code']==0 and sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']
  for kind in ['candidate','symbols']:assert result[kind+'_sha256']==row['files'][kind]['sha256']
 r=module('buyback_update_analysis',HERE/'analyze.py').analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 for label in e['variants']:
  row=r['variants'][label];assert len(row['unique_pairs'])==(388 if label=='origins'else 385)and len(row['unmatched_original'])==(50 if label=='origins'else 53)and not row['equals_original_capture']and not row['equals_original_elf_extent']
  if label!='control':assert r['deltas'][label]==dict(added_original_windows=[331936,652592,654336]if label=='origins'else[],lost_original_windows=[])
 assert r['raw_delta']==dict(added_original_windows=[],lost_original_windows=[])
 details={x['original']['address']:x for x in r['details']};assert [(details[k]['original']['bytes'],len(details[k]['calls']))for k in [331936,652592,654336]]==[(5856,43),(1744,9),(1568,9)]
 assert all(c['equal']for k,d in details.items()if k not in [651272,656832]for c in d['calls'])
 assert [(c['offset'],c['original_target'])for c in details[651272]['calls']if not c['equal']]==[(688,120816)]and [(c['offset'],c['original_target'])for c in details[656832]['calls']if not c['equal']]==[(160,408640),(464,147944)]
 assert all(v==r['exit_data']['original']for v in r['exit_data'].values())and all(v==r['exit_tokens']['original']for v in r['exit_tokens'].values())
 for d in r['recovered_data'].values():assert d['original']==d['candidate']
 d=r['recovered_data'];assert sum(len(v['original'])for v in d.values())==25
 expected=['authority','fee_program_global','buyback_vault','fee-program-global','fee_program_global','event_authority','program','authority','fee_program_global','fee_program_global','fee_program_global','buyback-vault','buyback_vault','event_authority','buyback_vault']
 assert [bytes.fromhex(x['value']).decode()for x in d['331936']['original']]==expected
 for key,message in [('652592','Instruction: UpdateBuybackAuthority'),('654336','Instruction: UpdateBuybackClaimRateLimit')]:
  rows=d[key]['original'];assert bytes.fromhex(rows[0]['value']).decode()==message and rows[1]['value']==rows[2]['value']==r['exit_data']['original']['owner'];assert bytes.fromhex(rows[3]['value'])==b'buyback_vault'and bytes.fromhex(rows[4]['value'])==b'fee_program_global'
 assert len(r['preserved_slice_contract']['locations'])==4 and len(r['preserved_common_locations'])==2 and r['preserved_buyback_origin']==dict(path='programs/pump-fees/src/instructions/buyback/mod.rs',line=12,error=4101)
 v=e['variants']['origins'];candidate=v['files']['candidate']['sha256'];original=sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes());full=receipt('origins-full');assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
 for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
 f=receipt('origins-flags');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
 assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
 for name,path,fn in [('precedence','fees-exotic-growth-precedence/verify.py','check_boundary'),('optional','fees-optional-account-ownership/optional_cases.py','validate'),('seeds','fees-social-seed-vector/seed_cases.py','validate'),('logs','fees-extend-size-logs/log_cases.py','validate'),('mint','fees-crank-interface-mint/mint_cases.py','validate')]:
  f=receipt('origins-'+name);assert f['candidate_sha256']==candidate and f['original_sha256']==original;assert not getattr(module('buyback_update_'+name,ROOT/'research'/path),fn)(f)
 print('PASS: update parser and two wrappers; 61/61 new direct callees; 25 data ranges; 388 unique / 50 unmatched; fresh regressions')
if __name__=='__main__':main()
