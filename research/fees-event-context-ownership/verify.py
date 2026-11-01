"""Verify isolated ownership trials, their accepted combination and regressions."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,re
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_text())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def receipt(n):return json.loads(gzip.decompress((HERE/f'receipts/{n}.json.gz').read_bytes()))
FILES={'social':'social.rs','withdrawal':'withdrawal.rs','sharing_v2':'sharing_update.rs','admin':'sharing_admin.rs','create_social':'instructions/fee_sharing/create_social_fee_pda.rs','create_sharing':'instructions/fee_sharing/create_fee_sharing_config.rs'}
ADDED={'social':[389488,645864],'withdrawal':[520760,657672],'sharing_v2':[],'admin':[],'create_social':[468624,644264],'create_sharing':[],'origins':[389488,468624,520760,644264,645864,657672]}
def transform(old):
 s,n=re.subn(r"(pub (?:event_authority|program):)UncheckedAccount<'info>",r"\1AccountInfo<'info>",old);assert n in [1,2];return s
def main():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}
 for n,h in manifest.items():assert sha((HERE/n).read_bytes())==h,n
 for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
 e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json')['variants']['origins'];base=e['variants']['control'];assert e['control_reused']and e['trials']==FILES and base['input_sha256']==parent['input_sha256']and base['source_paths']==parent['source_paths']
 assert [x[0]for x in e['combination']['included']]==['social','withdrawal','create_social']and e['combination']['expected_added']==ADDED['origins']
 for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['files'][kind][k]for k in ['sha256','bytes'])
 for label,row in e['variants'].items():
  assert len(row['input_sha256'])==36 and set(row['source_paths'])==set(row['input_sha256'])
  for n,h in row['input_sha256'].items():assert sha((ROOT/row['source_paths'][n]).read_bytes())==h,n
  for kind,d in row['files'].items():
   raw=gzip.decompress((HERE/d['path']).read_bytes());assert sha(raw)==d['sha256']and len(raw)==d['bytes']
  if label=='control':continue
  expected={'programs/pump-fees/src/'+FILES[x]for x in (['social','withdrawal','create_social']if label=='origins'else[label])};assert {n for n,h in base['input_sha256'].items()if row['input_sha256'][n]!=h}==expected
  for name in expected:assert (ROOT/row['source_paths'][name]).read_text()==transform((ROOT/base['source_paths'][name]).read_text())
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes();assert launch['inputs']==row['input_sha256']and result['compiled_root']and result['source_unchanged']and result['exit_code']==0 and sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']
  for kind in ['candidate','symbols']:assert result[kind+'_sha256']==row['files'][kind]['sha256']
 r=module('event_ownership_analysis',HERE/'analyze.py').analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
 for label in e['variants']:
  u=394 if label=='origins'else 390 if label in ['social','withdrawal','create_social']else 386 if label=='sharing_v2'else 388
  row=r['variants'][label];assert len(row['unique_pairs'])==u and len(row['unmatched_original'])==438-u and not row['equals_original_capture']and not row['equals_original_elf_extent']
  if label!='control':
   assert r['deltas'][label]==dict(added_original_windows=ADDED[label],lost_original_windows=[44632,641744]if label=='sharing_v2'else[])
   assert r['raw_deltas'][label]==dict(added_original_windows=[],lost_original_windows=[44632]if label=='sharing_v2'else[])
 details={x['original']['address']:x for x in r['details']};sizes={389488:(6168,46),468624:(7072,50),520760:(7904,72),644264:(1600,8),645864:(2104,13),657672:(1104,4)}
 for k,v in sizes.items():assert (details[k]['original']['bytes'],len(details[k]['calls']))==v
 bad={644264:[(712,190104)],645864:[(664,132744)],657672:[(440,249264)],651272:[(688,120816)],656832:[(160,408640),(464,147944)]}
 for k,d in details.items():assert [(c['offset'],c['original_target'])for c in d['calls']if not c['equal']]==bad.get(k,[])
 for d in r['recovered_data'].values():assert d['original']==d['candidate']
 assert sum(len(v['original'])for v in r['recovered_data'].values())==25
 for k,name in [('644264','CreateSocialFeePda'),('645864','ClaimSocialFeePda'),('657672','Withdraw')]:
  d=r['recovered_logs'][k];assert d['original']==d['candidate']and len(d['original'])==1 and d['original'][0]['value']=='Instruction: '+name
 assert all(v==r['exit_data']['original']for v in r['exit_data'].values())and all(v==r['exit_tokens']['original']for v in r['exit_tokens'].values())
 assert len(r['preserved_slice_contract']['locations'])==4 and len(r['preserved_common_locations'])==2 and r['preserved_buyback_origin']==dict(path='programs/pump-fees/src/instructions/buyback/mod.rs',line=12,error=4101)
 v=e['variants']['origins'];candidate=v['files']['candidate']['sha256'];original=sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes());full=receipt('origins-full');assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
 for s in full['suites'].values():assert s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))
 f=receipt('origins-flags');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
 assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
 for name,path,fn in [('precedence','fees-exotic-growth-precedence/verify.py','check_boundary'),('optional','fees-optional-account-ownership/optional_cases.py','validate'),('seeds','fees-social-seed-vector/seed_cases.py','validate'),('logs','fees-extend-size-logs/log_cases.py','validate'),('mint','fees-crank-interface-mint/mint_cases.py','validate')]:
  f=receipt('origins-'+name);assert f['candidate_sha256']==candidate and f['original_sha256']==original;assert not getattr(module('buyback_update_'+name,ROOT/'research'/path),fn)(f)
 print('PASS: six isolated trials; accepted combination adds six bodies without loss; 168 parser callees; 394 unique / 44 unmatched; fresh regressions')
if __name__=='__main__':main()
