"""Recheck source, actual artifacts and signed saved receipts; no compiler or VM."""
from pathlib import Path
from collections import Counter
import argparse,base64,difflib,gzip,hashlib,importlib.util,json,shutil,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return gzip.decompress(path.read_bytes())if path.suffix=='.gz'else path.read_bytes()
def load(path):return json.loads(read(path))
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def check_analysis(report):
 a,b=report['control'],report['candidate']
 assert a['normalized']==b['normalized']and len(b['normalized'])==577
 assert a['raw']==b['raw']and len(b['raw'])==198
 assert a['edges']==b['edges']and len(b['edges'])==3877 and sum(x[2]for x in b['edges'])==3870
 for r in [a,b]:
  assert r['unique_pairs']==430 and len(r['locations'])==181
  assert all(x[2]==x[3]for x in r['locations'])
  assert r['wrapper']['original']['address']==655904
  assert r['original_body']['address']==163920 and r['original_body']['bytes']==13800
  assert r['candidate_body']['signature']!=r['original_body']['signature']
  assert len(r['original_records'])==len(r['candidate_records'])==3
 values=lambda rows:Counter(tuple(x['value'])for x in rows)
 original=values(b['original_records'])
 assert original==values(b['candidate_records'])
 assert sum((original-values(a['candidate_records'])).values())==2
 assert sum((values(a['candidate_records'])-original).values())==2
 assert b['candidate_body']['bytes']==10704 and a['candidate_body']['bytes']==11160
 for col in [48,56]:assert original[('programs/pump-fees/src/common/mod.rs',33,col)]==1
def check_runtime(report,expected,parent):
 from solders.transaction import Transaction
 assert report['candidate_sha256']==expected
 assert report['original_sha256']==parent['original_sha256']
 assert report['case_count']==17331 and not report['mismatches']
 assert report['suites'].keys()==parent['suites'].keys()
 logs=transactions=signatures=0
 for name,suite in report['suites'].items():
  assert suite['candidate_sha256']==expected and suite['original_sha256']==report['original_sha256']
  old=parent['suites'][name]
  assert len(suite['cases'])==suite['case_count']==old['case_count']
  identity=lambda x:json.dumps(x.get('case',x.get('name')),sort_keys=True)
  assert [identity(x)for x in suite['cases']]==[identity(x)for x in old['cases']]
  assert not suite.get('mismatches',suite.get('failures',[]))
  for row in suite['cases']:
   if name!='queries':assert row.get('match')is True
   left,right=row['original'],row['candidate'];assert isinstance(left,dict)and left.keys()==right.keys()
   assert all(left[k]==right[k]for k in left if k!='logs')
   if 'logs'in left:
    app=lambda x:[l for l in x['logs']if l.startswith(('Program log:','Program data:'))]
    assert app(left)==app(right);logs+=1
   for result in [left,right]:
    if 'transaction_base64'in result:
     tx=Transaction.from_bytes(base64.b64decode(result['transaction_base64'],validate=True));checks=tx.verify_with_results();assert checks and all(checks)
     transactions+=1;signatures+=len(checks)
 assert logs==6413
 return {'cases':17331,'application_log_comparisons':logs,'signed_records':transactions,'signatures':signatures}
def check_curve(report,expected):
 from solders.transaction import Transaction
 fixture=module('quote_curve_cases',HERE/'curve_cases.py');d=fixture.d
 assert report['candidate_sha256']==expected and report['successes']==96 and not report['mismatches']
 assert report['original_sha256']==sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes())
 assert [x['case']for x in report['cases']]==fixture.cases()
 for row in report['cases']:
  assert row['match']is True;case=row['case'];left,right=row['original'],row['candidate']
  assert left.keys()==right.keys()and all(left[k]==right[k]for k in left if k!='logs')
  app=lambda x:[s for s in x['logs']if s.startswith(('Program log:','Program data:'))]
  assert app(left)==app(right)
  quote=bytes.fromhex(case['quote'])if case['curve_length']>=115 else bytes(32)
  if quote==bytes(32):quote=bytes(d.QUOTE)
  for result in [left,right]:
   assert result['error']is None and bytes.fromhex(result['data'])[74:106]==quote
   assert len(result['events'])==1
   data=base64.b64decode(result['events'][0].split(': ',1)[1],validate=True)
   assert len(data)==208 and data[:8]==hashlib.sha256(b'event:DonationFeePdaCreated').digest()[:8]
   assert data[16:]==bytes(d.AUTH.pubkey())+bytes(d.DONATION)+bytes(d.CONFIG)+bytes(d.MINT)+quote+bytes(d.AUTH.pubkey())
   tx=Transaction.from_bytes(base64.b64decode(result['transaction_base64'],validate=True));checks=tx.verify_with_results();assert checks and all(checks)
 return {'cases':96,'successful_creations':96,'signed_records':192,'decoded_event_records':192}
def check_build(label,inputs,candidate_hash,symbols_hash):
 folder=HERE/'builds'/label;launch=load(folder/'launch.json.gz');result=load(folder/'result.json.gz')
 assert launch['source_inputs']==inputs and launch['originals_mounted']is False
 command=launch['command'];assert '--network'in command and command[command.index('--network')+1]=='none'
 assert '--locked'in command and '--offline'in command
 assert result['exit_code']==0 and result['source_unchanged']and result['registry_unchanged']
 assert len(launch['registry_archives'])==252 and result['root_invocations']==result['math_invocations']==1
 log=read(folder/'build.log.gz');assert sha(log)==result['build_log_sha256']
 assert b'--crate-name pump_fees_candidate 'in log and b'--crate-name pump_fees_math 'in log
 assert result['artifacts']['candidate.so']['sha256']==candidate_hash and result['artifacts']['symbols.so']['sha256']==symbols_hash
 if label.startswith('layout-'):
  assert '-C'in command and 'linker=/config/linker.sh'in command and result['configuration_unchanged']
  assert launch['configuration_inputs']=={p.name:sha(p.read_bytes())for p in(HERE/'layout').iterdir()}
  assert read(folder/'sdk-default.ld.gz')==(HERE/'layout/default.ld').read_bytes()
  args=read(folder/'effective-link-args.txt.gz').decode().splitlines();assert '/config/ordered.ld'in args
 return launch
def check_manifest(folder):
 manifest=load(folder/'manifest.json')
 actual={p.relative_to(folder).as_posix()for p in folder.rglob('*')if p.is_file()and p!=folder/'manifest.json'and '__pycache__'not in p.parts}
 assert actual==set(manifest)
 for name,digest in manifest.items():assert not(folder/name).is_symlink()and sha((folder/name).read_bytes())==digest,name
 return manifest
def verify(skip_runtime=False,materialize=None):
 check_manifest(HERE)
 for name,digest in load(HERE/'external-inputs.json').items():assert sha((ROOT/name).read_bytes())==digest,name
 scope=load(HERE/'scope.json');parent=ROOT/scope['source_parent'];layout_parent=ROOT/scope['layout_parent']
 sources={p.relative_to(parent/'sources').as_posix().removesuffix('.gz'):read(p)for p in(parent/'sources').rglob('*.gz')}
 old=dict(sources);sources[scope['source_path']]=(HERE/'override.rs').read_bytes()
 assert len(sources)==46 and [n for n in sources if sources[n]!=old[n]]==[scope['source_path']]
 expected={n:sha(b)for n,b in sources.items()};assert expected==load(HERE/'source-inputs.json')
 patch=''.join(difflib.unified_diff(old[scope['source_path']].decode().splitlines(True),sources[scope['source_path']].decode().splitlines(True),fromfile='a/'+scope['source_path'],tofile='b/'+scope['source_path']))
 assert patch.encode()==(HERE/'source.patch').read_bytes()
 assert sources[scope['source_path']].count(b'crate::common::curve_quote_mint(curve.as_ref())')==1
 assert b'fn donation_raw_curve_quote'not in sources[scope['source_path']]
 analysis=module('quote_analysis',HERE/'analysis.py');report=analysis.reports();assert report==load(HERE/'analysis.json.gz');check_analysis(report)
 assert report['candidate']['symbols_sha256']==scope['symbols_sha256']and report['candidate']['original_sha256']==scope['original_sha256']
 for prefix,cand,sym in [('candidate',scope['candidate_sha256'],scope['symbols_sha256']),('native',scope['native_candidate_sha256'],scope['native_symbols_sha256'])]:
  stripped=read(HERE/f'artifacts/{prefix}-candidate.so.gz');symbols=read(HERE/f'artifacts/{prefix}-symbols.so.gz')
  assert sha(stripped)==cand and sha(symbols)==sym and cand!=scope['original_sha256']
  allocated=lambda image:{s['name']:s for s in analysis.w.m.elf_layout(image)['sections']if s['flags']&2}
  left,right=allocated(stripped),allocated(symbols);assert left.keys()==right.keys()
  for name,s in left.items():
   assert all(s[k]==right[name][k]for k in ['address','type','size','flags'])
   if s['type']!=8:assert analysis.w.m.section_data(stripped,name)==analysis.w.m.section_data(symbols,name)
 before={n:sha(b)for n,b in old.items()}
 native_parent=load(parent/'claims.json');layout_claims=load(layout_parent/'claims.json')
 for label in ['donation-common-quote','donation-common-fresh','donation-common-repeat']:
  launch=check_build(label,expected,scope['native_candidate_sha256'],scope['native_symbols_sha256'])
  if label!='donation-common-quote':assert launch['fresh_dependency_target']
 check_build('control',before,native_parent['candidate_sha256'],native_parent['symbols_sha256'])
 check_build('layout-control',before,sha(read(layout_parent/'artifacts/candidate-candidate.so.gz')),sha(read(layout_parent/'artifacts/candidate-symbols.so.gz')))
 for label in ['layout-quote','layout-quote-repeat']:check_build(label,expected,scope['candidate_sha256'],scope['symbols_sha256'])
 assert(HERE/'layout/ordered.ld').read_bytes()==(layout_parent/'layout/ordered.ld').read_bytes()
 runtime={}
 if not skip_runtime:
  parent_runtime=load(parent/'runtime.json.gz')
  for label,h in [('donation-common-quote',scope['native_candidate_sha256']),('layout-quote',scope['candidate_sha256'])]:
   runtime[label]=check_runtime(load(HERE/f'validation/{label}-runtime.json.gz'),h,parent_runtime)
   execution=load(HERE/f'validation/{label}-runtime-execution.json.gz');assert execution['candidate_sha256']==h
   assert execution['canonical_runner_sha256']==sha((ROOT/'scripts/fees_validate_all.py').read_bytes())
   for job in execution['suites'].values():assert job['exit_code']==0 and sha((ROOT/'scripts'/Path(job['command'][2]).name).read_bytes())==job['script_sha256']
  for label,h in [('control',native_parent['candidate_sha256']),('donation-common-quote',scope['native_candidate_sha256']),('layout-quote',scope['candidate_sha256'])]:runtime[label+'-curve']=check_curve(load(HERE/f'validation/{label}-curve-cases.json.gz'),h)
 if materialize:
  output=Path(materialize);output.mkdir(parents=True,exist_ok=False)
  for name,data in sources.items():p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 print(json.dumps({'source_files':46,'changed_source_files':1,'normalized_functions':577,'raw_local_functions':198,'repaired_typed_source_references':2,'new_complete_functions':0,'runtime':runtime,'compiler_executed':False,'target_executed':False},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--skip-runtime',action='store_true');p.add_argument('--materialize');a=p.parse_args();verify(a.skip_runtime,a.materialize)
