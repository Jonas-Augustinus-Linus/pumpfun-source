#!/usr/bin/env python3
"""Check saved source/build/replay bindings without compiling or executing targets."""
import argparse,difflib,gzip,hashlib,json,subprocess
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
FIELDS=['error','before','after','inner','return','transaction_base64','application_logs']
ORIGINAL='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
def sha(data):return hashlib.sha256(data).hexdigest()
def read(name):return json.loads((HERE/name).read_bytes())
def packed(name):return json.loads(gzip.decompress((HERE/name).read_bytes()))
def safe(name):
 p=PurePosixPath(name);assert name and not p.is_absolute()and str(p)==name and'..'not in p.parts and'\\'not in name and':'not in name
 return p
def integrity():
 assert not any(p.is_symlink()for p in HERE.rglob('*'))
 actual={p.relative_to(HERE).as_posix():sha(p.read_bytes())for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and'__pycache__'not in p.parts}
 assert actual==read('manifest.json'),'packet changed'
 for name,digest in read('validation-inputs.json').items():safe(name);assert sha((ROOT/name).read_bytes())==digest,name
def sources():
 baseline={}
 for name,row in read('baseline-sources.json').items():
  safe(name);safe(row['path']);rev=row['revision'];assert len(rev)==40 and all(c in'0123456789abcdef'for c in rev)
  data=subprocess.check_output(['git','--no-optional-locks','show',rev+':'+row['path']],cwd=ROOT);assert sha(data)==row['sha256'];baseline[name]=data
 proposal=dict(baseline);social='programs/pump-fees/src/social.rs';buyback='programs/pump-fees/src/buyback.rs'
 for name in [social,buyback]:proposal[name]=(HERE/'overrides'/name).read_bytes()
 assert baseline[social].count(b'**to+=amount;')==1
 expected=baseline[social].replace(b'**to+=amount;',b'**to=(**to).saturating_add(amount);')
 old=b'if amount==0 || ctx.accounts.recipient.executable{return Ok(None);}'
 assert expected.count(old)==1
 expected=expected.replace(old,b'if ctx.accounts.recipient.executable{msg!("Recipient account is executable, so it cannot receive lamports");return Ok(None);} if amount==0{msg!("No fees available to claim");return Ok(None);}')
 assert proposal[social]==expected
 assert proposal[social].split(b' pub fn claim(')[1]==baseline[social].split(b' pub fn claim(')[1],'legacy claim changed'
 old=b'**ctx.accounts.destination.try_borrow_mut_lamports()?+=sol_amount;';assert baseline[buyback].count(old)==1
 assert proposal[buyback]==baseline[buyback].replace(old,b'ctx.accounts.destination.add_lamports(sol_amount)?;')
 variants=dict(baseline=baseline,proposal=proposal)
 for label,data in variants.items():assert len(data)==43 and {n:sha(b)for n,b in data.items()}==read('source-inputs.json')[label]
 patch=''.join(''.join(difflib.unified_diff(baseline[n].decode().splitlines(True),proposal[n].decode().splitlines(True),fromfile='a/'+n,tofile='b/'+n))for n in [buyback,social])
 assert patch.encode()==(HERE/'source.patch').read_bytes()
 return variants
def observations():
 maps=read('source-inputs.json');hashes={}
 for label in ['baseline','proposal','repeat']:
  source='proposal'if label=='repeat'else label
  launch=read(f'builds/{label}/launch.json');result=read(f'builds/{label}/result.json');log=(HERE/f'builds/{label}/build.log').read_bytes()
  assert launch['source_inputs']==maps[source]and len(launch['registry_archives'])==252
  assert result['exit_code']==0 and result['source_unchanged']and result['registry_unchanged']and sha(log)==result['build_log_sha256']
  assert log.count(b'--crate-name pump_fees_candidate ')==result['root_invocations']==1
  assert log.count(b'--crate-name pump_fees_math ')==result['math_invocations']==1
  assert not launch['originals_mounted']and launch['command'][launch['command'].index('--network')+1]=='none'
  assert launch['fresh_dependency_target']==(label in ['baseline','repeat'])
  hashes[label]={k:v['sha256']for k,v in result['artifacts'].items()}
  if label!='repeat':
   for kind in ['candidate','symbols']:
    data=gzip.decompress((HERE/f'artifacts/{label}-{kind}.so.gz').read_bytes())
    assert sha(data)==hashes[label][kind+'.so']and len(data)==result['artifacts'][kind+'.so']['bytes']
 assert hashes['baseline']=={'candidate.so':'ed0d7bf81b71d2cd514d8e69beecf51a9767e0ba66a8c1b317dbf83d57cd01db','symbols.so':'f4d5e2f40061a716218c2860b8869bec884a67b9fc8d0bb69936dbbebbef7721'}
 assert hashes['proposal']==hashes['repeat']
 r=packed('validation/boundary.json.gz');assert r['fields']==FIELDS and r['case_count']==len(r['cases'])==119
 assert r['hashes']==dict(original=ORIGINAL,control=hashes['baseline']['candidate.so'],proposal=hashes['proposal']['candidate.so'])
 failures=[];corrected_overflow=0;corrected_noop=0
 for row in r['cases']:
  c=row['case'];results=row['results'];diff={n:[f for f in FIELDS if results['original'][f]!=results[n][f]]for n in ['control','proposal']}
  assert row['differences']==diff and not diff['proposal']
  expected=c['handler']!='legacy'and(c['overflow']or c.get('executable_recipient')or(c['handler']=='v2'and c['amount']==0 and not c.get('program_recipient')))
  assert bool(diff['control'])==bool(expected)
  if expected:
   failures.append(c['name'])
   if c['overflow']:corrected_overflow+=1;assert'ProgramFailedToComplete'in results['control']['error']
   else:corrected_noop+=1;assert diff['control']==['application_logs']
  if c['overflow']:
   error='ArithmeticOverflow'if c['handler']=='buyback'else'UnbalancedInstruction';assert error in results['original']['error']
   names=['buyback_vault','destination']if c['handler']=='buyback'else['social_fee_pda','recipient']
   for value in results.values():
    for name in names:assert value['before'][name]==value['after'][name]
   if c['handler']!='buyback':
    data=bytes(results['original']['return']['data']);assert data[0]==1
    offset=13+int.from_bytes(data[9:13],'little')+1+96;assert int.from_bytes(data[offset+32:offset+40],'little')==2**64-1
 assert (corrected_overflow,corrected_noop)==(30,8)and r['mismatches']==dict(control=failures,proposal=[])
 full=packed('validation/full.json.gz')
 assert full['candidate_sha256']==hashes['proposal']['candidate.so']and full['original_sha256']==ORIGINAL
 assert full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
 assert all(not s.get('mismatches',s.get('failures',[]))and s['candidate_sha256']==hashes['proposal']['candidate.so']for s in full['suites'].values())
 static=packed('validation/static.json.gz');assert set(static['reports'])=={'baseline','proposal'}
 for label,row in static['reports'].items():
  assert row['candidate_sha256']==hashes[label]['candidate.so']and row['symbols_sha256']==hashes[label]['symbols.so']
  assert (row['normalized'],row['raw'],row['location_uses_equal'])==(559,143,166)
  assert not row['whole_capture_equal']and not row['whole_meaningful_elf_equal']
 for t in static['transitions'].values():assert not any(t[k]for k in ['gains','losses','raw_losses','lost_equal_direct_edges'])
 return dict(recorded_focused_cases=119,corrected_overflow_cases=30,corrected_noop_cases=8,remaining_focused_mismatches=0,regression_cases=17331,compiler_executed=False,runtime_executed=False)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--variant',choices=['baseline','proposal'],default='proposal');p.add_argument('--materialize',type=Path);a=p.parse_args()
 integrity();data=sources();result=observations()
 if a.materialize:
  dest=a.materialize.absolute();assert not dest.exists()and not dest.is_symlink()and not any(p.is_symlink()for p in dest.parents);dest.mkdir(parents=True)
  for name,value in data[a.variant].items():path=dest/safe(name);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value)
  result['materialized']=str(dest)
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
