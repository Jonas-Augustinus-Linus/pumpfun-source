#!/usr/bin/env python3
"""Verify returned-account recipient-key provenance; official sell remains unequal."""
import argparse,base64,difflib,gzip,hashlib,json,re,subprocess,sys,tarfile,tempfile
from pathlib import Path
P=Path(__file__).resolve().parent
ROOT=P.parents[1]
sys.path.insert(0,str(P/'tools'))
from measure import measure
from key_audit import audit
sha=lambda b:hashlib.sha256(b).hexdigest()
ORIGINAL='6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
SYMBOLS={'control':'16ad4ae76fdb5c95694236b5752922524720b54ae0a97f4dc66e5c3ae5837110','clean':'511808573f8b4a831789c90756ba3a3d45eff6ed97ca9dc731bf82a763499e71'}
IMAGES={'control':'16d1b6f321e958025f5fef1f18d5d41167efe95b42f3dc091ee6d112027a588f','clean':'bda0a82482d6c6d09064109921e760e4a90a5a78f1e90c9ab4cf2a837527a10e'}

def doc(name):
 b=(P/name).read_bytes()
 return json.loads(gzip.decompress(b) if name.endswith('.gz') else b)

def unpack(name):
 files={}
 with tarfile.open(P/name) as archive:
  for m in archive:
   if m.isdir():continue
   n=Path(m.name)
   assert m.isfile() and not n.is_absolute() and '..' not in n.parts and m.name not in files
   files[m.name]=archive.extractfile(m).read()
 return files

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--signatures',action='store_true');args=parser.parse_args()
 manifest=doc('MANIFEST.json')
 for n,r in manifest['files'].items():
  b=(P/n).read_bytes();assert len(b)==r['bytes'] and sha(b)==r['sha256'],n
 assert {str(p.relative_to(P)) for p in P.rglob('*') if p.is_file() and '__pycache__' not in p.parts}==set(manifest['files'])|{'MANIFEST.json'}
 sources={k:unpack('sources/'+k+'.tar.gz') for k in ['control','candidate']};inv=doc('source-inventory.json')
 for k,s in sources.items():assert {n:sha(b) for n,b in s.items()}==inv[k]
 n='programs/pump-amm/src/instructions/swap/sell.rs';assert inv['changed']==[n]
 assert [x for x in sources['control'] if sources['control'][x]!=sources['candidate'][x]]==[n]
 before,after=[sources[k][n].decode() for k in ['control','candidate']]
 assert before.count('&user_volume_accumulator.key(),')==1
 assert before.replace('&user_volume_accumulator.key(),','&accumulator.key(),')==after
 assert len(before.splitlines())==len(after.splitlines())==567
 assert ''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),'a/'+n,'b/'+n))==(P/'source.patch').read_text()
 for kind,src,builder in [('control','control','control_builder.py'),('clean','candidate','candidate_builder.py')]:
  r=doc('builds/'+kind+'/attempt.json');assert r['returncode']==r['clean_returncode']==0 and r['source_unchanged'] and r['target_libraries_unchanged']
  assert r['source_sha256']==inv[src] and r['builder_sha256']==sha((P/'tools'/builder).read_bytes())
  assert all(x in r['command'] for x in ['--locked','--offline','--release','--target','sbpf-solana-solana','--manifest-path'])
  assert all(x in r['clean_command'] for x in ['--offline','--release','--target','sbpf-solana-solana','--manifest-path','pump-amm-recovered','native-transfer-fee'])
  log=gzip.decompress((P/('builds/'+kind+'/build.log.gz')).read_bytes());assert b'Compiling native-transfer-fee' in log and b'Compiling pump-amm-recovered' in log
 original=ROOT/'evidence/original/pump_amm/deployed.so';assert sha(original.read_bytes())==ORIGINAL
 with tempfile.TemporaryDirectory(prefix='amm-sell-checked-') as directory:
  t=Path(directory);paths={}
  for k in ['control','clean']:
   b=gzip.decompress((P/('builds/'+k+'/unstripped.so.gz')).read_bytes());assert sha(b)==SYMBOLS[k];paths[k]=t/(k+'.so');paths[k].write_bytes(b)
   assert sha(gzip.decompress((P/('builds/'+k+'/candidate.so.gz')).read_bytes()))==IMAGES[k]
  ledgers=[measure(original,paths[k]) for k in ['control','clean']]
  for k,rows in zip(['control','clean'],ledgers):
   assert len(rows)==785 and sum(bool(r['match']) for r in rows)==784 and sum(r['raw'] for r in rows)==267
   assert rows==doc('builds/'+k+'/score.json')['rows']
   assert next(r for r in rows if r['original']=='0x4c750')['match'] is None
  for key in ['match','raw']:assert {r['original'] for r in ledgers[0] if r[key]}=={r['original'] for r in ledgers[1] if r[key]}
  assert audit(original,paths['control'],paths['clean'])==doc('key-provenance.json')
  for k in ['control','clean']:
   graph=t/(k+'-graph.json');values=t/(k+'-values.json')
   subprocess.run([sys.executable,str(P/'tools/cfg_attribution.py'),'--original',str(original),'--candidate',str(paths[k]),'--output',str(graph)],stdout=subprocess.DEVNULL,check=True)
   assert graph.read_bytes()==gzip.decompress((P/('cfg/'+k+'.json.gz')).read_bytes())
   subprocess.run([sys.executable,str(P/'tools/value_attribution.py'),str(graph),str(values)],stdout=subprocess.DEVNULL,check=True)
   v=json.loads(values.read_text());assert v==doc('cfg/'+k+'-values.json')
   assert v['official_sell_status']=='UNEQUAL' and v['mapped_blocks']==v['same_value_operation_count_blocks']==77
   assert v['actual_direct_call_count']==80 and v['exact_actual_depth2_call_count']==80
   if k=='clean':
    assert v['identical_except_register_bytes_blocks']==77 and v['blocks_with_nonregister_value_differences']==0 and v['register_different_instruction_rows_in_those_blocks']==120
    registers=t/'registers.json';subprocess.run([sys.executable,str(P/'tools/register_attribution.py'),str(graph),str(registers)],stdout=subprocess.DEVNULL,check=True)
    reg=json.loads(registers.read_text());assert reg==doc('cfg/registers.json') and not reg['global']['consistent'] and reg['global']['conflict_count']==149 and reg['per_block']['consistent_blocks']==71
   graph.unlink()
 harness=unpack('runtime/harness-sources.tar.gz');assert {n:sha(b) for n,b in harness.items()}==doc('runtime/harness-inputs.json')
 before_inputs=doc('runtime/inputs-before.json')
 for name,expected in before_inputs.items():
  if '/scripts/' in name:
   relative='scripts/'+name.split('/scripts/',1)[1];assert sha(harness[relative])==expected
  elif name.endswith('/runtime/observe_suite.py'):
   assert sha(harness['repro/pump_amm/owner6048-v144/runtime/observe_suite.py'])==expected
 meter=re.compile(r'^Program \S+ consumed \d+ of \d+ compute units$');transactions=signatures=0
 for kind,image in [('control','control'),('candidate','clean')]:
  r=doc('runtime/'+kind+'.json.gz');assert r['original_sha256']==ORIGINAL and r['candidate_sha256']==IMAGES[image]
  assert r['case_count']==len(r['cases'])==575 and r['mismatches']==[]
  assert r['script_sha256']==sha(harness['scripts/pump_amm_legacy_sell_differential.py'])
  for row in r['cases']:
   assert row['diff']==[] and all(row['original'][k]==row['candidate'][k] for k in row['original'] if k!='logs')
   assert [s for s in row['original']['logs'] if not meter.match(s)]==[s for s in row['candidate']['logs'] if not meter.match(s)]
  sidecar=doc('runtime/'+kind+'-transactions.json.gz');assert sidecar['script_sha256']==r['script_sha256']
  assert sidecar['observer_sha256']==sha(harness['repro/pump_amm/owner6048-v144/runtime/observe_suite.py'])
  for name,loaded in sidecar['program_file_sha256'].items():
   if name in before_inputs:assert loaded['sha256']==before_inputs[name]
  count=0
  for i,row in enumerate(sidecar['transactions']):
   b=base64.b64decode(row['transaction_base64'],validate=True);assert sha(b)==row['transaction_sha256'] and row['all_signatures_verified']
   assert row['amm_program_sha256']==(ORIGINAL if i%2==0 else IMAGES[image])
   assert row['transaction_base64']==r['cases'][i//2]['original' if i%2==0 else 'candidate']['transaction_base64']
   if args.signatures:
    from solders.transaction import Transaction
    checks=Transaction.from_bytes(b).verify_with_results();assert checks and all(checks) and len(checks)==row['signature_count']
   count+=row['signature_count']
  assert sidecar['transaction_count']==len(sidecar['transactions'])==1150 and sidecar['signature_count']==count==1150
  transactions+=sidecar['transaction_count'];signatures+=count
 print(json.dumps({'result':'PASS','normalized':784,'raw':267,'normalized_gains':[],'normalized_losses':[],'raw_gains':[],'raw_losses':[],'official_sell_status':'UNEQUAL','actual_callees_before':80,'actual_callees_after':80,'actual_callee_count':80,'runtime_case_pairs_per_image':575,'transactions':transactions,'signatures':signatures,'signatures_reverified':args.signatures,'ordered_non_meter_log_mismatches':0,'nonregister_value_difference_blocks':0,'global_register_renaming_consistent':False,'locally_consistent_register_blocks':71}))

if __name__=='__main__':main()
