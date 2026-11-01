#!/usr/bin/env python3
"""Recompute complete-body census, actual call edges, source and signed runtime bindings."""
import argparse,base64,difflib,gzip,hashlib,json,re,sys,tarfile,tempfile
from pathlib import Path
P=Path(__file__).resolve().parent;ROOT=P.parents[1];sys.path.insert(0,str(P/'tools'))
from measure import measure
from audit import audit
ORIGINAL='6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
CANDIDATE='a775c319eefbb30c3134b46f452dc9c0286bb45c0eb65e96d0f73bb0f524ac68'
SYMBOLS='73d952aa51324e0ba17395a30f746e8b933cf739ae86bcb26675b4db69fbe126'
CONTROL='36a94b38f3c6fbc10a1f55c6526be07cd21356f1cc9da24ebaaa4bd28c79694e'
sha=lambda b:hashlib.sha256(b).hexdigest()
def doc(name):
 b=(P/name).read_bytes();return json.loads(gzip.decompress(b)if name.endswith('.gz')else b)
def unpack(name):
 result={}
 with tarfile.open(P/name)as archive:
  for member in archive:
   if member.isdir():continue
   n=Path(member.name);assert member.isfile()and not n.is_absolute()and '..'not in n.parts and member.name not in result
   result[member.name]=archive.extractfile(member).read()
 return result
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--signatures',action='store_true');args=parser.parse_args()
 manifest=doc('MANIFEST.json')
 for name,record in manifest['files'].items():
  raw=(P/name).read_bytes();assert len(raw)==record['bytes']and sha(raw)==record['sha256'],name
 assert {str(p.relative_to(P))for p in P.rglob('*')if p.is_file()and '__pycache__'not in p.parts}==set(manifest['files'])|{'MANIFEST.json'}
 inventory=doc('source-inventory.json');sources={kind:unpack('sources/'+kind+'.tar.gz')for kind in ['control','candidate']}
 for kind,files in sources.items():assert {n:sha(b)for n,b in files.items()}==inventory[kind]
 changed=[n for n in sources['control']if sources['control'][n]!=sources['candidate'][n]];assert changed==inventory['changed']==['programs/pump-amm/src/instructions/swap/buy.rs'];n=changed[0]
 before,after=[sources[k][n].decode().splitlines(True)for k in ['control','candidate']];assert len(before)==len(after)==993
 assert ''.join(difflib.unified_diff(before,after,'a/'+n,'b/'+n))==(P/'source.patch').read_text()
 assert {i for i,l in enumerate(after,1)if l.strip().startswith('//')}<={i for i,l in enumerate(before,1)if l.strip().startswith('//')}
 for kind,source in [('control','control'),('clean','candidate')]:
  build=doc('builds/'+kind+'/attempt.json');assert build['returncode']==build['clean_returncode']==0 and build['source_unchanged']and build['target_libraries_unchanged'];assert build['source_sha256']==inventory[source]
  assert build['builder_sha256']==sha((P/'tools/executed_builder.py').read_bytes())
  assert '--offline'in build['command']and '--offline'in build['clean_command']
  log=gzip.decompress((P/('builds/'+kind+'/build.log.gz')).read_bytes());assert b'Compiling native-transfer-fee'in log and b'Compiling pump-amm-recovered'in log
 portable=doc('builds/portable/result.json');assert portable['source_sha256']==inventory['candidate']and portable['source_unchanged']and portable['target_libraries_unchanged'];assert portable['candidate_sha256']==CANDIDATE and portable['unstripped_sha256']==SYMBOLS and portable['producer_sha256']==sha((P/'reproduce.py').read_bytes())
 original=ROOT/'evidence/original/pump_amm/deployed.so';assert sha(original.read_bytes())==ORIGINAL
 with tempfile.TemporaryDirectory(prefix='amm-buy-verify-')as directory:
  paths={}
  for label,expected in [('control',CONTROL),('clean',SYMBOLS)]:
   raw=gzip.decompress((P/('builds/'+label+'/unstripped.so.gz')).read_bytes());assert sha(raw)==expected;p=Path(directory)/(label+'.so');p.write_bytes(raw);paths[label]=p
  assert sha(gzip.decompress((P/'builds/clean/candidate.so.gz').read_bytes()))==CANDIDATE
  oldrows,newrows=[measure(original,paths[k])for k in ['control','clean']];assert len(oldrows)==len(newrows)==785
  old={r['original']for r in oldrows if r['match']};new={r['original']for r in newrows if r['match']};assert len(old)==783 and len(new)==784 and new-old=={'0x351a8'}and not old-new
  assert sum(r['raw']for r in oldrows)==236 and sum(r['raw']for r in newrows)==267
  assert oldrows==doc('builds/control/score.json')['rows']and newrows==doc('builds/clean/score.json')['rows']
  cp,panic=audit(original,paths['clean']);assert cp==doc('callproof.json')and panic==doc('panic-locations.json');assert cp['body_match']and cp['original_outgoing']==cp['candidate_outgoing']==25 and cp['original_incoming']==cp['candidate_incoming']==2;assert all(r['match']for r in cp['outgoing']+cp['incoming']);assert len(panic['locations'])==1 and not panic['mismatches']
 runtime=doc('runtime/legacy-buy.json.gz');assert runtime['candidate_sha256']==CANDIDATE and runtime['original_sha256']==ORIGINAL and runtime['case_count']==len(runtime['cases'])==1011 and runtime['mismatches']==[]
 meter=re.compile(r'^Program \S+ consumed \d+ of \d+ compute units$')
 for row in runtime['cases']:
  assert row['diff']==[]and all(row['original'][k]==row['candidate'][k]for k in row['original']if k!='logs')
  assert [l for l in row['original']['logs']if not meter.match(l)]==[l for l in row['candidate']['logs']if not meter.match(l)]
 assert doc('runtime/log-review.json')['ordered_log_mismatches']==[]
 harness=unpack('runtime/harness-sources.tar.gz');assert {n:sha(b)for n,b in harness.items()}==doc('runtime/inputs.json')
 sidecar=doc('runtime/legacy-buy-transactions.json.gz');assert sidecar['script_sha256']==sha(harness['scripts/pump_amm_legacy_buy_differential.py'])and sidecar['observer_sha256']==sha(harness['repro/pump_amm/owner6048-v144/runtime/observe_suite.py'])
 signatures=0
 for i,row in enumerate(sidecar['transactions']):
  raw=base64.b64decode(row['transaction_base64'],validate=True);assert sha(raw)==row['transaction_sha256']and row['all_signatures_verified']and row['amm_program_sha256']==(ORIGINAL if i%2==0 else CANDIDATE)
  if args.signatures:
   from solders.transaction import Transaction
   checks=Transaction.from_bytes(raw).verify_with_results();assert checks and all(checks)and len(checks)==row['signature_count']
  signatures+=row['signature_count']
 assert sidecar['transaction_count']==len(sidecar['transactions'])==2022 and sidecar['signature_count']==signatures==2022
 print(json.dumps({'result':'PASS','normalized':784,'raw':267,'gains':['0x351a8'],'losses':[],'outgoing_calls':25,'incoming_calls':2,'runtime_cases':1011,'transactions':2022,'signatures':2022,'signatures_reverified':args.signatures,'ordered_non_meter_log_mismatches':0}))
if __name__=='__main__':main()
