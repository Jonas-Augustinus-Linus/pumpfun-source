"""Recompute bounded references and retain, rather than normalize away, diagnostics."""
from pathlib import Path
import base64,gzip,hashlib,json,re
from solders.transaction import Transaction
import proof
from replay import CASES
P=Path(__file__).resolve().parent;R=P.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
require=proof.require
def read(path):return json.loads(path.read_bytes())
def errors(row):return [x for x in row['logs']if 'Error'in x or 'panicked'in x]
def logs(row):return [x for x in row['logs']if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units',x)]
def signed(row,wanted):
 raw=base64.b64decode(row['transaction_base64'],validate=True);tx=Transaction.from_bytes(raw)
 checked=tx.verify_with_results();require(checked and all(checked),'valid transaction signatures')
 require(row['signature_fields']==len(checked),'signature field count')
 program='pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA'
 require(row['amm_sha256']==wanted and row['loaded_programs'][program]==wanted,'actual loaded AMM artifact')
 return len(checked)

def runtime(directory):
 rows=json.loads(gzip.decompress((directory/'results.json.gz').read_bytes()))
 receipt=[json.loads(line)for line in gzip.decompress((directory/'observed.jsonl.gz').read_bytes()).splitlines()]
 header=read(directory/'observed.json')
 require([r['case']for r in rows]==CASES,'complete exact case manifest')
 require(header['observer_sha256']==sha((P/'observer.py').read_bytes()),'observer source hash')
 require(header['script_sha256']==sha((P/'replay.py').read_bytes()),'replay source hash')
 require(header['transactions']==len(receipt)==60,'actual transaction count')
 for n,wanted in header['input_reads'].items():require(sha((R/n).read_bytes())==wanted,'actual read input '+n)
 # Hashes derive from immutable actual artifacts, not candidate labels.
 wanted={'original':sha((R/'evidence/original/pump_amm/deployed.so').read_bytes()),'c651':sha((R/'repro/pump_amm/optional-context-recovery-20261027/results/build/candidate.so').read_bytes())}
 for b in read(P/'builds.json'):wanted[b['label']]=b['candidate_sha256']
 # Read IDL-independent keys from retained runtime helper for exact spelling.
 import pump_amm_legacy_buy_differential as h
 dependencies={str(pid):sha((R/path).read_bytes())for pid,path in [(h.TOKEN,'evidence/dependencies/spl_token/deployed.so'),(h.TOKEN22,'evidence/dependencies/spl_token_2022/deployed.so'),(h.ATA,'evidence/dependencies/associated_token/deployed.so'),(h.FEES,'evidence/original/pump_fees/deployed.so')]}
 summary=[];count=0;signatures=0
 for row in rows:
  original=row['results']['original'];entry=dict(case=row['case']['name'],error=original['error'],variants={})
  original_receipt=receipt[count]
  for label in ['original','c651','c693','c726']:
   observed=receipt[count];result=row['results'][label]
   require(observed['sequence']==count,'receipt sequence');count+=1
   signatures+=signed(observed,wanted[label])
   for pid,digest in dependencies.items():require(observed['loaded_programs'].get(pid)==digest,'loaded dependency')
   require(len(observed['loaded_programs'])==5,'exact loaded program set')
   for key in ['transaction_base64','error','logs','inner','return_data']:require(observed[key]==result[key],'actual send/result binding '+key)
   for phase in ['before','after']:
    for key,account in result[phase].items():
     require(key in observed[phase],'watched account in actual message')
     o=observed[phase][key]
     require((account is None and o is None)or(account is not None and o is not None and account==dict(data_hex=o['data'],lamports=o['lamports'],owner=o['owner'])),'account receipt binding')
   for key in ['transaction_base64','error','before','after','inner','return_data']:
    require(observed[key]==original_receipt[key],'paired actual '+key)
   # Solana charges a transaction fee even on failure; all other accounts roll back.
   if observed['error'] is not None:
    tx=Transaction.from_bytes(base64.b64decode(observed['transaction_base64']));payer=str(tx.message.account_keys[0])
    for key,before in observed['before'].items():
     after=observed['after'][key]
     if key!=payer:require(before==after,'failed transaction account rollback')
     else:
      require(before['data']==after['data']and before['owner']==after['owner']and before['lamports']-after['lamports']==5000,'failed payer fee only')
   entry['variants'][label]=dict(error_logs=errors(observed),error_logs_equal=errors(observed)==errors(original_receipt),non_compute_logs_equal=logs(observed)==logs(original_receipt))
  summary.append(entry)
 require(signatures==header['signature_fields']==60,'verified signature total')
 lookup={r['case']:r for r in summary}
 for name in ['division-zero','virtual-cancellation','accrued-cancellation']:
  r=lookup[name];require('constant_product.rs:85.'in r['variants']['original']['error_logs'][0],'reached original math origin')
  require(not r['variants']['c651']['error_logs_equal']and r['variants']['c693']['error_logs_equal']and r['variants']['c726']['error_logs_equal'],'old control and recovered math origins')
 for name in ['negative-effective-before-math','unfunded-accrual-before-math']:
  r=lookup[name];require(r['variants']['c693']['error_logs_equal']and not r['variants']['c726']['error_logs_equal'],'retained composition diagnostic regression')
 require(lookup['normal-fee-success-control']['error']is None,'genuine success control')
 return dict(transactions=count,signature_fields=signatures,paired_state_error_inner_return_mismatches=0,cases=summary)

def verify(check_manifest=True):
 if check_manifest:
  manifest=read(P/'manifest.json')
  for n,digest in manifest['files'].items():require(sha((P/n).read_bytes())==digest,'packet hash '+n)
  for n,digest in manifest['external_files'].items():require(sha((R/n).read_bytes())==digest,'external hash '+n)
 for b in read(P/'builds.json'):
  for name,digest in [('candidate',b['candidate_sha256']),('unstripped',b['symbol_sha256'])]:require(sha(gzip.decompress((P/'public'/b['label']/(name+'.so.gz')).read_bytes()))==digest,'public artifact hash')
  cut=gzip.decompress((P/'public'/b['label']/'candidate.so.gz').read_bytes());sym=gzip.decompress((P/'public'/b['label']/'unstripped.so.gz').read_bytes())
  for section in proof.w.m.elf_layout(cut)['sections']:
   if section['flags']&2 and section['type']!=8:
    other=next(s for s in proof.w.m.elf_layout(sym)['sections']if s['name']==section['name'])
    require(section['address']==other['address']and proof.w.m.section_data(cut,section['name'])==proof.w.m.section_data(sym,section['name']),'loaded/symbol allocated section identity')
 result=dict(static=proof.all_builds(),runtime=runtime(P/'runtime'),portable_repeat=runtime(P/'repeat'))
 require(result['runtime']==result['portable_repeat'],'portable fresh-VM repeat results')
 if check_manifest:require(result==json.loads(gzip.decompress((P/'report.json.gz').read_bytes())),'fresh recomputed report')
 return result

if __name__=='__main__':
 report=verify();print(json.dumps(dict(static={k:dict(roots=v['roots'],typed_reference_sites=len(v['typed_references']),reachable_pairs=v['reachable_pairs'],direct_edges=len(v['direct_edges']))for k,v in report['static'].items()},runtime=report['runtime']),indent=2))
