"""Check persistent VM receipts and independently account for each transfer fee."""
from pathlib import Path
from collections import defaultdict
import base64,gzip,hashlib,json,struct
from solders.transaction import Transaction
import replay
P=Path(__file__).resolve().parent;R=P.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def require(ok,reason):
 if not ok:raise AssertionError(reason)
def read(p):return json.loads(p.read_bytes())
def vector(value):
 require(isinstance(value,list)and isinstance(value[0],list),'serialized short vector')
 size=0;shift=0
 for b in value[0]:size|=(b&127)<<shift;shift+=7
 require(size==len(value)-1,'short-vector length')
 return bytes(value[1:])
def fee(amount,maximum,bps):
 require(0<=bps<=10000 and 0<=amount<2**64,'bounded fee oracle inputs')
 return min(maximum,(amount*bps+9999)//10000)
def token_state(a):
 if a is None:return None
 data=bytes.fromhex(a['data'])
 if a['owner']!=str(replay.h.TOKEN22)or len(data)<166 or data[165]!=2:return None
 require(data[166:170]==struct.pack('<HH',2,8)and len(data)==178,'single TransferFeeAmount extension')
 return dict(amount=int.from_bytes(data[64:72],'little'),withheld=int.from_bytes(data[170:178],'little'),mint=str(replay.h.Pubkey.from_bytes(data[:32])))
def event_transfer_fee(row):
 disc=bytes(next(e for e in replay.h.IDL['events']if e['name']=='BuyEvent')['discriminator'])
 events=[base64.b64decode(x.removeprefix('Program data: '),validate=True)for x in row['logs']if x.startswith('Program data: ')]
 events=[x for x in events if x[:8]==disc];require(len(events)==1,'one actual BuyEvent')
 raw=events[0];offset=8
 fields=next(t for t in replay.h.IDL['types']if t['name']=='BuyEvent')['type']['fields']
 require(fields[-1]['name']=='creator_fee_unclaimed','pinned historical event prefix')
 for field in fields:
  kind=field['type']
  if kind=='string':
   length=int.from_bytes(raw[offset:offset+4],'little');offset+=4+length
  else:
   require(kind in ['u64','i64','i128','bool','pubkey'],'known event field')
   if kind=='bool':require(raw[offset]in [0,1],'event boolean')
   offset+={'u64':8,'i64':8,'i128':16,'bool':1,'pubkey':32}[kind]
  require(offset<=len(raw),'event field bounds')
 # The captured IDL omits this one recovered u64 suffix; do not reinterpret an
 # arbitrary trailing region. Both captures and maintained Rust bind this shape.
 require(len(raw)==offset+8,'exact recovered quote_transfer_fee suffix')
 return int.from_bytes(raw[offset:],'little')
def oracle(row,epoch_override=None):
 before=row['before'];after=row['after'];epoch=row['clock']['epoch']if epoch_override is None else epoch_override
 mint=str(replay.h.quote);raw=bytes.fromhex(before[mint]['data'])
 require(before[mint]['owner']==str(replay.h.TOKEN22)and len(raw)==278 and raw[165:170]==bytes([1])+struct.pack('<HH',1,108),'actual transfer-fee mint envelope')
 old=struct.unpack('<QQH',raw[242:260]);new=struct.unpack('<QQH',raw[260:278]);chosen=new if epoch>=new[0]else old
 tx=Transaction.from_bytes(base64.b64decode(row['transaction_base64']));keys=[str(k)for k in tx.message.account_keys]
 changes=defaultdict(lambda:[0,0]);transfers=[]
 for group in row['inner']:
  for nested in group:
   ix=nested['instruction']
   if keys[ix['programIdIndex']]!=str(replay.h.TOKEN22):continue
   data=vector(ix['data']);accounts=vector(ix['accounts'])
   require(nested['stackHeight']==2 and len(data)==10 and data[0]==12 and len(accounts)==4,'actual Token-2022 TransferChecked CPI')
   source,mintkey,dest,_=[keys[i]for i in accounts];require(mintkey==mint,'fee mint CPI binding')
   amount=int.from_bytes(data[1:9],'little');charge=fee(amount,chosen[1],chosen[2])
   require(token_state(before[source])['mint']==mint and token_state(before[dest])['mint']==mint,'source/destination mint binding')
   changes[source][0]-=amount;changes[dest][0]+=amount-charge;changes[dest][1]+=charge
   transfers.append(dict(source=source,destination=dest,gross=amount,fee=charge,net=amount-charge))
 failed=row['error']is not None
 if failed:require(not transfers,'slippage rejected before token transfers')
 else:require(len(transfers)==4,'four successful quote transfers')
 for key,b in before.items():
  x=token_state(b)
  if x is None:continue
  y=token_state(after[key]);require(y is not None,'retained token extension')
  delta=changes[key]
  require(y['amount']-x['amount']==delta[0]and y['withheld']-x['withheld']==delta[1],'token amount/withheld fee conservation')
  if not failed:require(y['withheld']>=x['withheld'],'no withheld-fee reset')
 require(before[mint]==after[mint],'mint schedule unchanged during swaps')
 if not failed:
  debit=-changes[str(replay.h.userquote)][0];require(0<debit<=10**7,'exact quote user budget')
  require(sum(d[0]+d[1]for d in changes.values())==0,'total spendable plus withheld conserved')
  pool_transfers=[t for t in transfers if t['destination']==str(replay.h.vaultquote)]
  require(len(pool_transfers)==1 and event_transfer_fee(row)==pool_transfers[0]['fee'],'event fee equals actual pool transfer fee')
 return dict(epoch=epoch,selected_fee=list(chosen),transfers=transfers,event_quote_transfer_fee=None if failed else event_transfer_fee(row))

def check(directory):
 header=read(directory/'observed.json');rows=[json.loads(x)for x in gzip.decompress((directory/'observed.jsonl.gz').read_bytes()).splitlines()]
 require(len(rows)==header['transactions']==header['signature_fields']==48,'48 observed normal signatures')
 require(header['observer_sha256']==sha(P/'observer.py')and header['script_sha256']==sha(P/'replay.py'),'executed observer and replay sources')
 for name,digest in header['input_reads'].items():require(sha(R/name)==digest,'actual input '+name)
 dependencies={str(pid):sha(R/path)for pid,path in [(replay.h.TOKEN,'evidence/dependencies/spl_token/deployed.so'),(replay.h.TOKEN22,'evidence/dependencies/spl_token_2022/deployed.so'),(replay.h.ATA,'evidence/dependencies/associated_token/deployed.so'),(replay.h.FEES,'evidence/original/pump_fees/deployed.so')]}
 previous={};seen_signatures=set();groups={};result=[];failures=0;successes=0;transfers=0
 for index,row in enumerate(rows):
  require(row['sequence']==index,'receipt order')
  profile=replay.PROFILES[index//12];label=['original','c651','c726'][(index%12)//4];step=replay.STEPS[index%4]
  require(row['context']==dict(profile=profile['name'],artifact=label,step=step['name']),'complete profile/variant/step grid')
  require(row['vm']==index//4,'one actual VM per four-step sequence')
  require(row['clock']['epoch']==step['epoch'],'actual VM epoch')
  want=replay.HASHES[label];require(row['amm_sha256']==want and row['loaded_programs']==dict(dependencies,**{str(replay.h.PROGRAM):want}),'actual loaded binary set')
  tx=Transaction.from_bytes(base64.b64decode(row['transaction_base64'],validate=True));checks=tx.verify_with_results();require(checks==[True]and row['signature_fields']==1,'valid normal payer signature')
  # Identical counterpart messages are expected; every step within each VM differs.
  pair=(row['vm'],str(tx.signatures[0]));require(pair not in seen_signatures,'unique signed transaction within sequence');seen_signatures.add(pair)
  require(len(tx.message.instructions)==1 and tx.message.account_keys[tx.message.instructions[0].program_id_index]==replay.h.PROGRAM,'AMM-only top-level transaction')
  data=bytes(tx.message.instructions[0].data)
  expected_disc=bytes(next(x for x in replay.h.IDL['instructions']if x['name']=='buy_exact_quote_in')['discriminator'])
  require(data==expected_disc+struct.pack('<QQ',10**7,step['limit'])+b'\0','exact signed trade arguments')
  mint=bytes.fromhex(row['before'][str(replay.h.quote)]['data'])
  require(mint[242:278]==struct.pack('<QQH',*profile['old'])+struct.pack('<QQH',*profile['new']),'actual scheduled fee parameters')
  if row['vm']in previous:require(previous[row['vm']]['after']==row['before'],'persistent account continuity, no reset')
  previous[row['vm']]=row
  fail=step['name']=='activation-rejected';require((row['error']is not None)==fail,'expected success/rejection')
  if fail:
   failures+=1;require('Custom(6040)'in row['error'],'expected min-base slippage error')
   payer=str(tx.message.account_keys[0])
   for key,b in row['before'].items():
    a=row['after'][key]
    if key==payer:require(b['data']==a['data']and b['owner']==a['owner']and b['lamports']-a['lamports']==5000,'failed payer fee only')
    else:require(b==a,'failed account rollback')
  else:successes+=1
  calc=oracle(row);transfers+=len(calc['transfers']);result.append(dict(context=row['context'],**calc))
  key=(profile['name'],step['name'])
  if label=='original':groups[key]=row
  else:
   for field in ['transaction_base64','before','after','error','inner','return_data']:require(row[field]==groups[key][field],'paired original/candidate '+field)
   a=[x for x in groups[key]['logs']if x.startswith('Program data: ')];b=[x for x in row['logs']if x.startswith('Program data: ')];require(a==b,'serialized event bytes')
 require((successes,failures,transfers)==(36,12,144),'complete success/failure/fee-CPI coverage')
 return dict(transactions=len(rows),signatures=len(rows),persistent_sequences=len(previous),successes=successes,slippage_rejections=failures,fee_transfers=transfers,paired_state_error_inner_return_event_mismatches=0,fees=result)

def verify():
 m=read(P/'manifest.json')
 for n,digest in m['files'].items():require(sha(P/n)==digest,'packet hash '+n)
 for n,digest in m['external_files'].items():require(sha(R/n)==digest,'external hash '+n)
 require(hashlib.sha256(gzip.decompress((P/'public/candidate.so.gz').read_bytes())).hexdigest()==replay.HASHES['c726'],'public candidate')
 require(sha(R/'evidence/original/pump_amm/deployed.so')==replay.HASHES['original'],'original capture')
 require(sha(R/'repro/pump_amm/optional-context-recovery-20261027/results/build/candidate.so')==replay.HASHES['c651'],'maintained control')
 report=check(P/'runtime');require(report==read(P/'report.json'),'recomputed conservation report');return report

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('--runtime',type=Path);args=parser.parse_args()
 report=check(args.runtime.resolve())if args.runtime else verify()
 print(json.dumps({k:v for k,v in report.items()if k!='fees'},indent=2))
