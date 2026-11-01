#!/usr/bin/env python3
"""Verify fresh captured creation reports with the sealed accrual proof's exact checks."""
import argparse,base64,hashlib,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/pump-multihop-accrual-qualification-20261028'
SEAL='d5a7e29ae52b385453e055cc619a1bee700f646123e86507daf35d9be5a2c9dd'

def verify(candidate_path,runtime):
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    if digest(PACKET/'MANIFEST.json')!=SEAL:raise ValueError('Unreviewed creation proof')
    manifest=json.loads((PACKET/'MANIFEST.json').read_text())['files']
    for name,expected in manifest.items():
        if digest(PACKET/name)!=expected:raise ValueError('Changed creation proof input: '+name)
    spec=importlib.util.spec_from_file_location('sealed_accrual_creation',PACKET/'verify.py')
    proof=importlib.util.module_from_spec(spec);spec.loader.exec_module(proof)
    P,R,doc,need,sha,check_loader=proof.P,proof.R,proof.doc,proof.need,proof.sha,proof.check_loader
    candidate=digest(Path(candidate_path));need(candidate==digest(P/'artifacts/candidate.so'),'Wrong fresh candidate')
    from solders.transaction import VersionedTransaction
    d=Path(runtime).resolve(); execution=doc(d/'execution.json'); x=doc(d/'cases.json.gz'); inputs=doc(P/'inputs.json')
    need(execution['returncode']==0 and execution['candidate_sha256']==candidate and execution['controller_sha256']==sha((P/'replay_captured_create.py').read_bytes()), 'fresh captured create execution')
    need(execution['report_sha256']==sha((d/'cases.json.gz').read_bytes()) and execution['loader_sha256']==sha((d/'loader.json').read_bytes()), 'actual captured create outputs')
    for name in ('producer','wrapper','actual_build_receipt','source_frozen'):
        need(sha((R/inputs[name]).read_bytes())==inputs[name+'_sha256'], 'captured replay input '+name)
    need(x['runner_sha256']==inputs['producer_sha256'] and x['build_receipt_sha256']==inputs['actual_build_receipt_sha256'] and x['source_coordinate_normalization'] is None, 'captured actual source/build binding')
    need(len(x['cases'])==14 and {r['family'] for r in x['cases']}=={'616','651'}, 'captured fixture set')
    program=lambda run:[s for s in run['logs'] if s.startswith(('Program log: ','Program data: '))]
    txs=sigs=0
    for row in x['cases']:
        runs=row['results']; a,b=runs['original'],runs['candidate']
        need(set(runs)=={'original','canonical','candidate'} and program(a)==program(b), 'captured strict Source messages')
        for k in ('before','after','error','events','inner','return'): need(a[k]==b[k], 'captured state/result '+k)
        need(len({r['transaction_base64'] for r in runs.values()})==1, 'same captured fixture wire')
        for run in runs.values():
            raw=base64.b64decode(run['transaction_base64'],validate=True); tx=VersionedTransaction.from_bytes(raw)
            need(bytes(tx)==raw and (tx.signatures and all(tx.verify_with_results())), 'captured actual signatures'); txs+=1; sigs+=len(tx.signatures)
    original=(R/'evidence/original/pump/deployed.so').read_bytes(); old=(R/'repro/pump/canonical-frontier-20261028/candidate.so').read_bytes(); new=(P/'artifacts/candidate.so').read_bytes()
    blobs={sha(v):v for v in (original,old,new)}; loads=doc(d/'loader.json')['loads']
    need((txs,sigs,len(loads))==(42,84,42) and {r['elf_sha256'] for r in loads}==set(blobs), 'captured execution/signature/image totals')
    for load in loads: check_loader(load,blobs)
    return dict(status="PASS",candidate_sha256=candidate,cases=14,executions=42,signature_fields=84,actual_captured_loads=42,source_normalization=None)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--runtime-directory',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(verify(args.candidate,args.runtime_directory),indent=2))
