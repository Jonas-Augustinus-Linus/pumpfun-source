#!/usr/bin/env python3
"""Verify fresh captured creation reports with the sealed program-creator notice proof's exact checks."""
if not __debug__: raise SystemExit('Optimized Python is unsupported; run without -O.')
import argparse,base64,hashlib,importlib.util,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/pump-program-creator-notice-qualification-20261028'
SEAL='ef50bb5262f67c59f4d1850f83e2821fa1e9c5f02649589cab356a6e28cffb49'

def verify(candidate_path,runtime):
    if len(SEAL)!=64 or any(c not in '0123456789abcdef' for c in SEAL):raise ValueError('Program-creator notice final seal is not frozen')
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    if digest(PACKET/'MANIFEST.json')!=SEAL:raise ValueError('Unreviewed creation proof')
    manifest=json.loads((PACKET/'MANIFEST.json').read_text())['files']
    for name,expected in manifest.items():
        if digest(PACKET/name)!=expected:raise ValueError('Changed creation proof input: '+name)
    spec=importlib.util.spec_from_file_location('sealed_program_creator_creation',PACKET/'verify.py')
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
    reference=doc(P/'runtime/captured-create-supplement/cases.json.gz')['cases']
    fixture=lambda row:(row['family'],row['index'],row['input'],row['results']['original']['transaction_base64'])
    need([fixture(row) for row in x['cases']]==[fixture(row) for row in reference], 'captured exact sealed fixture descriptors and original signed wires')
    cu=re.compile(r'^Program [1-9A-HJ-NP-Za-km-z]+ consumed [0-9]+ of [0-9]+ compute units$')
    ordered=lambda run:[s for s in run['logs'] if not cu.fullmatch(s)]
    txs=sigs=0
    for row in x['cases']:
        runs=row['results']; a,b=runs['original'],runs['candidate']
        need(set(runs)=={'original','canonical','candidate'} and ordered(a)==ordered(b), 'captured full ordered Source/log messages')
        for k in ('before','after','error','events','inner','return'): need(a[k]==b[k], 'captured state/result '+k)
        need(len({r['transaction_base64'] for r in runs.values()})==1, 'same captured fixture wire')
        for run in runs.values():
            raw=base64.b64decode(run['transaction_base64'],validate=True); tx=VersionedTransaction.from_bytes(raw)
            need(bytes(tx)==raw and (tx.signatures and all(tx.verify_with_results())), 'captured actual signatures'); txs+=1; sigs+=len(tx.signatures)
    original=(R/'evidence/original/pump/deployed.so').read_bytes(); old=(R/'repro/pump/canonical-frontier-20261028/candidate.so').read_bytes(); new=(P/'artifacts/candidate.so').read_bytes()
    blobs={sha(v):v for v in (original,old,new)}; loads=doc(d/'loader.json')['loads']
    need((txs,sigs,len(loads))==(42,84,42) and {r['elf_sha256'] for r in loads}==set(blobs), 'captured execution/signature/image totals')
    need([r['elf_sha256'] for r in loads]==[sha(original),sha(old),sha(new)]*14, 'per-case captured creation image association')
    for load in loads: check_loader(load,blobs)
    return dict(status="PASS",candidate_sha256=candidate,cases=14,executions=42,signature_fields=84,actual_captured_loads=42,source_normalization=None)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--runtime-directory',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(verify(args.candidate,args.runtime_directory),indent=2))
