#!/usr/bin/env python3
"""Verify source/artifact/observation bindings; never compile or execute a VM."""
import argparse,difflib,gzip,hashlib,json,subprocess
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
NAME='programs/pump-fees/src/donation.rs'
FIELDS=['error','before','after','inner','transaction_base64','program_logs','events']

def sha(data):return hashlib.sha256(data).hexdigest()
def read(name):return json.loads((HERE/name).read_bytes())
def compressed(name):return json.loads(gzip.decompress((HERE/name).read_bytes()))
def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and str(p)==name and '..' not in p.parts and '\\' not in name and ':' not in name
    return p
def blob(row):
    safe(row['path']);rev=row['revision']
    assert len(rev)==40 and all(c in '0123456789abcdef'for c in rev)
    data=subprocess.check_output(['git','--no-optional-locks','show',rev+':'+row['path']],cwd=ROOT)
    assert sha(data)==row['sha256'];return data
def sources():
    baseline={name:blob(row)for name,row in read('baseline-sources.json').items()}
    control=dict(baseline);control[NAME]=blob(read('control-parent.json'))
    proposal=dict(control);proposal[NAME]=(HERE/'overrides'/NAME).read_bytes()
    old=b'**ctx.accounts.donation_fee_pda_ata.to_account_info().try_borrow_mut_lamports()? += excess;'
    assert control[NAME].count(old)==1
    assert proposal[NAME]==control[NAME].replace(old,b'ctx.accounts.donation_fee_pda_ata.add_lamports(excess)?;')
    variants=dict(baseline=baseline,control=control,proposal=proposal)
    for label,source in variants.items():
        assert len(source)==42
        for name in source:safe(name)
        assert {n:sha(b)for n,b in source.items()}==read('source-inputs.json')[label]
    for old,new in [('baseline','control'),('control','proposal')]:
        patch=''.join(difflib.unified_diff(variants[old][NAME].decode().splitlines(True),variants[new][NAME].decode().splitlines(True),fromfile='a/'+NAME,tofile='b/'+NAME))
        assert patch.encode()==(HERE/(new+'.patch')).read_bytes()
    return variants
def bindings():
    expected=read('manifest.json')
    assert not any(p.is_symlink()for p in HERE.rglob('*'))
    actual={p.relative_to(HERE).as_posix():sha(p.read_bytes())for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and'__pycache__'not in p.parts}
    assert actual==expected,'packet changed'
    for name,digest in read('validation-inputs.json').items():
        safe(name);assert sha((ROOT/name).read_bytes())==digest,name
def observations():
    hashes={};maps=read('source-inputs.json')
    for label in ['baseline','control','proposal','repeat']:
        launch=read('builds/'+label+'/launch.json');r=read('builds/'+label+'/result.json');log=(HERE/'builds'/label/'build.log').read_bytes()
        assert launch['source_inputs']==maps['proposal'if label=='repeat'else label]
        assert r['exit_code']==0 and r['source_unchanged'] and r['registry_unchanged']
        assert r['build_log_sha256']==sha(log)
        assert log.count(b'--crate-name pump_fees_candidate ')==r['root_invocations']==1
        assert log.count(b'--crate-name pump_fees_math ')==1
        assert len(launch['registry_archives'])==252 and not launch['originals_mounted']
        assert launch['command'][launch['command'].index('--network')+1]=='none'
        assert launch['fresh_dependency_target']==(label in ['baseline','repeat'])
        hashes[label]={k:v['sha256']for k,v in r['artifacts'].items()}
        if label!='repeat':
            for kind in ['candidate','symbols']:
                data=gzip.decompress((HERE/'artifacts'/(label+'-'+kind+'.so.gz')).read_bytes())
                assert sha(data)==hashes[label][kind+'.so'] and len(data)==r['artifacts'][kind+'.so']['bytes']
    assert hashes['baseline']['candidate.so']=='d85fe4eb037cd91b982eea55169faac1b342e6841ce440bee26c28b5f5617e36'
    assert hashes['proposal']==hashes['repeat']
    boundary=compressed('validation/boundary.json.gz');assert boundary['fields']==FIELDS
    assert boundary['hashes']['original']=='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
    assert boundary['case_count']==len(boundary['cases'])==76
    for label in ['control','proposal']:assert boundary['hashes'][label]==hashes[label]['candidate.so']
    failures=[]
    for row in boundary['cases']:
        results=row['results'];diff={n:[f for f in FIELDS if results['original'][f]!=results[n][f]]for n in ['control','proposal']}
        assert row['differences']==diff and not diff['proposal']
        if row['case'].get('credit_overflow'):
            assert diff['control']==['error','program_logs'];failures.append(row['case']['name'])
            assert 'ArithmeticOverflow'in results['original']['error'] and 'ProgramFailedToComplete'in results['control']['error']
            for result in results.values():
                for account in ['donation','donation_ata']:assert result['before'][account]==result['after'][account]
        else:assert not diff['control']
    assert len(failures)==15 and boundary['mismatches']==dict(control=failures,proposal=[])
    full=compressed('validation/full-validation.json.gz');sequence=compressed('validation/sequence.json.gz')
    for report in [full,sequence]:
        assert report['candidate_sha256']==hashes['proposal']['candidate.so'] and not report['mismatches']
        assert report['original_sha256']==boundary['hashes']['original']
    assert full['case_count']==17331 and len(full['suites'])==18
    assert len(sequence['steps'])==10 and not sequence['unexpected_errors']
    static=compressed('validation/static.json.gz')
    for label,r in static['reports'].items():
        assert r['candidate_sha256']==hashes[label]['candidate.so'] and r['symbols_sha256']==hashes[label]['symbols.so']
        assert (r['normalized'],r['raw'],r['unique_pairs'],r['location_uses_equal'])==(553,118,406,163)
        assert not r['crank_body_matched'] and not r['whole_capture_equal'] and not r['whole_meaningful_elf_equal']
    for r in static['transitions'].values():assert not any(r[k]for k in ['gains','losses','raw_losses','lost_equal_direct_edges'])
    overlap=compressed('pr201-overlap.json.gz');assert overlap['revision']=='bafc0a87df612e5b99849e2ab72159eafdcaf467'
    assert overlap['candidate_sha256']=='0c9fec3e80398e6f6e022a97a4fbbfeb6e0a97e66f3179594d7388fb5301e36c'
    assert len(overlap['cases'])==2
    for index,row in enumerate(overlap['cases']):
        diff=[f for f in FIELDS if row['original'][f]!=row['candidate'][f]]
        assert diff==row['differences']==(['error','program_logs']if index==0 else[])
    assert 'ArithmeticOverflow'in overlap['cases'][0]['original']['error']and'ProgramFailedToComplete'in overlap['cases'][0]['candidate']['error']
    return dict(recorded_cases=76,reproduced_error_mismatches=15,remaining_focused_mismatches=0,regression_cases=17331,persistent_steps=10,compiler_executed=False,runtime_executed=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--materialize',type=Path);p.add_argument('--variant',choices=['baseline','control','proposal'],default='proposal');a=p.parse_args()
    bindings();variants=sources();result=observations()
    if a.materialize:
        dest=a.materialize.absolute();assert not dest.exists() and not dest.is_symlink()and not any(p.is_symlink()for p in dest.parents)
        dest.mkdir(parents=True)
        for name,data in variants[a.variant].items():
            path=dest/safe(name);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        result['materialized']=str(dest)
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
