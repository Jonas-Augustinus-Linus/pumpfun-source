"""Verify compiled artifacts and the separately executed precedence matrix."""
from pathlib import Path
import difflib,gzip,hashlib,importlib.util,itertools,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
load=lambda p:json.loads(p.read_text())
def check_boundary(r):
    assert r['fields']==['error','data_hex','lamports','owner','balance_deltas','events','inner_instructions']
    assert r['case_count']==len(r['cases'])==24
    expected={(a,l,b,f)for a,l,b,f in itertools.product([2512,4097],[1,10**9],[1,10**9],[(1,2,3),(10001,0,0),(2**64-1,1,0)])}
    assert {(x['case']['allocation'],x['case']['lamports'],x['authority_lamports'],tuple(x['fees']))for x in r['cases']}==expected
    mismatches=[]
    for i,x in enumerate(r['cases']):
        equal=all(x['original'][k]==x['candidate'][k]for k in r['fields']);assert x['match']==equal
        if not equal:mismatches.append(i)
    assert r['mismatches']==mismatches
    return mismatches

def main():
    manifest=load(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert actual==set(manifest)
    for n,h in manifest.items():
        p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
    for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
    e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json');base=e['variants']['control'];assert e['control_reused']and base['input_sha256']==parent['variants']['origins']['input_sha256']
    for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['variants']['origins']['files'][kind][k]for k in ['sha256','bytes'])
    root='programs/pump-fees/src/lib.rs';old=(ROOT/base['source_paths'][root]).read_text();diffs={}
    for label,v in e['variants'].items():
        assert len(v['input_sha256'])==35 and set(v['input_sha256'])==set(v['source_paths'])
        for n,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][n]).read_bytes())==h,n
        launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes();assert launch['inputs']==v['input_sha256']and result['source_unchanged']and result['exit_code']==0
        assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command'];assert log.count(b'--crate-name pump_fees_candidate ')==1 and sha(log)==result['log_sha256'];assert result['candidate_sha256']==v['files']['candidate']['sha256']and result['symbols_sha256']==v['files']['symbols']['sha256']
        if label!='control':
            assert {n for n,h in base['input_sha256'].items()if v['input_sha256'][n]!=h}=={root}
            text=(ROOT/v['source_paths'][root]).read_text();diffs[label]={root:''.join(difflib.unified_diff(old.splitlines(True),text.splitlines(True),fromfile='control/'+root,tofile=label+'/'+root))}
    assert diffs==load(HERE/'source-diffs.json')
    a=old.index('pub fn set_exotic_flat_fees(');b=old.index('\n    #[allow',a);part=old[a:b];call='        ctx.accounts.fee_config.set_exotic_flat_fees(exotic_flat_fees)?;';assert part.count(call)==1;part=part.replace(call,'');mark='\n\n        let event = SetExoticFlatFeesEvent';assert part.count(mark)==1;part=part.replace(mark,'\n'+call+'\n        let event = SetExoticFlatFeesEvent').replace('info.realloc(4097, true)?','info.realloc(4097, false)?');expected=old[:a]+part+old[b:];assert (ROOT/e['variants']['origins']['source_paths'][root]).read_text()==expected and len(expected.splitlines())==len(old.splitlines())
    spec=importlib.util.spec_from_file_location('exotic_analysis',HERE/'analyze.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);report=m.analyze();assert report==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
    for label,r in report['variants'].items():assert len(r['unique_pairs'])==368 and len(r['unmatched_original'])==68 and not r['equals_original_capture']and not r['equals_original_elf_extent']and not r['exotic']['complete_body_match']
    assert all(not d['added_original_windows']and not d['lost_original_windows']for d in report['deltas'].values())
    assert report['original_exotic']['realloc_zero_init']==0 and report['original_exotic']['data_len_dominates_validation']
    assert report['variants']['control']['exotic']['realloc_zero_init']==1 and not report['variants']['control']['exotic']['data_len_dominates_validation']
    assert report['variants']['origins']['exotic']['realloc_zero_init']==0 and report['variants']['origins']['exotic']['data_len_dominates_validation']
    assert report['variants']['argument_order']['exotic']['bytes']==5520
    for label,failures in [('control',[1,2,4,5]),('late',[4,5]),('nozero',[]),('origins',[])]:
        r=json.loads(gzip.decompress((HERE/f'receipts/{label}-precedence.json.gz').read_bytes()));assert r['candidate_sha256']==e['variants'][label]['files']['candidate']['sha256'];assert check_boundary(r)==failures
    full=json.loads(gzip.decompress((HERE/'receipts/origins-full.json.gz').read_bytes()));assert full['candidate_sha256']==e['variants']['origins']['files']['candidate']['sha256']and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
    for s in full['suites'].values():assert s['candidate_sha256']==full['candidate_sha256']and s['original_sha256']==full['original_sha256']and not s.get('mismatches',s.get('failures',[]))
    flags=json.loads(gzip.decompress((HERE/'receipts/origins-flags.json.gz').read_bytes()));assert flags['candidate_sha256']==full['candidate_sha256']and flags['original_sha256']==full['original_sha256']and flags['case_count']==len(flags['cases'])==1542 and not flags['failures']and not flags['compute_differences'];assert all(x['original']==x['candidate']for x in flags['cases'])
    assert {(x['cap'],x['pool'],x['flag_hex'])for x in flags['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
    for n,h in load(ROOT/'research/fees-sharing-owned-legacy/experiment.json')['harness_sha256'].items():assert sha((ROOT/n).read_bytes())==h,n
    print('PASS: 24 boundary cases; four control disagreements corrected; 17,331 suite and 1,542 exact cases; no new body matches')
if __name__=='__main__':main()
