"""Verify source-only event changes, exact body checks and bounded replay."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
load=lambda p:json.loads(p.read_text())
NAMES=['update_fee_config','upsert_fee_tiers','update_stable_fee_config','upsert_stable_fee_tiers']
def transform(text,admin):
    for name in NAMES:
        start=text.index('pub fn '+name+'(');end=text.index('\n    #[allow',start);part=text[start:end];assert part.count('emit!(event.clone())')==1
        part=part.replace('emit!(event.clone())','emit!(event)')
        if admin:
            assert part.count('ctx.accounts.admin.key()')==1
            part=part.replace('ctx.accounts.admin.key()','ctx.accounts.fee_config.admin')
        text=text[:start]+part+text[end:]
    return text

def main():
    manifest=load(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert actual==set(manifest)
    for n,h in manifest.items():
        p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
    for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
    e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json');assert e['control_reused']and e['variants']['control']['input_sha256']==parent['variants']['origins']['input_sha256']
    for kind in ['candidate','symbols']:assert all(e['variants']['control']['files'][kind][k]==parent['variants']['origins']['files'][kind][k]for k in ['sha256','bytes'])
    for name,v in e['variants'].items():
        assert len(v['input_sha256'])==35 and set(v['input_sha256'])==set(v['source_paths'])
        for n,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][n]).read_bytes())==h,n
        launch=load(HERE/f'builds/{name}-launch.json');result=load(HERE/f'builds/{name}-result.json');log=(HERE/f'builds/{name}-build.log').read_bytes()
        assert launch['inputs']==v['input_sha256']and result['source_unchanged']and result['exit_code']==0
        assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
        assert 'sbpf-solana-solana'in launch['command']and 'RUSTFLAGS=-Zremap-cwd-prefix='in launch['command']
        assert sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
        assert result['candidate_sha256']==v['files']['candidate']['sha256']and result['symbols_sha256']==v['files']['symbols']['sha256']
    root='programs/pump-fees/src/lib.rs';base=e['variants']['control'];old=(ROOT/base['source_paths'][root]).read_text()
    for name in ['borrow','origins']:
        v=e['variants'][name];assert {k for k,h in base['input_sha256'].items()if v['input_sha256'][k]!=h}=={root}
        text=(ROOT/v['source_paths'][root]).read_text();assert text==transform(old,name=='origins')and len(text.splitlines())==len(old.splitlines())
    context=(ROOT/base['source_paths']['programs/pump-fees/src/contexts.rs']).read_text()
    for name in ['UpdateFeeConfig','UpdateStableFeeConfig','UpsertFeeTiers','UpsertStableFeeTiers']:
        part=context[context.index('pub struct '+name+"<'info>"):];part=part[:part.index('\n}')]
        assert 'has_one = admin @ FeeError::InvalidAdmin'in part
    spec=importlib.util.spec_from_file_location('event_analysis',HERE/'analyze.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a);r=a.analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
    for name,expect in e['expected'].items():
        row=r['variants'][name];assert len(row['unique_pairs'])==expect['unique']and len(row['unmatched_original'])==expect['unmatched']and row['candidate_windows']==expect['windows'];assert not row['equals_original_capture']and not row['equals_original_elf_extent']
    assert r['deltas']==dict(borrow=dict(added_original_windows=[],lost_original_windows=[]),origins=dict(added_original_windows=[98232,100840,115160,117688],lost_original_windows=[]))
    assert sum(len(x['calls'])for x in r['callers'])==49 and [x['selection']for x in r['callers']]==['body_unique','body_unique','outgoing_callee_disambiguated','outgoing_callee_disambiguated']
    assert all(all(c['equal']for c in x['calls'])for x in r['callers'])
    assert all(x['rejected'][0]['conflicting_call_offsets']==[120,448,912]for x in r['callers'][2:])
    full=json.loads(gzip.decompress((HERE/'receipts/origins-full.json.gz').read_bytes()));assert full['candidate_sha256']==e['variants']['origins']['files']['candidate']['sha256']and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
    for s in full['suites'].values():assert s['candidate_sha256']==full['candidate_sha256']and s['original_sha256']==full['original_sha256']and not s.get('mismatches',s.get('failures',[]))
    flags=json.loads(gzip.decompress((HERE/'receipts/origins-flags.json.gz').read_bytes()));assert flags['case_count']==len(flags['cases'])==1542 and flags['candidate_sha256']==full['candidate_sha256']and flags['original_sha256']==full['original_sha256']and not flags['failures']and not flags['compute_differences'];assert all(x['original']==x['candidate']for x in flags['cases']);assert {(x['cap'],x['pool'],x['flag_hex'])for x in flags['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
    for n,h in load(ROOT/'research/fees-sharing-owned-legacy/experiment.json')['harness_sha256'].items():assert sha((ROOT/n).read_bytes())==h,n
    print('PASS: four caller bodies; 368 unique pairs and 68 unmatched; 49 callee bindings; 17,331 suite and 1,542 exact focused comparisons')
if __name__=='__main__':main()
