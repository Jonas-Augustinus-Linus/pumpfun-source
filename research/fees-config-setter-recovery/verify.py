"""Check exact source edits, retained binaries, callees and bounded runtime."""
from pathlib import Path
import gzip, hashlib, importlib.util, json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
load=lambda p:json.loads(p.read_text())

def main():
    manifest=load(HERE/'manifest.json')
    actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts}
    assert actual==set(manifest)
    for name,h in manifest.items():
        p=HERE/name;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,name
    for name,h in load(HERE/'parents.json').items():assert sha((ROOT/name).read_bytes())==h,name
    e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json')
    assert e['control_reused'] is True
    assert e['variants']['control']['input_sha256']==parent['variants']['origins']['input_sha256']
    for kind in ['candidate','symbols']:
        assert all(e['variants']['control']['files'][kind][k]==parent['variants']['origins']['files'][kind][k]for k in ['sha256','bytes'])
    for name,v in e['variants'].items():
        assert len(v['input_sha256'])==35 and set(v['input_sha256'])==set(v['source_paths'])
        for source,h in v['input_sha256'].items():assert sha((ROOT/v['source_paths'][source]).read_bytes())==h,source
        launch=load(HERE/f'builds/{name}-launch.json');result=load(HERE/f'builds/{name}-result.json')
        assert launch['inputs']==v['input_sha256']and result['source_unchanged']and result['exit_code']==0
        assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
        assert 'sbpf-solana-solana'in launch['command']and 'RUSTFLAGS=-Zremap-cwd-prefix='in launch['command']
        log=(HERE/f'builds/{name}-build.log').read_bytes()
        assert sha(log)==result['log_sha256']and log.count(b'--crate-name pump_fees_candidate ')==1
        assert result['candidate_sha256']==v['files']['candidate']['sha256']and result['symbols_sha256']==v['files']['symbols']['sha256']
    source='programs/pump-fees/src/lib.rs';state='programs/pump-fees/src/state.rs'
    base=(ROOT/e['variants']['control']['source_paths'][source]).read_text()
    original_state=(ROOT/e['variants']['control']['source_paths'][state]).read_text()
    lines=original_state.splitlines();assert len(lines)<361
    lines+=['']*(361-len(lines))
    lines+=['impl crate::types::FeeConfig {','    #[inline(never)]','    pub fn set_flat_fees(&mut self, flat_fees: crate::types::Fees) -> Result<()> {','        require!(flat_fees.is_valid(), crate::FeeError::InvalidFeeTotal);','        self.flat_fees = flat_fees;','        Ok(())','    }','','    #[inline(never)]','    pub fn set_exotic_flat_fees(&mut self, exotic_flat_fees: crate::types::Fees) -> Result<()> {','        require!(exotic_flat_fees.is_valid(), crate::FeeError::InvalidFeeTotal);','        self.exotic_flat_fees = exotic_flat_fees;','        Ok(())','    }','}']
    expected_state='\n'.join(lines)+'\n'
    for label in ['negative','setters','origins']:
        v=e['variants'][label]
        changed={k for k,h in e['variants']['control']['input_sha256'].items()if v['input_sha256'][k]!=h}
        assert changed==({source,state,'programs/pump-fees/src/sharing_update.rs'}if label=='origins'else{source,state})
        expected=base.replace('validate_fees(&flat_fees)?;','ctx.accounts.fee_config.set_flat_fees(flat_fees)?;').replace(' ctx.accounts.fee_config.flat_fees = flat_fees.clone();','').replace('validate_fees(&exotic_flat_fees)?;','ctx.accounts.fee_config.set_exotic_flat_fees(exotic_flat_fees)?;').replace('        ctx.accounts.fee_config.exotic_flat_fees = exotic_flat_fees.clone();\n','\n'if label!='negative'else'')
        assert (ROOT/v['source_paths'][source]).read_text()==expected
        assert (ROOT/v['source_paths'][state]).read_text()==expected_state
    assert (ROOT/e['variants']['control']['source_paths']['programs/pump-fees/src/sharing_update.rs']).read_bytes()==(ROOT/'research/fees-sharing-owned-v2/sources/control/programs/pump-fees/src/sharing_update.rs').read_bytes()
    assert (ROOT/e['variants']['origins']['source_paths']['programs/pump-fees/src/sharing_update.rs']).read_bytes()==(ROOT/'research/fees-sharing-owned-v2/sources/origins/programs/pump-fees/src/sharing_update.rs').read_bytes()
    spec=importlib.util.spec_from_file_location('setter_analysis',HERE/'analyze.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
    report=a.analyze();assert report==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
    for label,expect in e['expected'].items():
        r=report['variants'][label]
        assert len(r['unique_pairs'])==expect['unique']and len(r['unmatched_original'])==expect['unmatched']and r['candidate_windows']==expect['windows']
        assert r['unique_raw_pairs']==expect['raw'] and not r['equals_original_capture']and not r['equals_original_elf_extent']
    assert report['deltas']['setters']==dict(added_original_windows=[260568,261192],lost_original_windows=[])
    assert report['deltas']['origins']==dict(added_original_windows=[9528,44632,260568,261192,641744],lost_original_windows=[])
    cleanup=next(p for p in report['variants']['origins']['unique_pairs']if p['original']['address']==44632)
    assert cleanup['original']['raw_sha256']==cleanup['candidate']['raw_sha256']
    assert report['deltas']['negative']==dict(added_original_windows=[260568,261192],lost_original_windows=[659640,660160])
    for row,line,stores in zip(report['setters']['origins'],[365,372],[[96,88,80],[120,112,104]]):
        assert row['bytes']==624 and len(row['calls'])==5
        assert row['source_and_fields']==dict(file='programs/pump-fees/src/state.rs',line=line,field_stores=stores)
    for label in ['setters','origins']:
        runtime=json.loads(gzip.decompress((HERE/f'receipts/{label}-full.json.gz').read_bytes()))
        assert runtime['candidate_sha256']==e['variants'][label]['files']['candidate']['sha256']and runtime['case_count']==17331 and len(runtime['suites'])==18 and not runtime['mismatches']
        for suite in runtime['suites'].values():
            assert suite['original_sha256']==runtime['original_sha256']and suite['candidate_sha256']==runtime['candidate_sha256']and not suite.get('mismatches',suite.get('failures',[]))
        flags=json.loads(gzip.decompress((HERE/f'receipts/{label}-flags.json.gz').read_bytes()))
        assert flags['candidate_sha256']==runtime['candidate_sha256']and flags['original_sha256']==runtime['original_sha256']
        assert flags['case_count']==len(flags['cases'])==1542 and not flags['failures']and not flags['compute_differences']
        assert all(r['original']==r['candidate']for r in flags['cases'])
        assert {(r['cap'],r['pool'],r['flag_hex'])for r in flags['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
    from_types=load(ROOT/'research/fees-sharing-owned-legacy/experiment.json')['harness_sha256']
    assert len(from_types)==187
    for name,h in from_types.items():assert sha((ROOT/name).read_bytes())==h,name
    print('PASS: five added bodies; 362 unique pairs and 76 unmatched; ten setter callee bindings; 34,662 suite and 3,084 exact focused comparisons')
if __name__=='__main__':main()
