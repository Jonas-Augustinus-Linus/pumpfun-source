"""Check the extension-size log transform, fresh build, complete bodies and replay bindings."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def load(p):return json.loads(p.read_text())
def main():
    manifest=load(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert actual==set(manifest)
    for n,h in manifest.items():
        p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
    for n,h in load(HERE/'parents.json').items():assert sha((ROOT/n).read_bytes())==h,n
    e=load(HERE/'experiment.json');parent=load(ROOT/e['parent']/'experiment.json');base=e['variants']['control'];v=e['variants']['origins'];assert e['control_reused']
    assert base['input_sha256']==parent['variants']['origins']['input_sha256']and base['source_paths']==parent['variants']['origins']['source_paths']
    for kind in ['candidate','symbols']:assert all(base['files'][kind][k]==parent['variants']['origins']['files'][kind][k]for k in ['sha256','bytes'])
    for row in e['variants'].values():
        assert len(row['input_sha256'])==35 and set(row['input_sha256'])==set(row['source_paths'])
        for n,h in row['input_sha256'].items():assert sha((ROOT/row['source_paths'][n]).read_bytes())==h,n
    changed='programs/pump-fees/src/lib.rs'
    assert {n for n,h in base['input_sha256'].items()if v['input_sha256'][n]!=h}=={changed}
    old=(ROOT/base['source_paths'][changed]).read_text();new=(ROOT/v['source_paths'][changed]).read_text()
    before='if current_size >= 4097 { return Ok(()); }'
    after='if current_size == 4097 { msg!("Fee config account already has the correct size"); return Ok(()); } if current_size > 4097 { msg!("Fee config account already has more than {} bytes: {}", 4097usize, current_size); return Ok(()); }'
    assert old.count(before)==1 and new==old.replace(before,after)
    launch=load(HERE/'builds/origins-launch.json');result=load(HERE/'builds/origins-result.json');log=(HERE/'builds/origins-build.log').read_bytes()
    assert launch['inputs']==v['input_sha256']and result['source_unchanged']and result['exit_code']==0 and result['compiled_root']
    assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
    assert 'sbpf-solana-solana'in launch['command']and 'RUSTFLAGS=-Zremap-cwd-prefix='in launch['command']
    assert log.count(b'--crate-name pump_fees_candidate ')==1 and sha(log)==result['log_sha256']
    for kind in ['candidate','symbols']:assert result[kind+'_sha256']==v['files'][kind]['sha256']
    a=module('optional_analysis',HERE/'analyze.py');r=a.analyze();assert r==json.loads(gzip.decompress((HERE/'analysis.json.gz').read_bytes()))
    assert r['delta']==dict(added_original_windows=[52568],lost_original_windows=[])
    assert r['raw_delta']==dict(added_original_windows=[52376],lost_original_windows=[])
    for name,u,left,raw in [('control',371,65,64),('origins',372,64,64)]:
        row=r['variants'][name];assert len(row['unique_pairs'])==u and len(row['unmatched_original'])==left and row['unique_raw_pairs']==raw
        assert not row['equals_original_capture']and not row['equals_original_elf_extent']
    assert [t['raw_equal']for t in r['targets']]==[False]
    assert set(r['targets'][0]['raw_difference_offsets'])<=set(range(84,88))|set(range(388,392))|set(range(444,448))
    assert all(c['equal']for t in r['targets']for c in t['calls'])and sum(len(t['calls'])for t in r['targets'])==3
    assert all(len(x['recovered_target_calls'])==1 for x in r['callers'])
    assert r['callers'][0]['window']['signature']!=r['callers'][1]['window']['signature']
    receipts={name:json.loads(gzip.decompress((HERE/f'receipts/origins-{name}.json.gz').read_bytes()))for name in ['full','flags','precedence','optional','seeds','logs']}
    original_sha=sha((ROOT/'evidence/original/pump_fees/deployed.so').read_bytes())
    for row in receipts.values():assert row['candidate_sha256']==v['files']['candidate']['sha256']and row['original_sha256']==original_sha
    full=receipts['full'];assert full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
    for suite in full['suites'].values():assert suite['candidate_sha256']==full['candidate_sha256']and suite['original_sha256']==original_sha and not suite.get('mismatches',suite.get('failures',[]))
    flags=receipts['flags'];assert flags['case_count']==len(flags['cases'])==1542 and not flags['failures']and not flags['compute_differences']
    assert all(x['original']==x['candidate']for x in flags['cases'])
    assert {(x['cap'],x['pool'],x['flag_hex'])for x in flags['cases']}=={(cap,pool,flag)for cap in (0,1000,2**128-1)for pool in (0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
    p=module('retained_precedence_verify',ROOT/'research/fees-exotic-growth-precedence/verify.py');assert not p.check_boundary(receipts['precedence'])
    o=module('optional_cases',ROOT/'research/fees-optional-account-ownership/optional_cases.py');assert not o.validate(receipts['optional'])
    t=module('seed_cases',ROOT/'research/fees-social-seed-vector/seed_cases.py');assert not t.validate(receipts['seeds'])
    q=module('size_log_cases',HERE/'log_cases.py');assert not q.validate(receipts['logs'])
    control=json.loads(gzip.decompress((HERE/'receipts/control-logs.json.gz').read_bytes()))
    assert control['candidate_sha256']==base['files']['candidate']['sha256']and control['original_sha256']==original_sha
    assert q.validate(control)==list(range(8))
    assert all(all(x['original'][k]==x['candidate'][k]for k in q.FIELDS if k!='program_logs')for x in control['cases'])
    print('PASS: complete formatting body; 372 unique pairs / 64 residuals; 8 log discrepancies corrected; fresh regression passed')
if __name__=='__main__':main()
