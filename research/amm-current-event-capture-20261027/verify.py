"""Verify the current-parent event composition from exact saved inputs and receipts."""
from pathlib import Path
import argparse,base64,gzip,hashlib,importlib.util,json,subprocess,sys,tempfile
if not __debug__:
    raise RuntimeError('Verification requires assertions; Python -O is unsupported')
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):
    b=p.read_bytes();return gzip.decompress(b) if p.suffix=='.gz' else b
def load(p):
    if not p.exists() and p.suffix=='.json':p=p.with_suffix('.json.gz')
    return json.loads(read(p))
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def verify(packet):
    paths=list(packet.rglob('*'))
    assert not any(p.is_symlink() for p in paths),'packet symlink'
    assert all(p.is_file() or p.is_dir() for p in paths),'packet special file'
    actual={p.relative_to(packet).as_posix():sha(p.read_bytes()) for p in paths if p.is_file() and p!=packet/'manifest.json'}
    assert actual==load(packet/'manifest.json'),'packet inventory/hashes'
    for name,digest in load(packet/'external-inputs.json').items():assert sha((ROOT/name).read_bytes())==digest,('external input',name)
    parent=ROOT/'repro/pump_amm/source-abi-recovery-20261027'
    helper=module('event_comparison',ROOT/'research/amm-event-capture-independent-replay/analyze.py')
    recipe=module('event_source_recipe',parent/'workspace_recipe_v2.py')
    direct=module('event_direct',parent/'compare_direct_cached.py')
    digest='dc6365752c9b2d8d5b3b2f304285f1b5a92ef10d9e2eedf4d705aae87715db53'
    symbols_digest='1da44eed6c1226dbba63733e39a1684ce65f2759037e672e28419e8bff63a499'
    assert (packet/'source.patch').read_bytes()==(ROOT/'research/amm-event-capture-independent-replay/source.patch').read_bytes()
    _,files=recipe.expected_workspace(parent/'results/canonical-source');assert len(files)==51
    before={n:sha(b) for n,b in files.items()}
    with tempfile.TemporaryDirectory(prefix='amm-event-current-') as td:
        stage=Path(td)/'source';stage.mkdir()
        for name,b in files.items():p=stage/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        subprocess.run(['git','apply',str(packet/'source.patch')],cwd=stage,check=True,capture_output=True)
        after={p.relative_to(stage).as_posix():sha(p.read_bytes()) for p in stage.rglob('*') if p.is_file()}
        changed='programs/pump-amm/src/instructions/swap/trade_v2.rs'
        assert set(before)==set(after) and [n for n in before if before[n]!=after[n]]==[changed]
        assert (stage/changed).read_bytes()==(packet/'source/trade_v2.rs').read_bytes()
        for label in ['first','repeat']:
            path=packet/'builds'/label;r=load(path/'result.json')
            assert r['returncode']==0 and r['source_unchanged'] and r['compiler_network']=='none'
            assert r['candidate_sha256']==sha(read(path/'candidate.so.gz'))==digest
            assert r['symbols_sha256']==sha(read(path/'symbols.so.gz'))==symbols_digest
            assert load(path/'source-manifest.json')==after
            command=load(path/'command.json')
            assert '--offline' in command and '--locked' in command and command[command.index('--network')+1]=='none'
            assert 'Compiling pump-amm-recovered' in read(path/'build.log.gz').decode()
            if label=='first':assert r['target_initially_empty'] is True
            else:assert r['target_initially_empty'] is False and r['root_package_cleaned'] is True
            packages=load(parent/'results/dependency-proof/packages.json')
            check=load(path/'compiler-input-check.json')
            assert check['authenticated_registry_inputs']=={p['name']+'-'+p['version']+'/'+n:h for p in packages for n,h in (p['archived_files']|p['cargo_generated_cache_files']).items()}
            assert len(check['authenticated_registry_inputs'])==169
        original=helper.Elf(ROOT/'evidence/original/pump_amm/deployed.so')
        for name in ['candidate','symbols']:(Path(td)/(name+'.so')).write_bytes(read(packet/'builds/first'/(name+'.so.gz')))
        candidate=helper.Elf(Path(td)/'candidate.so');symbols=helper.Elf(Path(td)/'symbols.so')
        rows=helper.windows(original,candidate,symbols);assert rows==load(packet/'window-inventory.json.gz')
        base=parent/'results/build';previous=helper.windows(original,helper.Elf(base/'candidate.so'),helper.Elf(base/'unstripped.so'))
        matched=lambda data:{r['start'] for r in data if r['matches']}
        raw=lambda data:{r['start'] for r in data if r['raw_match']}
        result=helper.summarize(rows)
        result.update(before=helper.summarize(previous),gained=sorted(matched(rows)-matched(previous)),lost=sorted(matched(previous)-matched(rows)),raw_lost=sorted(raw(previous)-raw(rows)),candidate_sha256=digest,symbols_sha256=symbols_digest,whole_elf_equal=candidate.b==original.b)
        assert result==load(packet/'measurement.json')
        assert result['normalized']==641 and result['raw']==128 and result['matched_text']==800816
        assert result['before']=={'normalized':640,'raw':128,'matched_text':799032}
        assert result['gained']==[0x52c58] and not result['lost'] and not result['raw_lost'] and not result['whole_elf_equal']
        event=next(r for r in rows if r['start']==0x52c58);assert event['end']-event['start']==1784 and len(event['matches'])==1
        dest=event['matches'][0]['start'];left=original.callsites(event['start'],1784);right=candidate.callsites(dest,1784);assert len(left)==len(right)==3
        ends=dict(zip(original.entries,original.entries[1:]+[original.hi]))
        for a,b in zip(left,right):
            n=ends[a['target']]-a['target'];assert a['offset']==b['offset']
            assert any(f['start']==b['target'] and f['size']==n for f in symbols.funcs)
            assert original.normalized[a['target']:a['target']+n]==candidate.normalized[b['target']:b['target']+n]
            assert original.pattern(a['target'],n)==candidate.pattern(b['target'],n)
        assert original.pattern(event['start'],1784)==candidate.pattern(dest,1784)==[]
    runtime=packet/'runtime';summary=load(runtime/'summary.json');assert summary['candidate_sha256']==digest and summary['suites']==25 and summary['cases']==17462 and summary['inputs_unchanged']
    expected_suites={r['suite'] for r in load(ROOT/'repro/pump_amm/pool-serialization-thirty-seven/replay-commands.json')['commands']}
    progress=load(runtime/'progress.json');assert len(progress)==25 and {r['suite']for r in progress}==expected_suites
    for name,h in summary['harness_sha256'].items():assert sha((ROOT/name).read_bytes())==h
    for run in progress:
        assert run['returncode']==0 and not run['mismatches']
        assert sha(read(runtime/(run['suite']+'.json.gz')))==run['receipt_sha256']
        assert sha((runtime/(run['suite']+'-transactions.json.gz')).read_bytes())==run['sidecar_sha256']
    audit=direct.audit(runtime,digest);assert audit==load(runtime/'direct-audit.json')
    assert audit['cases']==17462 and audit['transactions']==35074 and audit['signature_fields']==35418 and audit['identical_signed_message_pairs']==17537 and not audit['mismatches']
    from solders.transaction import Transaction
    for name,count in [('sell',10),('buy',16)]:
        data=load(packet/'focused'/(name+'.json'));side=load(packet/'focused'/(name+'-transactions.json.gz'))
        assert data['candidate_sha256']==digest and data['case_count']==len(data['cases'])==count and data['mismatch_count']==0
        assert side['transaction_count']==len(side['transactions'])==2*count
        assert data['probe_sha256']==side['script_sha256']==sha((parent/('probe_'+name+'_events.py')).read_bytes())
        for i,row in enumerate(data['cases']):
            assert direct.clean(row['original'])==direct.clean(row['candidate']) and not row['mismatched_fields']
            messages=[]
            for txr,which,want in zip(side['transactions'][2*i:2*i+2],['original','candidate'],[summary['original_sha256'],digest]):
                raw_tx=base64.b64decode(txr['transaction_base64'],validate=True);tx=Transaction.from_bytes(raw_tx)
                assert all(tx.verify_with_results()) and txr['all_signatures_verified']
                assert sha(raw_tx)==txr['transaction_sha256'] and txr['amm_program_sha256']==want and len(tx.signatures)==txr['signature_count']
                assert txr['logs_sha256']==sha(json.dumps(row[which]['logs'],separators=(',',':')).encode())
                messages.append(bytes(tx.message))
            assert messages[0]==messages[1]
    return {'verified':True,**result,'runtime':audit,'focused_pairs':26,'scope':'Saved current-parent research evidence. No selected-source promotion or whole-ELF identity.'}
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--packet',type=Path,default=HERE);a=ap.parse_args();print(json.dumps(verify(a.packet.resolve()),indent=2))
