"""Verify retained artifacts, exact public source delta, and signed local results."""
from pathlib import Path, PurePosixPath
import argparse, base64, gzip, hashlib, importlib.util, json, subprocess, sys, tempfile
if not __debug__:
    raise RuntimeError('Assertions required; Python -O is unsupported')
sys.dont_write_bytecode = True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE))
from analyze import analyze, sha, read
from solders.transaction import Transaction

P=ROOT/'repro/pump_amm/guard-data-recovery-20261027'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
recipe=module('event_recipe',P/'workspace_recipe_v2.py')
direct=module('event_direct',P/'compare_direct_cached.py')

EXPECTED={
 'historical-control':('a4b978ee1ab15dd822a31bc42e85d55e409f4e777f7af671a3197ea175891101',599,125),
 'historical-proposal':('5e853b8419b7836af219551b3277040e584c9bae50c2222efcf8a9447337086e',600,125),
 'control-623':('badc94982f2ae20adc2a6be7fd22bba9d900c289de7c3b9e7475847af960ca7d',623,128),
 'current-proposal':('a11fbac3b2f5f7279541015a85bf09f00296cf7b26027a82b9fe73b67a69ebd1',624,128),
 'current-repeat':('a11fbac3b2f5f7279541015a85bf09f00296cf7b26027a82b9fe73b67a69ebd1',624,128),
 'latest-control':('e97b3900800d4378486d9b1f7df040e6b7a57d34b31a9470a5f5eb3a9d2fb24b',638,128),
 'latest-proposal':('2dc29037a69daa41e6482094ac4acc1ce0530c22a03c9e1feed6b1513ac92bc0',639,128),
 'latest-repeat':('2dc29037a69daa41e6482094ac4acc1ce0530c22a03c9e1feed6b1513ac92bc0',639,128)}
EXPECTED_SYMBOLS={
 'historical-control':'784592ce8c66f9d82f4b7df0d8e2e153276f8ffb7794845e7cb882d172b55ddb',
 'historical-proposal':'dbe8b0bc65d5646b3f87b5988c69ef3d25575af6099e89bce7bbc67614d59068',
 'control-623':'9c8fc5241a0e14146b843e96c798e5b4094e88ab2bd310e6e69a2bc12a091c9d',
 'current-proposal':'6627417e3fb9737d9a707486be663ec85651d64c8e45efdb1a59466d3ef27f69',
 'current-repeat':'6627417e3fb9737d9a707486be663ec85651d64c8e45efdb1a59466d3ef27f69',
 'latest-control':'4777cebca298760aa9ab599634b7fa12f27c90c951342d1d01562586ab4b1b8d',
 'latest-proposal':'32520a6f694a57a43ec303444dbc68dea058733cf29c9c0b1f2ea5f89754ffaa',
 'latest-repeat':'32520a6f694a57a43ec303444dbc68dea058733cf29c9c0b1f2ea5f89754ffaa'}

def load(packet,name):
    path=packet/name
    if not path.exists() and path.suffix=='.json':path=path.with_suffix('.json.gz')
    return json.loads(read(path))

def verify(packet):
    manifest=load(packet,'manifest.json')
    paths=list(packet.rglob('*'))
    assert not any(p.is_symlink() for p in paths),'packet symlink'
    assert all(p.is_file() or p.is_dir() for p in paths),'packet special file'
    assert {p.relative_to(packet).as_posix() for p in paths if p.is_file()}==set(manifest)|{'manifest.json'},'packet inventory'
    for name,h in manifest.items():
        n=PurePosixPath(name)
        assert not n.is_absolute() and '..' not in n.parts and n.as_posix()==name
        assert sha((packet/name).read_bytes())==h,name
    for name,h in load(packet,'repository-references.json').items():
        assert sha((ROOT/name).read_bytes())==h,('repository reference',name)
    assert (packet/'source.patch').read_bytes()==(ROOT/'research/claude-amm-mid-20261027/source.patch').read_bytes()
    source_groups=[('historical','native-fee-cpi-recovery-20261027',['historical-control'],['historical-proposal']),
      ('intermediate','account-context-recovery-20261027',['control-623'],['current-proposal','current-repeat']),
      ('latest','guard-data-recovery-20261027',['latest-control'],['latest-proposal','latest-repeat'])]
    relative='programs/pump-amm/src/instructions/swap/trade_v2.rs'
    with tempfile.TemporaryDirectory(prefix='amm-event-source-') as td:
        for kind,parent,controls,proposals in source_groups:
            _,files=recipe.expected_workspace(ROOT/'repro/pump_amm'/parent/'results/canonical-source')
            assert len(files)=={'historical':46,'intermediate':48,'latest':49}[kind]
            before={n:sha(b) for n,b in files.items()}
            scratch=Path(td)/kind;scratch.mkdir()
            for n,b in files.items():
                q=scratch/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
            subprocess.run(['git','apply',str(packet/'source.patch')],cwd=scratch,check=True,capture_output=True)
            after={p.relative_to(scratch).as_posix():sha(p.read_bytes()) for p in scratch.rglob('*') if p.is_file()}
            assert set(before)==set(after) and [n for n in before if before[n]!=after[n]]==[relative]
            assert (scratch/relative).read_bytes()==(packet/'source'/kind/'trade_v2.rs').read_bytes()
            for label in controls+proposals:
                assert load(packet,'builds/'+label+'/source-manifest.json')==(before if label in controls else after),(label,'source binding')
    report=analyze(packet)
    assert report==load(packet,'static.json'),'recomputed static results'
    assert not report['whole_capture_equal']
    for label,(digest,norm,raw) in EXPECTED.items():
        row=report['builds'][label];receipt=load(packet,'builds/'+label+'/result.json')
        assert (row['candidate_sha256'],row['normalized'],row['raw'])==(digest,norm,raw),label
        assert receipt['candidate_sha256']==digest and receipt['symbols_sha256']==row['symbols_sha256']
        assert row['symbols_sha256']==EXPECTED_SYMBOLS[label]
        assert receipt['returncode']==0 and receipt['source_unchanged'] and receipt['compiler_network']=='none'
        command=load(packet,'builds/'+label+'/command.json')
        assert command[command.index('--network')+1]=='none' and '--offline' in command and '--locked' in command
        assert 'Compiling pump-amm-recovered' in (packet/'builds'/label/'build.log').read_text()
    for prefix in ['current','latest']:
        assert report['builds'][prefix+'-proposal']==report['builds'][prefix+'-repeat']
    fresh=load(packet,'portable-build/result.json')
    assert fresh['returncode']==0 and fresh['source_unchanged'] and fresh['target_initially_empty'] and fresh['compiler_network']=='none'
    for name in ['candidate','symbols']:
        assert sha(read(packet/'portable-build'/(name+'.so.gz')))==fresh[name+'_sha256']==report['builds']['latest-proposal'][name+'_sha256']
    assert load(packet,'portable-build/source-manifest.json')==load(packet,'builds/latest-proposal/source-manifest.json')
    checked=load(packet,'portable-build/compiler-input-check.json')
    packages=json.loads((P/'results/dependency-proof/packages.json').read_text())
    assert checked['authenticated_registry_inputs']=={p['name']+'-'+p['version']+'/'+n:h for p in packages for n,h in (p['archived_files']|p['cargo_generated_cache_files']).items()}
    parent=json.loads((P/'results/build/build-comparison.json').read_text())
    assert checked['tools']=={**{n.split('/sdk/',1)[1]:h for n,h in parent['tool_sha256'].items()},**parent['target_rlib_sha256']}
    for row in report['comparisons'].values():
        assert row['gained']==[0x52c58] and row['lost']==row['raw_lost']==[]
        assert row['after']['matched_text']-row['before']['matched_text']==1784
    assert report['sell_event']['bytes']==1784 and report['sell_event']['relocations']==[]
    assert all(c['complete_normalized_callee'] for c in report['sell_event']['direct_calls'])
    runtime_results={}
    expected_suites={r['suite'] for r in json.loads((ROOT/'repro/pump_amm/pool-serialization-thirty-seven/replay-commands.json').read_text())['commands']}
    for folder,label in [('intermediate-runtime','current-proposal'),('runtime','latest-proposal')]:
        digest=EXPECTED[label][0];progress=load(packet,folder+'/progress.json');summary=load(packet,folder+'/summary.json')
        assert len(progress)==25 and {r['suite'] for r in progress}==expected_suites
        assert summary['candidate_sha256']==digest and summary['cases']==17462 and summary['inputs_unchanged']
        for run in progress:
            assert run['returncode']==0 and not run['mismatches']
            p=packet/folder/(run['suite']+'.json')
            if not p.exists():p=p.with_suffix('.json.gz')
            assert sha(read(p))==run['receipt_sha256']
            assert sha((packet/folder/(run['suite']+'-transactions.json.gz')).read_bytes())==run['sidecar_sha256']
        check=direct.audit(packet/folder,digest)
        assert check['cases']==17462 and check['transactions']==35074 and check['signature_fields']==35418 and check['identical_signed_message_pairs']==17537 and not check['mismatches']
        runtime_results[folder]=check
    focused={}
    for folder,label in [('intermediate-focused','current-proposal'),('focused','latest-proposal')]:
        digest=EXPECTED[label][0]
        for name,count in [('sell',10),('buy',16)]:
            data=load(packet,folder+'/'+name+'.json');side=load(packet,folder+'/'+name+'-transactions.json.gz')
            assert data['candidate_sha256']==digest and data['case_count']==len(data['cases'])==count and data['mismatch_count']==0
            assert len(side['transactions'])==side['transaction_count']==2*count
            assert side['script_sha256']==data['probe_sha256']==sha((P/('probe_'+name+'_events.py')).read_bytes())
            for i,row in enumerate(data['cases']):
                assert direct.clean(row['original'])==direct.clean(row['candidate']) and not row['mismatched_fields']
                messages=[]
                for txr,which,want in zip(side['transactions'][2*i:2*i+2],['original','candidate'],[report['original_sha256'],digest]):
                    raw=base64.b64decode(txr['transaction_base64'],validate=True);tx=Transaction.from_bytes(raw)
                    assert all(tx.verify_with_results()) and txr['all_signatures_verified']
                    assert sha(raw)==txr['transaction_sha256'] and txr['amm_program_sha256']==want
                    assert len(tx.signatures)==txr['signature_count']
                    assert txr['logs_sha256']==sha(json.dumps(row[which]['logs'],separators=(',',':')).encode())
                    messages.append(bytes(tx.message))
                assert messages[0]==messages[1]
            focused[folder+'/'+name]=count
    return {'verified':True,'static':report['comparisons'],'runtime':runtime_results,'focused':focused,'scope':'Saved evidence verification; no fresh compiler or VM execution.'}

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--packet',type=Path,default=HERE)
    args=ap.parse_args();print(json.dumps(verify(args.packet.resolve()),indent=2))
