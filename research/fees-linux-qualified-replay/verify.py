"""Verify retained native outputs, complete source inputs and unchanged window counts."""
from collections import Counter
from functools import lru_cache
import argparse
import difflib
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile

if not __debug__:raise RuntimeError('verification requires assertions')
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
load=lambda p:json.loads(p.read_bytes())

def source_inputs():
    expected=load(P/'inputs.json')
    with tarfile.open(P/'inputs.tar.xz')as t:
        members=t.getmembers()
        assert all(m.isfile() and not m.name.startswith('/') and '..'not in Path(m.name).parts for m in members)
        assert len({m.name for m in members})==len(members)
        values={m.name:t.extractfile(m).read()for m in members}
    assert {n:sha(b)for n,b in values.items()}==expected
    return values

def verify(original_path):
    files=[p for p in P.rglob('*')if p.is_file()]
    assert not any(p.is_symlink()for p in P.rglob('*'))
    assert {p.relative_to(P).as_posix():sha(p.read_bytes())for p in files if p.name!='manifest.json'}==load(P/'manifest.json')
    provenance=load(P/'provenance.json');original=original_path.read_bytes()
    assert sha(original)==provenance['original_sha256']
    values=source_inputs();workspace={n:b for n,b in values.items()if not n.startswith('vendor/')}
    vendor={n.removeprefix('vendor/'):b for n,b in values.items()if n.startswith('vendor/')}
    assert len(workspace)==48 and len(vendor)==18
    assert {n:sha(workspace[n])for n in provenance['qualified_source_inputs']}==provenance['qualified_source_inputs']
    bindings=load(P/'qualified-source-bindings.json')
    assert bindings['ref']==provenance['reference_commit']
    assert {n:r['sha256']for n,r in bindings['files'].items()}==provenance['qualified_source_inputs']
    for n,h in provenance['method_sha256'].items():assert sha((P/'method'/n).read_bytes())==h
    spec=importlib.util.spec_from_file_location('pinned_fees_windows',P/'method/research/fees-composed-frontier188/window_map.py')
    w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
    w.m.elf_layout=lru_cache(maxsize=6)(w.m.elf_layout)
    ow=w.windows(original);oc=Counter(r['signature']for r in ow);rawc=Counter(r['raw_sha256']for r in ow)
    assert len(ow)==585
    key='programs/pump-fees/src/lib.rs'
    before=workspace[key]
    old=b'let result = anchor_lang::solana_program::program::invoke(&ix, &infos);'
    new=b'let result: Result<()> = try { anchor_lang::solana_program::program::invoke(&ix, &infos)?; };'
    assert before.count(old)==1
    after=before.replace(old,new)
    patch=''.join(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),
        fromfile='before/'+key,tofile='after/'+key))
    assert patch.encode()==gzip.decompress((P/'crank-convert-before-drops.patch.gz').read_bytes())
    assert before.count(b'\n')==after.count(b'\n')
    reports={};control_rows=None
    for label,source in [('qualified-control',workspace),('crank-convert-before-drops',{**workspace,key:after})]:
        p=P/'builds'/label
        launch,result,saved=[load(p/n)for n in ['launch.json','result.json','measure.json']]
        symbols,stripped,log=[gzip.decompress((p/(n+'.gz')).read_bytes())for n in ['symbols.so','candidate.so','build.log']]
        assert result['exit_code']==0 and result['source_unchanged'] and result['vendor_unchanged'] and result['toolchain_unchanged']
        assert sha(symbols)==result['symbols_sha256'] and sha(stripped)==result['candidate_sha256'] and sha(log)==result['log_sha256']
        assert launch['source_inputs']=={n:sha(b)for n,b in source.items()}
        assert launch['vendor_inputs']=={n:sha(b)for n,b in vendor.items()}
        assert '--locked'in launch['command'] and '--offline'in launch['command']
        assert launch['command'][launch['command'].index('--target')+1]=='sbpf-solana-solana'
        assert log.count(b'--crate-name pump_fees_candidate ')==1 and b'Finished `release`'in log
        assert original!=stripped
        for section in w.m.elf_layout(symbols)['sections']:
            if section['flags']&2 and section['type']!=8:
                assert w.m.section_data(symbols,section['name'])==w.m.section_data(stripped,section['name'])
        cw=w.windows(symbols);cc=Counter(r['signature']for r in cw)
        assert len(cw)==586 and sum((oc&cc).values())==583
        assert sum((rawc&Counter(r['raw_sha256']for r in cw)).values())==200
        assert saved['injective_normalized']==583 and saved['raw']==200 and not saved['lost_qualified_normalized']
        for name,needle,expected_bytes in [('Crank','19pump_fees_candidate22crank_donation_fee_pda',15224 if label=='qualified-control'else 15664),
            ('CreateDonation','23create_donation_fee_pda6create',11112)]:
            rows=[r for r in cw if needle in (r.get('name')or'')];assert len(rows)==1
            assert rows[0]==saved['bodies'][name]['candidate'] and rows[0]['bytes']==expected_bytes
            assert saved['bodies'][name]['original']==next(r for r in ow if r['address']==(147944 if name=='Crank'else 163920))
            assert not saved['bodies'][name]['normalized_equal']
        if label=='qualified-control':
            expected=provenance['expected_control']
            assert sha(symbols)==expected['symbols_sha256'] and sha(stripped)==expected['candidate_sha256']
            control_rows=cw
        else:
            assert oc&cc==oc&Counter(r['signature']for r in control_rows)
        reports[label]=dict(normalized=583,raw=200,symbols_sha256=sha(symbols),candidate_sha256=sha(stripped))
    assert provenance['new_complete_original_windows']==0 and not provenance['new_vm_execution'] and not provenance['whole_elf_equal']
    return dict(verified=True,builds=reports,new_complete_original_windows=0,whole_elf_equal=False)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original',type=Path,default=P.parents[1]/'evidence/original/pump_fees/deployed.so')
    args=parser.parse_args();print(json.dumps(verify(args.original)))
