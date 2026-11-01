"""Independent native, dependency, and complete-function checks."""
from pathlib import Path
from collections import Counter
from functools import lru_cache
import gzip,hashlib,importlib.util,json,tarfile
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def archive(path):
    with tarfile.open(path) as a:return {m.name:sha(a.extractfile(m).read()) for m in a.getmembers() if m.isfile()}
assert json.loads((HERE/'manifest.json').read_text())=={p.relative_to(HERE).as_posix():sha(p.read_bytes()) for p in sorted(HERE.rglob('*')) if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts}
s=importlib.util.spec_from_file_location('branch_windows',ROOT/'research/fees-composed-frontier188/window_map.py')
w=importlib.util.module_from_spec(s);s.loader.exec_module(w)
w.m.elf_layout=lru_cache(maxsize=8)(w.m.elf_layout);w.m.relocations=lru_cache(maxsize=8)(w.m.relocations)
original=(ROOT/'evidence/original/pump_fees/deployed.so').read_bytes()
parent=gzip.decompress((HERE/'qualified-symbols.so.gz').read_bytes())
assert sha(parent)=='c63bf0a47e0fba4a3845fde7c6f0056af1c592502432d7567e784eeb6de9dae3'
ow,pw=[w.windows(b) for b in [original,parent]];oc,pc=[Counter(r['signature'] for r in rows) for rows in [ow,pw]]
wanted=oc&pc;assert len(ow)==585 and sum(wanted.values())==583
vendor=archive(HERE/'macro-vendor.tar.gz');anchor=archive(HERE/'crank-anchor.tar.gz')
builds=sorted((HERE/'builds').iterdir());assert len(builds)==21
for build in builds:
    launch=json.loads((build/'launch.json').read_text());result=json.loads((build/'result.json').read_text());prior=json.loads((build/'measure.json').read_text())
    assert result['returncode']==0 and result['source_unchanged'] and result['vendor_unchanged']
    assert archive(build/'source.tar.gz')==launch['source_inputs'] and vendor==launch['vendor_inputs']
    crank=build.name.startswith('crank')
    if crank:assert result['anchor_unchanged'] and launch['anchor_inputs']==anchor
    blobs={name:gzip.decompress((build/(name+'.gz')).read_bytes()) for name in ['symbols.so','candidate.so']}
    assert sha(blobs['symbols.so'])==result['symbols_sha256'] and sha(blobs['candidate.so'])==result['candidate_sha256']
    rows=w.windows(blobs['symbols.so']);cc=Counter(r['signature'] for r in rows)
    address,needle=(147944,'19pump_fees_candidate22crank_donation_fee_pda') if crank else (163920,'19pump_fees_candidate23create_donation_fee_pda')
    a=next(x for x in ow if x['address']==address);b=next(x for x in rows if x['name'] and needle in x['name'])
    report=dict(label=build.name,original_matched=sum((oc&cc).values()),prior_retained=sum((wanted&cc).values()),candidate_windows=len(rows),target_bytes=b['bytes'],target_instructions=b['instructions'],complete_normalized_equal=a['signature']==b['signature'],whole_elf_equal=original==blobs['candidate.so'])
    assert report['target_bytes']==prior['candidate_bytes'] and report['target_instructions']==prior['candidate_instructions']
    assert sum(x['signature'] in cc for x in ow)==prior['normalized_original_windows']
    assert not report['complete_normalized_equal'] and not report['whole_elf_equal']
    assert report['original_matched']==583 and report['prior_retained']==583
    print(json.dumps(report))
print('Verified 21 native controls; no maintained checkpoint changes.')
