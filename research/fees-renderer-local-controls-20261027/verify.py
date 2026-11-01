"""Verify retained normal-build artifacts and independent Fees measurements."""
from pathlib import Path
import gzip,hashlib,json,tarfile,tempfile,importlib.util
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def digest(b):return hashlib.sha256(b).hexdigest()
def archive_inputs(path):
    with tarfile.open(path) as a:
        return {m.name:digest(a.extractfile(m).read()) for m in a.getmembers() if m.isfile()}
manifest=json.loads((HERE/'manifest.json').read_text())
assert manifest=={p.relative_to(HERE).as_posix():digest(p.read_bytes()) for p in sorted(HERE.rglob('*')) if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts}
spec=importlib.util.spec_from_file_location('retained_remote_recipe',HERE/'remote_recipe.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r);r.REPO=ROOT
w=r.reader();vendor=archive_inputs(HERE/'macro-vendor.tar.gz')
assert digest(gzip.decompress((HERE/'qualified-symbols.so.gz').read_bytes()))=='c63bf0a47e0fba4a3845fde7c6f0056af1c592502432d7567e784eeb6de9dae3'
with tempfile.TemporaryDirectory() as temporary:
    r.WORK=Path(temporary)
    (r.WORK/'qualified-symbols.so.gz').write_bytes((HERE/'qualified-symbols.so.gz').read_bytes())
    builds=sorted((HERE/'builds').iterdir());assert len(builds)==9
    for build in builds:
        launch=json.loads((build/'launch.json').read_text())
        assert archive_inputs(build/'source.tar.gz')==launch['source_inputs']
        assert vendor==launch['vendor_inputs']
        result=json.loads((build/'result.json').read_text())
        assert result['returncode']==0 and result['source_unchanged'] and result['vendor_unchanged']
        out=r.WORK/build.name;out.mkdir()
        for name in ['symbols.so','candidate.so']:
            data=gzip.decompress((build/(name+'.gz')).read_bytes());(out/name).write_bytes(data)
            assert digest(data)==result['symbols_sha256' if name=='symbols.so' else 'candidate_sha256']
        measured=r.measure(out,w)
        assert json.loads(json.dumps(measured))==json.loads((build/'measurement.json').read_text())
        assert measured['original_matched']==583 and not measured['create_full_normalized_equal']
print('Verified 9 native builds, 8 source controls, retained 583/585; no frontier promotion.')
