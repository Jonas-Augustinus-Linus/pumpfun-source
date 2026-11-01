"""Verify the Fees whole-ELF end-state packet (diagnostic evidence, no reconstruction claim).

Run from the repository root:  python3 -B research/claude-fees100-whole-elf-endstate-20261027/verify.py
Standard library only; runs the packet's elfinv.py inventory on the accepted 582-function parent artifacts.
Executes no compiler, linker or target program.
"""
from pathlib import Path
import gzip, hashlib, json, subprocess, sys, tempfile
if not __debug__:
    raise RuntimeError('verification requires assertions; do not run under python -O')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sha = lambda b: hashlib.sha256(b).hexdigest()

def check_manifest():
    paths = list(HERE.rglob('*'))
    assert not any(p.is_symlink() for p in paths), 'packet contains a symlink'
    assert all(p.is_dir() or p.is_file() for p in paths), 'packet contains a special file'
    actual = {p.relative_to(HERE).as_posix(): sha(p.read_bytes()) for p in paths
              if p.is_file() and p.relative_to(HERE).as_posix() != 'manifest.json'}
    assert actual == json.loads((HERE / 'manifest.json').read_text()), 'manifest mismatch (extra, missing or changed file)'

def verify():
    check_manifest()
    original = (ROOT / 'evidence/original/pump_fees/deployed.so').read_bytes()
    extent = 873256
    assert not any(original[extent:]), 'bytes after the meaningful ELF extent are not all zero'
    # 1. the diagnostic transplant relink produced exactly the original meaningful ELF
    result = json.loads((HERE / 'transplant/transplant3-result.json').read_text())
    assert result['exit_code'] == 0
    assert result['candidate_sha256'] == sha(original[:extent]), 'transplant relink != original meaningful ELF'
    report = json.loads((HERE / 'transplant/transplant3-report.json').read_text())
    assert sorted(w['window'] for w in report['windows']) == [120816, 147944, 163920]
    obj = gzip.decompress((HERE / 'transplant/transplant3.o.gz').read_bytes())
    assert obj[:4] == b'\x7fELF'
    # 2. re-run the whole-ELF inventory on the accepted 582-function parent: no independent difference
    parent = ROOT / 'research/fees-extend-integration/builds/candidate'
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'c.so').write_bytes(gzip.decompress((parent / 'candidate.so.gz').read_bytes()))
        (tmp / 's.so').write_bytes(gzip.decompress((parent / 'symbols.so.gz').read_bytes()))
        subprocess.run([sys.executable, '-I', '-B', str(HERE / 'tools/elfinv.py'), str(tmp / 'c.so'), '--symbols',
                        str(tmp / 's.so'), '--json', str(tmp / 'inv.json'), '--quiet'], check=True,
                       stdout=subprocess.DEVNULL)
        inv = json.loads((tmp / 'inv.json').read_text())
    saved = json.loads((HERE / 'reports/w582-elfinv.json').read_text())
    assert inv['candidate']['sha256'] == saved['candidate']['sha256'] == sha(gzip.decompress((parent / 'candidate.so.gz').read_bytes()))
    assert inv['B_independent'] == [] == saved['B_independent'], inv['B_independent']
    assert inv['A_consequences'] == saved['A_consequences']
    assert inv['.rodata_equal'] and inv['.dynstr_equal'] and inv['.shstrtab_equal']
    return dict(transplant_equals_original_extent=True, extent=extent, parent_independent_differences=0,
                parent_consequence_items=len(inv['A_consequences']), rodata_equal=True)

if __name__ == '__main__':
    print(json.dumps(verify(), indent=1))
