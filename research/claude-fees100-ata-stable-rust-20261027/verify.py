"""Verify the stable-Rust ATA equivalence packet.

Run from the repository root:  python3 -B research/claude-fees100-ata-stable-rust-20261027/verify.py
Standard library only. Executes no compiler or target program.
"""
from pathlib import Path
import gzip, hashlib, json, sys
if not __debug__:
    raise RuntimeError('verification requires assertions; do not run under python -O')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT = ROOT / 'research/fees-extend-integration'
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
    claims = json.loads((HERE / 'claims.json').read_text())
    candidate = gzip.decompress((HERE / 'builds/linux/candidate.so.gz').read_bytes())
    symbols = gzip.decompress((HERE / 'builds/linux/symbols.so.gz').read_bytes())
    for role in ['linux', 'repeat']:
        result = json.loads((HERE / 'builds' / role / 'result.json').read_text())
        assert result['exit_code'] == 0
        assert result['candidate_sha256'] == sha(candidate) and result['symbols_sha256'] == sha(symbols), role
    parent_candidate = gzip.decompress((PARENT / 'builds/candidate/candidate.so.gz').read_bytes())
    parent_symbols = gzip.decompress((PARENT / 'builds/candidate/symbols.so.gz').read_bytes())
    assert sha(parent_candidate) == claims['parent_candidate_sha256']
    assert candidate == parent_candidate, 'stripped ELF differs from the accepted 582-function parent'
    assert claims['stripped_identical_to_parent'] is True
    same_symbols = symbols == parent_symbols
    assert same_symbols == claims['symbols_identical_to_parent']
    for name, digest in claims['stable_file_sha256'].items():
        text = (HERE / 'overrides' / name).read_bytes()
        assert sha(text) == digest, name
        assert b'try_blocks' not in text and b'= try {' not in text, name
    mod = (HERE / 'overrides' / claims['changed_files'][0]).read_text()
    assert "'create: { let true = associated_account.owner == &anchor_lang::system_program::ID else { break 'create };" in mod
    lib = (HERE / 'overrides' / claims['changed_files'][1]).read_text()
    assert lib.startswith('#![feature(core_intrinsics)] ')
    return dict(stripped_identical_to_parent=True, symbols_identical_to_parent=same_symbols,
                candidate_sha256=sha(candidate), feature_try_blocks_removed=True)

if __name__ == '__main__':
    print(json.dumps(verify(), indent=1))
