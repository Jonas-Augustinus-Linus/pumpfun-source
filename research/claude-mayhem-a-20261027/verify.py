#!/usr/bin/env python3
"""Verify Layer A (safe-Rust O0193 initializer form) — standard library only.

Checks, reading only files inside this repository (no HOME, network, compiler or VM):
1. The shipped Layer A ELFs decompress to the recorded SHA-256 values and are
   byte-for-byte equal to the parent's published artifacts
   (research/mayhem-quotes-current-recovery-20261027/builds/current/*.so.gz).
2. Materializing the safe-Rust source — the parent's src/state.rs with this
   packet's source.patch applied by a small exact-context patcher — reproduces the
   shipped source/src/state.rs, whose hash is the one recorded for src/state.rs in
   layers/initializer-safe-form/source-inputs.json.
3. Every other one of the 67 source inputs is unchanged from the parent's
   source-inputs.json, and the patch touches only src/state.rs.
4. The materialized source contains no `unsafe`, `MaybeUninit` or `repr(C)` in the
   initializer region, and keeps the two Location lines 531/532 byte-identical to the
   parent.

usage: python3 -I -B research/claude-mayhem-a-20261027/verify.py [--repository-root R]
"""
import argparse, gzip, hashlib, json, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STRIPPED = '73dff97e65535ce7d2552ba6f29f94fe0e08ebd414a51871a81c6cba2d7d6168'
SYMBOLS = '440b92811753dd9af1468f6bf2d0e9139309984de3519a8f9a937babfdb6c903'
PARENT = 'research/mayhem-quotes-current-recovery-20261027'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def apply_patch(original: str, patch: str, path: str) -> str:
    """Apply the unified-diff hunks for `path` with exact context matching."""
    files = re.split(r'(?m)^--- ', patch)
    target = [f for f in files if f.startswith('a/' + path + '\t') or f.startswith('a/' + path + '\n')]
    assert len(target) == 1, f'expected one diff for {path}'
    body = target[0].split('\n', 2)[2]  # drop '--- a/..' and '+++ b/..' lines
    src = original.split('\n')
    out, pos = [], 0
    for hunk in re.split(r'(?m)^(?=@@ )', body):
        if not hunk.startswith('@@ '):
            continue
        m = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', hunk)
        start = int(m.group(1)) - 1
        lines = hunk.split('\n')[1:]
        if lines and lines[-1] == '':
            lines = lines[:-1]
        out.extend(src[pos:start])
        pos = start
        for ln in lines:
            if ln.startswith('\\'):
                continue
            tag, text = ln[:1], ln[1:]
            if tag == ' ':
                assert src[pos] == text, (path, pos + 1, 'context mismatch')
                out.append(text); pos += 1
            elif tag == '-':
                assert src[pos] == text, (path, pos + 1, 'removal mismatch')
                pos += 1
            elif tag == '+':
                out.append(text)
            else:
                raise AssertionError(f'bad hunk line {ln!r}')
    out.extend(src[pos:])
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repository-root', type=Path, default=HERE.parents[1])
    root = ap.parse_args().repository_root.resolve()
    layer = HERE / 'layers/initializer-safe-form'
    checks = {}

    # 1. artifacts
    for name, want in [('candidate.so', STRIPPED), ('symbols.so', SYMBOLS)]:
        mine = gzip.decompress((layer / 'artifacts' / (name + '.gz')).read_bytes())
        parent = gzip.decompress((root / PARENT / 'builds/current' / (name + '.gz')).read_bytes())
        assert sha(mine) == want, (name, sha(mine))
        assert mine == parent, f'{name} differs from parent'
        checks[name] = dict(sha256=want, bytes=len(mine), equal_to_parent=True)

    # 2. source materialization
    parent_inputs = json.loads((root / PARENT / 'source-inputs.json').read_text())
    parent_state = (root / PARENT / 'overrides/src/state.rs').read_bytes()
    assert sha(parent_state) == parent_inputs['src/state.rs'], 'parent override is not the parent state.rs'
    patch = (layer / 'source.patch').read_text()
    touched = sorted(set(re.findall(r'(?m)^\+\+\+ b/(\S+)', patch)))
    assert touched == ['src/state.rs'], touched
    materialized = apply_patch(parent_state.decode(), patch, 'src/state.rs').encode()
    shipped = (layer / 'source/src/state.rs').read_bytes()
    assert materialized == shipped, 'materialized source differs from shipped source'
    mine_inputs = json.loads((layer / 'source-inputs.json').read_text())
    assert sha(shipped) == mine_inputs['src/state.rs']
    # 3. all other inputs unchanged
    assert set(mine_inputs) == set(parent_inputs) and len(mine_inputs) == 67
    changed = sorted(k for k in mine_inputs if mine_inputs[k] != parent_inputs[k])
    assert changed == ['src/state.rs'], changed
    checks['source'] = dict(state_rs_sha256=sha(shipped), changed_inputs=changed, inputs=len(mine_inputs))

    # 4. plain safe Rust in the initializer region; Location lines kept
    text = shipped.decode().split('\n')
    region = '\n'.join(text[525:550])
    for bad in ('unsafe', 'MaybeUninit', 'repr(C)'):
        assert bad not in region, bad
    ptext = parent_state.decode().split('\n')
    assert text[530] == ptext[530] and text[531] == ptext[531], 'Location lines 531/532 changed'
    assert 'let mut mint_key=Pubkey::default();' in text[527] and 'mint_key=mint.key();' in text[527]
    checks['source']['initializer_region_safe'] = True
    # 5. the recorded build used exactly these safe-form inputs and produced the shipped ELFs
    rec = layer / 'builds/recovered'
    launch = json.loads((rec / 'launch.json').read_text())
    result = json.loads((rec / 'result.json').read_text())
    assert launch['source_inputs'] == mine_inputs, 'build launch inputs differ from the safe-form inputs'
    assert result['returncode'] == 0 and result['source_unchanged'], 'build record is not a clean build'
    assert result['candidate_sha256'] == STRIPPED and result['symbols_sha256'] == SYMBOLS, 'build outputs differ'
    checks['build_record'] = dict(inputs=len(launch['source_inputs']), state_rs=launch['source_inputs']['src/state.rs'],
                                  candidate_sha256=result['candidate_sha256'], symbols_sha256=result['symbols_sha256'])
    # 6. packet inventory equals manifest.json
    manifest = json.loads((HERE / 'manifest.json').read_text())
    files = {f.relative_to(HERE).as_posix() for f in HERE.rglob('*') if f.is_file()}
    assert not any(f.is_symlink() for f in HERE.rglob('*')), 'packet includes a symlink'
    assert files == set(manifest) | {'manifest.json'}, 'packet file inventory differs from manifest.json'
    for name, digest in manifest.items():
        assert sha((HERE / name).read_bytes()) == digest, ('manifest digest', name)
    checks['manifest'] = dict(files=len(manifest))

    print(json.dumps(checks, indent=1))
    print('OK: Layer A ELFs equal the parent; safe-Rust source materializes exactly.')


if __name__ == '__main__':
    main()
