# Preserve inventory output ownership during publication

This is a static tooling correction tested against
`599891304e83e853ec723dc1417550bef4e1c074`. The inventory CLI disassembles the
nine retained ELF captures; it does not execute, assemble or modify them.

The fresh-directory contract established by [#2303](https://github.com/lalalune/pumpfun-source/pull/2303)
has two gaps. Resolving `--output` before testing `is_symlink()` hides a dangling
leaf link. Plain `Path.rename()` can also replace an empty directory created by
another process after the initial admission check. Both situations publish a
complete inventory into a destination the caller no longer owns exclusively.

The correction keeps the lexical absolute leaf for admission and calls the
existing `deep_disassembly.rename_directory` no-replace helper for publication.
That helper was introduced in
[`240ad77c6`](https://github.com/lalalune/pumpfun-source/commit/240ad77c6cc0b5777f8dd9274ed0e98b4f7deb92).
It is reused unchanged; parent directory aliases and the short staging prefix
from [#3622](https://github.com/lalalune/pumpfun-source/pull/3622) remain supported.

`before.json` and `after.json` record ten actual CLI invocations per revision.
`reproduce.py` copies exact script bytes and genuine retained captures into a
private cohort. It uses an unmodified, independently built Blueshift executable.
For the late-directory case, the supervising process waits for the real staging
directory to appear, then creates the destination while actual disassembly is
still running. No tool, production function or publication operation is mocked.

| Case | Base | Corrected |
| --- | --- | --- |
| Fresh output | Success | Success |
| Parent directory symlink | Success | Success |
| Dangling output symlink | Follows link and publishes target | Refuses; target remains absent |
| Output symlink to populated directory | Refuses; preserves bytes | Same |
| Existing empty/full directory or regular file | Refuses; preserves inode/bytes | Same |
| Empty directory created after admission | Replaces directory inode | Refuses; preserves directory |
| Real captured input used directly/as link target for output | Refuses; preserves capture | Same |

Each completed packet covers **788,302 logical instructions** from nine captures.
The two normal output cases retain identical bytes for all **27 payload files**
before and after. The semantic manifest is identical too; only its intended
`generator_sha256` changes. All original captures, private input copies, the
admitted executable and its tracked source remain unchanged. Failed cases leave
no staging directory.

## Reproduce

The host tool is the official [`blueshift-gg/sbpf`](https://github.com/blueshift-gg/sbpf)
at commit `422a6316cbb1ac60b07b60a555bfbcb8e557bcef` (version 0.3.3), built with
`cargo build --locked --release --package sbpf --bin sbpf`. Its lockfile SHA-256
is `998462a5c5cac8433f7039ea7727e0b80ab7e7f43ffd4b4f9c23599bfd5c2a1c`.
Use an already inspected checkout and separate Cargo cache/target directory;
the inventory expects the executable at `<tool-source>/target/release/sbpf`.
`tool-build.json` records the tested host compiler, successful build and binary.
The local build emitted optional debug-stripping warnings for a missing
`libLLVM.dylib`; Cargo returned zero and the resulting executable passed version
and real disassembly checks. No upstream test, assembly, deployment or VM command
was run. Tool hashes can differ when another host builds the same locked source.

From this repository, with Python 3.12 and an unused result path:

```sh
python -B research/sbpf-inventory-publication-20261101/reproduce.py . \
  --tool-source /path/to/pinned/sbpf \
  --revision 599891304e83e853ec723dc1417550bef4e1c074 \
  --expect before --output /tmp/inventory-before.json
python -B research/sbpf-inventory-publication-20261101/reproduce.py . \
  --tool-source /path/to/pinned/sbpf \
  --expect fixed --compare /tmp/inventory-before.json \
  --output /tmp/inventory-after.json
python -B scripts/test_sbpf_disassembly_inventory_publication.py
python -B scripts/test_sbpf_disassembly_inventory_long_output.py
python -B scripts/test_deep_disassembly_publication.py
python -B scripts/verify_evidence.py
```

The existing inventory publication suite is already invoked by CI. Its small
regressions use controlled workers for deterministic boundary coverage; the
separate retained proof above exercises the real executable and all captures.
Twenty-five affected static regression methods and the nine-capture verifier
passed locally. This packet does not claim an additional full tooling run.

Limits: the actual publication proof ran on macOS arm64. The unchanged helper
also implements Linux and Windows no-replace publication; those hosts were not
executed here. Other unsupported hosts fail closed. Parent-directory replacement
races are not addressed, and parent symlinks remain intentional. This establishes
output preservation and unchanged static diagnostic payloads, not source
reconstruction, runtime equivalence or security acceptance. Historical manifests
and capture bytes are preserved; no historical inventory pin was refreshed.
