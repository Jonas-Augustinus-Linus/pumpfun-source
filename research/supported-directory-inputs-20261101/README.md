# Explicit directory inputs in the supported Cargo adapter

Base: `599891304e83e853ec723dc1417550bef4e1c074`.

The documented `--extra-input` option admits repository-local build assets.
`build_source_manifest.source_manifest` explicitly walks directory arguments,
but intentionally returns file hashes only. The v1.53/v1.54 supported adapter
used that file map as its entire staging recipe. Consequently an admitted
empty directory disappeared, and a genuine build script using `read_dir`
failed with `No such file or directory`. An empty directory added after
planning or during compilation also escaped the file-only unchanged check.

The adapter now records `extra_input_directories`, a sorted list of
repository-relative directory paths for **explicit directory arguments**.
These are directory identities, not synthetic file hashes. It rechecks the
list before staging, creates the directories alongside the unchanged file
copy, and compares both caller and staged directory lists after compilation.
`extra_input_directories_after` and `caller_extra_input_directories_after`
record those observations; `source_unchanged` requires both directory and
file equality. The per-extra root `target/` and every nested `.git/` remain
excluded; a source asset's nested `target/` remains included. A directly
supplied file, including one named `target`, keeps the existing file contract.
Directories that were not declared as assets are not newly admitted.

The file inventory utility and both measured policy JSON files are unchanged.
No program source, retained capture, historical build or source pin changes.
This is a residual supported-adapter correction, distinct from the experiment
and harness source identities addressed by
[#2922](https://github.com/lalalune/pumpfun-source/pull/2922),
[#3679](https://github.com/lalalune/pumpfun-source/pull/3679) and
[#3690](https://github.com/lalalune/pumpfun-source/pull/3690).

## Actual build proof

`probe.py` creates a tiny dependency-free generic crate and an empty offline
Cargo cache. Its build script counts an explicitly supplied asset directory
and writes a constant into Cargo's `OUT_DIR`. The real supported `plan` and
`execute` API performs compilation and stripping, using the unmodified
installed policy. An independent source copy is also compiled directly by
the same SDK; stripped image hashes are compared. No resulting image is run.

The measured tools are the official Darwin arm64 v1.53 distribution
(`rustc 1.89.0-dev`, LLVM 20.1.7; Cargo 1.89.0), with the adapter's pinned
v1.52 `llvm-objcopy`. The v1.53 release archive digest is
`239bc517f47320dd1b0a0d35511ca4b66f71679c79a0a6baf978c3b8389ad23b`.
The adapter authenticates the selected installed tool/sysroot files against
its existing policy on every plan; the proof records tool and source hashes.
The tool cache must already contain both authenticated versions. No downloads
are performed by the probe.

```sh
python -B research/supported-directory-inputs-20261101/probe.py \
  --repo . --tools /path/to/solana-cache \
  --revision 599891304e83e853ec723dc1417550bef4e1c074 \
  --expect base --output /tmp/directories-before.json
python -B research/supported-directory-inputs-20261101/probe.py \
  --repo . --tools /path/to/solana-cache \
  --expect fixed --output /tmp/directories-after.json
```

| Case | Base adapter | Corrected adapter |
| --- | --- | --- |
| Empty directory explicitly supplied | Cargo 101; adapter 1 | Complete; direct-build hash identical |
| Nested empty directory explicitly supplied | Cargo 101; adapter 1 | Complete; direct-build hash identical |
| Populated directory | Complete | Same candidate hash |
| File-only asset | Complete | Same candidate hash; no directory admission |
| Undeclared empty directory | Cargo/adapter 101 | Same refusal |
| Empty directory added after planning | Publishes with `source_unchanged: true` | Refuses before Cargo |
| Build script adds a staged empty directory | Publishes with `source_unchanged: true` | Cargo 0; refuses publication with `source_unchanged: false` |

All seven direct control builds succeed on both revisions, with identical
per-case hashes across revisions. All caller source files and directories
remain unchanged by the adapter. The base probe performs 14 real Cargo
builds; the corrected probe performs 13 because the preflight drift is
rejected before compilation. `results.json` retains the stable observations;
the full probe output also retains compiler diagnostics and tool identities.

## Tests and limits

```sh
PUMP_TEST_RUST_BIN=/path/to/host-rust/bin \
PUMP_SUPPORTED_TEST_TOOLS=/path/to/solana-cache \
python -B tests/test_supported_directory_inputs.py -v
```

The six regression methods cover ordering, overlapping extras, exclusions,
file-only inputs, symlinks, added/removed membership, actual host Cargo builds
of the adapter's unchanged staging statements, and the full SDK proof. The
host build runs whenever Cargo/rustc is present (or explicitly selected),
without running its compiled library. The SDK method explicitly skips unless
the qualified Darwin SDK cache is supplied. CI invokes the regression file.

The surviving affected entry-path, package-path, stack-diagnostic,
source-policy, file-inventory and option-routing tests pass (29 methods).
The required `scripts/test_tooling.py` passes all 253 tests and
`scripts/verify_evidence.py` verifies all nine captures.
The existing `test_supported_sbpf_policy.py` cannot import its optional
`repro/build-tooling/supported-sbpf-proposal/test_proposal.py` on the base
revision because that packet is absent; this change preserves that limitation.
The old supported-history fixture paths are also absent and are not repinned.

The public proof is ordinary generic build-tool execution, with no VM,
native model, protocol or resulting image execution. The adapter reads a
retained reference image only for its required postcompile byte comparison;
the generated crate does not reproduce it, and no equivalence claim follows.
The unchanged mandatory tooling suite includes its existing LiteSVM fixtures.
The selected-input inventory is not a hermetic build closure or a filesystem
lock against transient concurrent changes. Only v1.53 was actually compiled;
the installed v1.54 planner is covered by its existing source-policy test.
