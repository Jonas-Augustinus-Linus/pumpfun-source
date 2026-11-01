# Pump admin_cto persistent differential

This package adds multi-transaction coverage that the maintained 388-case
`scripts/pump_admin_cto_differential.py` matrix intentionally does not provide.
That matrix creates a new LiteSVM per case; this suite retains state, expires the
blockhash, signs a new message for every step, and compares a captured Pump Main
image with a freshly built source candidate in independent VMs.

## Coverage and comparison contract

Nine deterministic lifecycles execute 20 unique signed transactions per image:

- native creator A→B→C, failure/retry, automatic and explicit fee collection;
- holder-reward conversion, immutable-holder rejection, and retry;
- SPL and Token-2022 creator settlement through captured dependency programs;
- shared creator A→B→C updates through genuine Pump Fees CPI;
- frozen wallet and frozen shared-vault behavior;
- an invalid Fees event-authority attempt followed by a successful retry;
- two mints in one VM, with the other mint's curve, pool, and sharing config
  required to remain byte-identical after every step.

Every receipt retains exact transaction bytes, signature verification results,
message and blockhash identity, errors, events, return data, inner instructions,
raw and normalized logs, compute units, and complete account-by-account state.
Semantic equality excludes only invoke/success scaffolding, compute-unit lines,
and the known `programs/pump/src/` source prefix. Failed transactions must roll
back all tracked state except the transaction payer fee. Three negative controls
alter an error, event, and post-state and must all be detected.

The fixture state is synthetic. It uses canonical PDAs and the captured PumpSwap,
Pump Fees, SPL Token, Token-2022, and Associated Token programs. PDA authority is
obtained only by real CPI; the outer transaction never marks a PDA as a signer.
The suite makes bounded runtime claims, not whole-program or ELF-identity claims.

## Reproduce

Requires the repository's pinned v1.44 toolchain and `solders==0.27.1`:

```sh
out=$(mktemp -d)
reconstruction/verification/pump-admin-cto-stateful/build_candidate.sh "$PWD" "$out/build"

uv run --python 3.12 --with solders==0.27.1 python \
  reconstruction/verification/pump-admin-cto-stateful/lifecycle.py \
  --candidate "$out/build/candidate.so" --output "$out/report.json.gz"

uv run --python 3.12 --with solders==0.27.1 python \
  reconstruction/verification/pump-admin-cto-stateful/verify.py \
  --candidate "$out/build/candidate.so" --report "$out/report.json.gz" --replay

uv run --python 3.12 --with solders==0.27.1 python -m unittest -v \
  reconstruction/verification/pump-admin-cto-stateful/test_lifecycle.py
```

The report is canonical JSON with deterministic gzip metadata and binds the
complete Pump source tree, IDL, candidate, original, and dependency identities.
