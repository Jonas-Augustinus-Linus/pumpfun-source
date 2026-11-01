# Literal text in AMM attempt searches

The actual `attempts.py note` recorder accepts ordinary quoted, backslash and
Unicode text. At base `599891304e83e853ec723dc1417550bef4e1c074`, `grep TEXT`
silently misses that text because it searches the ASCII-escaped JSON encoding.
For example, a successfully recorded note containing `Reuse the "parent" report`
is not found by `grep '"parent"'`. Korean text and a literal Windows path are
also missed. Searching a plain ASCII phrase still works.

This follows [dhkdzhgud's merged main-Pump correction #1707](https://github.com/lalalune/pumpfun-source/pull/1707).
The maintained AMM query is a separate consumer with contiguous-substring
semantics. Its fix adds Unicode-visible and JSON-string-escaped literal matching
while retaining the original ASCII JSON search. It does not split a multiword
query into independent words. Encoded Unicode queries, metadata syntax, ordering,
empty queries, ranking and ledger serialization retain their existing behavior.

## Reproduce

From the repository root, on a POSIX host with Python:

```sh
python -B research/amm-literal-search-20261101/probe.py
python -B scripts/test_amm_sell_literal_search.py
```

The probe copies four complete production modules from the named Git base and
the working tree into temporary directories. The actual base recorder creates
six notes in an owned scratch ledger; no row is constructed or inserted by the
probe. Both actual query CLIs then read those identical ledger bytes. Each of
the 30 search calls verifies the ledger is unchanged. The probe invokes no build,
program, VM or network operation and does not access a live ledger.

`results.json` retains the source hashes and compact query results. The six
literal cases fail on base and pass after this change. Nine controls preserve
ASCII case matching, contiguous phrases, negative queries, metadata syntax,
escaped quotes/backslashes/Unicode, multiple-result order and the empty query.
The regression has two methods: the literal method fails six subcases on base;
both methods pass after the fix. The existing recorder uses `fcntl`, so this
actual-recorder regression is skipped on Windows.

The full query receipts printed by the probe are bound in `results.json` by
SHA-256 of UTF-8 JSON with `sort_keys=True`, `ensure_ascii=False` and compact
separators `(',', ':')`. Random recorder IDs and timestamps never appear in
query output; ledger bytes are compared directly within each run.

The probe also copies all eight retained AMM lane ledgers (337 rows), preserving
their exact bytes. Six existing query commands per ledger (`summary`, `best`,
`approaches`, two `grep` controls and `seen` for a retained source file) produce
identical output before and after: 48 calls per revision. Their output hashes
are emitted under `retained_controls`; the compact receipt hashes that object
with the same canonical JSON encoding.

The affected query, torn-ledger, row-limit and `seen` suites pass (18 methods
including the new regression), and the nine captured inputs verify unchanged.
This is an ordinary offline text-search correction. It changes no attempt
conclusions, source programs, scores or byte-identity claims.
