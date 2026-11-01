# Current diagnostic integration review

This review composes the bounded tooling fixes in #3836, #3842, #3843, #3845,
#3848, #3849, #3850, #3857, #3882, #3889, #3891, #3896, #3900, #3901, #3902,
#3903, #3908 and #3909 on main `36aacdaf1192187007f521f5a9f2cbc536809b21`.
Their original commits remain in ancestry. The data-reference fix in #3834 was
already repaired and merged through #3837.

The integration preserves the current data-reference producer and separately
admits the reviewed census, hotness and call-target producer bytes in the portable
adapter. The analysis-retention wrapper admits the exact LF and CRLF forms of
#3900's capture-directory mapping. Unknown helper bytes remain rejected. These
changes retain the original wrapper allowlists and historical generated packets.

The swap-hop packet keeps its historical `RESULT.json`, including the original
measurement implementation identities. Its verifier separately admits the exact
current implementations of section admission and symbol reading reviewed in
#3891. The verifier rejects drift in either the historical metadata or current
code. Passing the packet without its optional candidate does not claim to replay
the historical candidate or prove current whole-program identity.

The verify-current entry guard also protects its declared objdump path and reads
the canonical captured original through the existing resolver. Its negative tests
use private inputs. The distribution-LLVM disassembly fallback preserves win.py's
executable mode. Its assignment-style output is canonicalized only for census
argument-write extraction, so branches cannot become writes and real scalar or
section-pointer arguments remain visible. Retained instruction witnesses and
actual distribution/SDK disassembly exercise both syntaxes. Clone increment
witnesses use the same adjacent load/increment instruction bytes, preserving
counts under either printer. No program, build recipe, normalization rule or completion count
changes in this integration.

Output-preservation guards in census, hotness, callid, capture-inline and
verify-current apply to aliases present at CLI entry. They do not promise immutable
analysis snapshots, atomic publication or protection against later path changes.
The stronger data-reference publication guarantees remain scoped to that producer.

Validation includes the actual current-capture LF/CRLF wrapper proofs, all nine
capture checks, both Python modes of the swap-hop packet, distribution-LLVM range
diffs, CFG and diagnostic regressions, real Git symlink-materialization controls,
and the affected analysis, signature, math, ledger-search and publication tests.
The full prior broad suite is separate historical evidence; this is a focused
integration validation. Static patterns remain diagnostic candidates, with no new
runtime, compiler or source-equivalence claim.
