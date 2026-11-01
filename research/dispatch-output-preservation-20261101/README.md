# Preserve captured inputs when publishing dispatch reports

At base `599891304e83e853ec723dc1417550bef4e1c074`, the real
`scripts/recover_dispatch.py` command writes its completed report directly to
`evidence/dispatch-map.json`. If that destination is a symlink or hardlink to a
capture or IDL, the command exits successfully after replacing the input bytes
with JSON. A dangling destination symlink creates its target instead.

The command now uses the existing `analyze.publish_reports` helper, already
used by the adjacent binary/interface inventory CLI. It refuses symlink and
non-file destinations, stages complete UTF-8 JSON beside the destination, then
replaces the directory entry. Replacing a hardlink detaches the report without
truncating the capture or IDL. Ordinary report regeneration keeps the same JSON
bytes and console output. The recovery algorithm and historical evidence stay
unchanged.

The proof runs both complete command versions on private copies of the four
retained original captures and three upstream IDLs. It makes no compiler, VM,
program, RPC or network call. Both versions analyze the same bytes before
publication. Four alias cases change their input files on base; all inputs
remain intact after the fix. The dangling-link target also remains absent.
Fresh output, regular-file replacement, a prior output directory and a later
IDL parsing failure provide controls. Every successful report has SHA-256
`609e4795d796aeed61c7e6d8853407264362166afd05bd9d76687ed673ecc2f9`.

```sh
python -B research/dispatch-output-preservation-20261101/probe.py --checkout . --revision 599891304e83e853ec723dc1417550bef4e1c074 --expect base --output work/dispatch-before.json
python -B research/dispatch-output-preservation-20261101/probe.py --checkout . --expect fixed --output work/dispatch-after.json
python -B tests/test_recover_dispatch_publication.py
```

Use fresh proof output names. `results.json` retains both observed results,
including source/input hashes. The four regression methods execute all nine
scenarios through the actual CLI and are discovered by the existing contract
test workflow. Link controls were run on macOS; native Windows link privileges
are not validated. These checks establish output/input preservation for the
listed cases, not equivalence of reconstructed programs or new dispatch gains.
