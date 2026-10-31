# Saved-score comparison publication

Base: `9120883a957d7d9b2cab6140f66fb5bc9e6774d5`.

`compare_scores.py` opens its final `--json` destination before writing. A
failed write leaves a partial comparison receipt, and the command's intended
exclusive-create behavior then prevents the same command from retrying.

The probe runs the actual standalone CLI with the two retained baseline
reports, each containing 1,035 windows. It sets a 64-byte file-size limit in
the child only, then repeats the identical command without that limit. It
does not change the input reports, invent score rows or run a program/build.

| Actual CLI scenario | Base | Fixed |
| --- | --- | --- |
| Limited write | exit 2; 64-byte partial report | exit 2; no report or staging file |
| Same-command unlimited retry | exit 2; existing partial blocks retry | exit 0; complete 274-byte report |
| Separate unlimited output | exit 0 | exit 0; identical JSON bytes |
| Existing receipt destination | exit 2; retained | exit 2; retained |
| Either input as destination | exit 2; retained | exit 2; retained |

The fix stages the complete text in the destination directory, flushes,
fsyncs and closes it, then publishes it exclusively. POSIX uses a hard link; Windows uses its
non-replacing rename. An existing or concurrently created destination is
never replaced. Cleanup removes only the staging file created by this call.
Normal umask-derived modes and existing comparison/exit-status rules remain.

Reproduce on POSIX:

```sh
python -B research/runtime-score-publication-20261101/probe.py . \
  --revision 9120883a957d7d9b2cab6140f66fb5bc9e6774d5
python -B research/runtime-score-publication-20261101/probe.py .
python -B tests/test_compare_scores_publication.py
python -B -m unittest discover -s reconstruction/harness -p 'test_compare_scores*.py'
python -B scripts/test_tooling.py
python -B scripts/verify_evidence.py
```

`--revision` copies only the reviewed, standalone comparison script from Git
into an owned temporary directory. Inputs come from the selected checkout;
the probe records their hashes and verifies they remain unchanged. The proof
and fixed tests ran on macOS/Python 3.12.13. Three new tests and eleven
existing comparison tests pass, along with 250 tooling tests and all nine
captured-evidence checks. One new test also injects a competing writer at
publication to check exclusive creation; the failure/retry proof itself uses
real filesystem errors and actual CLI processes, without mocks.

This qualifies local report publication, not a new score or program match.
The limit test is explicitly skipped where POSIX file-size limits are
unavailable; native Windows execution and filesystems without hard-link
support were not qualified. No crash/power-loss durability claim is made.
