"""Captured-program checks for the events a multi-hop route emits before
it fails.

`tests/test_multi_hop_events_captured.py` compares the events of routes
that settle, and for a route that fails it only checks that the events
host repeats the state model's error — the events the failed transaction
logged are not compared, and `multi_hop_events.rs` lists them as
unconfirmed. This test compares them: for every fixed and seeded-random
route of the Token-2022 multi-hop packet, the events in the failed
transaction's logs must equal the events
`programs/pump/recovered/multi_hop_failed_events.rs` records before the
failure, and for a route that settles this host must answer exactly what
the events host answers. The self-CPI payload side is compared as a
prefix on failing routes: the harness reports no inner instructions for
a failed transaction that emitted events (on these corpora, exactly the
319 failing routes with events before the failure), so the payloads it
does report must match the model's first payloads, and the log payloads
— which the failed transaction carries in full — must match exactly.
This shows matching behavior on these inputs only; it is not a
byte-identity claim.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import test_multi_hop_events_captured as ev
import test_multi_hop_token2022_captured as t22

HOST_SOURCE = ROOT / 'programs/pump/recovered/multi_hop_failed_events_host.rs'
_HOST = None


def host_binary():
    global _HOST
    if _HOST is None:
        out = Path(tempfile.mkdtemp()) / 'multi_hop_failed_events_host'
        subprocess.run(['rustc', '--edition=2021', '-O', '-D', 'warnings', str(HOST_SOURCE), '-o', str(out)],
                       check=True)
        _HOST = out
    return _HOST


def failed_model(routes):
    text = ''.join(t22.host_line(r) + '\n' for r in routes)
    answers = subprocess.run([str(host_binary())], input=text, capture_output=True, text=True,
                             check=True).stdout.splitlines()
    if len(answers) != len(routes):
        raise ValueError(f'failed-events host returned {len(answers)} answers for {len(routes)} routes')
    return answers


def run_labelled(chain, labelled):
    """(problems per label, failing routes that emitted at least one event)."""
    routes = [r for _, r in labelled]
    answers = t22.model(routes)
    lines = failed_model(routes)
    settled_lines = ev.events_model(routes)
    assert len(answers) == len(labelled), 'one model answer is required per captured route'
    assert len(lines) == len(labelled), 'one failed-events answer is required per captured route'
    problems = {}
    failed_with_events = 0
    for (label, r), answer, line, settled in zip(labelled, answers, lines, settled_lines):
        got = chain.run(r)
        bad = t22.check(r, got, answer)
        if answer.startswith('ok'):
            if line != settled:
                bad.append(f'failed-events host {line!r} != events host {settled!r}')
            bad += ev.event_problems(r, line, got)
        elif line != answer and not line.startswith(answer + ';'):
            bad.append(f'failed-events host {line!r} does not start with the model answer {answer!r}')
        else:
            want, want_cpi = ev.expected_events(r, 'ok' + line[len(answer):])
            if got['events'] != want:
                detail = f"{len(got['events'])} captured vs {len(want)} modelled"
                for i, (a, b) in enumerate(zip(got['events'], want)):
                    if a != b:
                        detail += f'; first difference at event {i}'
                        break
                bad.append(f'log events differ: {detail}')
            if got['self_cpi'] != want_cpi[:len(got['self_cpi'])]:
                bad.append('self-CPI event payloads differ on the reported prefix')
            if want:
                failed_with_events += 1
        if bad:
            problems[label] = bad
    return problems, failed_with_events


class MultiHopFailedEventsCaptured(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = ev.Chain()
        cls.fixed = run_labelled(cls.chain, t22.fixed_cases())
        cls.random = run_labelled(cls.chain, t22.random_cases())

    def test_fixed_cases(self):
        self.assertEqual(len(t22.fixed_cases()), t22.FIXED_COUNT)
        problems, _ = self.fixed
        self.assertEqual(problems, {})

    def test_random_cases(self):
        problems, _ = self.random
        self.assertEqual(problems, {})

    def test_failed_routes_do_emit_events(self):
        total = self.fixed[1] + self.random[1]
        self.assertGreater(total, 100)

    def test_host_never_drifts(self):
        routes = [r for _, r in t22.fixed_cases()] + [r for _, r in t22.random_cases()]
        for line in failed_model(routes):
            self.assertNotEqual(line, 'error:model-drift')

    def test_checker_rejects_tampered_events(self):
        labelled = t22.fixed_cases()
        routes = [r for _, r in labelled]
        answers = t22.model(routes)
        lines = failed_model(routes)
        for (label, r), answer, line in zip(labelled, answers, lines):
            if answer.startswith('ok') or ';T,' not in line:
                continue
            got = self.chain.run(r)
            records = line.split(';')
            fields = records[1].split(',')
            fields[6] = str(int(fields[6]) + 1)
            records[1] = ','.join(fields)
            tampered_want, _ = ev.expected_events(r, 'ok;' + ';'.join(records[1:]))
            self.assertNotEqual(got['events'], tampered_want, label)
            return
        self.fail('no failing route with a trade event to tamper with')


if __name__ == '__main__':
    unittest.main()
