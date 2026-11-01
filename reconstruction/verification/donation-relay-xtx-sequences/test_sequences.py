#!/usr/bin/env python3
import importlib.util
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("relay_xtx", HERE / "producer.py")
xtx = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = xtx
SPEC.loader.exec_module(xtx)

FEE = "FeePayer1111111111111111111111111111111111"
DONOR_STATE = {"epoch": 0, "epoch_state": 1, "debouncer_state": 1,
               "debouncer_total": 3_000_000, "source_tokens": 7_000_000,
               "destination_tokens": 3_000_000}


def fabricated_step(error=None, changed=()):
    before = {"AcctA": {"lamports": 5}, FEE: {"lamports": 9}}
    after = json.loads(json.dumps(before))
    for address in changed:
        after[address] = {"lamports": 4}
    return {"original": {"error": error, "before": before, "after": after},
            "original_state": json.loads(json.dumps(DONOR_STATE))}


class DeclarationTests(unittest.TestCase):
    def test_case_set_and_step_counts(self):
        self.assertEqual(xtx.CASE_NAMES, [
            "intra_tx_double_donate", "intra_tx_triple_donate",
            "intra_tx_success_then_fail", "fail_then_success_retry",
            "success_fail_success", "failed_close_between_donations",
            "zero_after_nonzero",
        ])
        counts = {name: len(xtx.CASES[name]["steps"]) for name in xtx.CASE_NAMES}
        self.assertEqual(counts, {
            "intra_tx_double_donate": 1, "intra_tx_triple_donate": 1,
            "intra_tx_success_then_fail": 1, "fail_then_success_retry": 3,
            "success_fail_success": 3, "failed_close_between_donations": 3,
            "zero_after_nonzero": 2,
        })
        self.assertEqual(sum(counts.values()), 14)

    def test_instruction_counts_per_step(self):
        fixture = xtx.Fixture.create()
        shapes = {}
        for name in xtx.CASE_NAMES:
            shapes[name] = []
            for build in xtx.CASES[name]["steps"]:
                instructions, signers, _extra = build(fixture)
                shapes[name].append((len(instructions),
                                     [str(k.pubkey()) for k in (signers or [fixture.donor])]))
        self.assertEqual([n for n, _ in shapes["intra_tx_double_donate"]], [2])
        self.assertEqual([n for n, _ in shapes["intra_tx_triple_donate"]], [3])
        self.assertEqual([n for n, _ in shapes["intra_tx_success_then_fail"]], [2])
        self.assertEqual([n for n, _ in shapes["fail_then_success_retry"]], [1, 1, 1])
        close_signers = shapes["failed_close_between_donations"][1][1]
        self.assertEqual(close_signers, [str(fixture.outsider.pubkey())])

    def test_expected_final_states_are_arithmetically_consistent(self):
        for name in xtx.CASE_NAMES:
            state = xtx.CASES[name]["final_state"]
            if state["debouncer_total"] is None:
                # The whole-transaction rollback case: nothing was created
                # and the source kept every token.
                self.assertEqual(state["source_tokens"], 10_000_000, name)
                self.assertIsNone(state["destination_tokens"], name)
            else:
                self.assertEqual(state["debouncer_total"], state["destination_tokens"], name)
                self.assertEqual(state["source_tokens"] + state["destination_tokens"],
                                 10_000_000, name)

    def test_step_error_declarations_match_step_counts(self):
        for name in xtx.CASE_NAMES:
            spec = xtx.CASES[name]
            self.assertEqual(len(spec["step_errors"]), len(spec["steps"]), name)


class ExpectationCheckTests(unittest.TestCase):
    SPEC = {"step_errors": [None], "final_state": dict(DONOR_STATE)}

    def test_truncated_steps_are_rejected(self):
        self.assertEqual(xtx.check_expectations([], self.SPEC, FEE), ["step_count"])

    def test_matching_expectations_pass(self):
        self.assertEqual(xtx.check_expectations([fabricated_step()], self.SPEC, FEE), [])

    def test_negative_control_wrong_debouncer_total_is_flagged(self):
        spec = json.loads(json.dumps(self.SPEC))
        spec["final_state"]["debouncer_total"] += 1
        problems = xtx.check_expectations([fabricated_step()], spec, FEE)
        self.assertIn("original_expected_debouncer_total", problems)

    def test_unexpected_step_error_is_flagged(self):
        step = fabricated_step(error="TransactionErrorInstructionError((1, Custom(6009)))")
        problems = xtx.check_expectations([step], self.SPEC, FEE)
        self.assertIn("step_0_expected_success", problems)

    def test_missing_step_error_is_flagged(self):
        spec = {"step_errors": ["Custom(6009)"], "final_state": dict(DONOR_STATE)}
        problems = xtx.check_expectations([fabricated_step()], spec, FEE)
        self.assertIn("step_0_expected_error", problems)

    def test_failed_step_state_change_is_flagged_but_fee_change_is_not(self):
        error = "TransactionErrorInstructionError((1, Custom(6009)))"
        spec = {"step_errors": ["Custom(6009)"], "final_state": dict(DONOR_STATE)}
        changed = xtx.check_expectations([fabricated_step(error, changed=("AcctA",))], spec, FEE)
        self.assertIn("step_0_failed_state_changed", changed)
        fee_only = xtx.check_expectations([fabricated_step(error, changed=(FEE,))], spec, FEE)
        self.assertNotIn("step_0_failed_state_changed", fee_only)


class SharedWitnessTests(unittest.TestCase):
    @staticmethod
    def matching_step():
        row = {
            "error": None,
            "logs": ["Program log: hi", "Program consumed: 1 of 1400000 compute units"],
            "events": [],
            "inner_instructions": [],
            "return_data": [None, ""],
            "before": {"SomeAccount11111111111111111111111111111111": {"lamports": 1}},
            "after": {"SomeAccount11111111111111111111111111111111": {"lamports": 2}},
        }
        return {"original": row, "candidate": json.loads(json.dumps(row))}

    def test_negative_control_replays_mutations_through_the_case_comparison(self):
        step = self.matching_step()
        self.assertEqual(xtx.negative_control(step), {"error": True, "after": True})

    def test_negative_control_fails_when_the_comparison_stops_reporting(self):
        step = self.matching_step()
        with unittest.mock.patch.object(xtx.base.Pair, "compare_rows", return_value=[]):
            self.assertEqual(xtx.negative_control(step), {"error": False, "after": False})

    def test_transaction_identity_rejects_reused_signature(self):
        cases = [{"steps": [
            {"signature": "same", "signature_verified": True},
            {"signature": "same", "signature_verified": True},
        ]}]
        identity = xtx.transaction_identity(cases)
        self.assertEqual(identity["count"], 2)
        self.assertEqual(identity["unique_count"], 1)
        self.assertTrue(identity["all_signatures_verified"])


if __name__ == "__main__":
    unittest.main()
