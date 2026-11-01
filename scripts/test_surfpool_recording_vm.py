"""Offline VM recording and real fixture preparation remain available."""
import base64
import importlib
import unittest

from solders.account import Account
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from surfpool_recording_vm import RecordingVM


RUNNERS = (
    'pump_buy_v2_surfpool', 'pump_cashback_surfpool', 'pump_create_control_surfpool',
    'pump_create_nested_surfpool', 'pump_create_quote_surfpool', 'pump_create_surfpool',
    'pump_create_v2_surfpool', 'pump_global_init_surfpool', 'pump_idl_authority_surfpool',
    'pump_legacy_buy_surfpool', 'pump_v3_token_extensions_surfpool',
)


class RecordingVMTests(unittest.TestCase):
    def test_wrapper_records_inputs_before_signed_transfer(self):
        vm = RecordingVM(LiteSVM())
        self.assertIs(vm.with_transaction_history(0), vm)
        payer = Keypair.from_seed(bytes([31]) * 32)
        destination = Keypair.from_seed(bytes([32]) * 32).pubkey()
        vm.set_account(payer.pubkey(), Account(10**10, b'', Pubkey.default()))
        before = dict(vm.accounts[str(payer.pubkey())])
        tx = Transaction.new_signed_with_payer(
            [transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=destination, lamports=10**7))],
            payer.pubkey(), [payer], vm.latest_blockhash(),
        )
        self.assertTrue((tx.signatures and all(tx.verify_with_results())))
        vm.send_transaction(tx)
        self.assertEqual(vm.transaction, tx)
        self.assertEqual(vm.accounts[str(payer.pubkey())], before)
        self.assertLess(vm.get_account(payer.pubkey()).lamports, before['lamports'])
        self.assertEqual(vm.get_account(destination).lamports, 10**7)

    def test_each_repaired_runner_prepares_a_real_signed_case(self):
        for name in RUNNERS:
            with self.subTest(runner=name):
                module = importlib.import_module(name)
                if name == 'pump_create_nested_surfpool':
                    _, case = module.nested.prepare(module.nested.cases()[0])
                else:
                    case = module.fixtures.cases()[0]
                row = module.prepare(case)
                tx = Transaction.from_bytes(base64.b64decode(row['transaction_base64']))
                self.assertTrue((tx.signatures and all(tx.verify_with_results())))
                self.assertTrue(row['accounts'])
                self.assertEqual(row['case'], case)
                self.assertIn('litesvm_error', row)


if __name__ == '__main__':
    unittest.main()
