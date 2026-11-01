"""Captured-program checks for the `Left:` / `Right:` sites the base packet
left unconfirmed.

`tests/test_error_log_left_right_captured.py` pins 93 sites and lists the
rest as unconfirmed: the create_v2 quote-chain guards, the holder-list
guard (6085), the `buy_v2.rs:121` token-owner check, and the
`multi_hop_curve_swap` occurrences. This test takes those up, minus the
`claim_cashback_v2` sites in the token-incentives handlers, which stay
unconfirmed. Recording VMs run the base packet's case selection and suites,
the create_v2 pool-chain cases, and the Token-2022 multi-hop routes on
`evidence/original/pump/deployed.so`; a small fixture of this test reaches
`buy_v2.rs:121` by giving the v3 quote user account a stored owner that is
not the user. Every pair logged at a site in
`programs/pump/recovered/error_log_left_right_rest.rs` is checked against
the model: the host must name the model's side forms, the sides are
evaluated from the transaction and the pre-state (the ATA and
bonding-curve derivations are recomputed, not pinned by position), and the
host must rebuild the logged block. This shows matching behavior on these
inputs only; it is not a byte-identity claim.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import hashlib
import importlib

import json
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from solders.pubkey import Pubkey
from solders.transaction_metadata import FailedTransactionMetadata

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import test_error_log_left_right_captured as prev

PUMP_ELF = prev.PUMP_ELF
PUMP_SHA256 = prev.PUMP_SHA256
PUMP = prev.PUMP
SLOT_NAMES = prev.SLOT_NAMES
HOST_SOURCE = ROOT / 'programs/pump/recovered/error_log_left_right_rest_host.rs'
MODEL_SOURCE = ROOT / 'programs/pump/recovered/error_log_left_right_rest.rs'
SUITE_MODULES = prev.SUITE_MODULES
ATA_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'

CONSTANTS = dict(prev.CONSTANTS)
CONSTANTS.update({
    'unsupported_quote_mint': '9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP',
    'quote_control': '6z6GDdfb2AjR9ZhJmAUQ5cipJCVxQvLJhB2H8mCwTFBP',
})
FORM_NAMES = {'Pump': 'pump', 'UnsupportedQuoteMint': 'unsupported_quote_mint',
              'QuoteControl': 'quote_control', 'QuoteAta': 'quote_ata',
              'AncestorCurve': 'ancestor_curve', 'HolderPassedAta': 'holder_passed_ata',
              'HolderDerivedAta': 'holder_derived_ata', 'HopQuoteMint': 'hop_quote_mint',
              'RouteFinalMint': 'route_final_mint', 'Slot': 'slot:', 'Remaining': 'remaining:',
              'OwnerOfRemaining': 'owner-remaining:', 'StoredMint': 'stored-mint:',
              'StoredTokenOwner': 'stored-token-owner:'}


class RestRecorder(prev.RecordingVm):
    """The base packet's recorder, also keeping the instruction's ordered
    account keys and a prefix of every account's data."""

    def send_transaction(self, tx):
        keys = [str(key) for key in tx.message.account_keys]
        pump_ix = [ix for ix in tx.message.instructions if keys[ix.program_id_index] == PUMP]
        extra = None
        if len(pump_ix) == 1:
            alldata = {}
            for key in keys:
                account = self.vm.get_account(Pubkey.from_string(key))
                if account is not None and len(account.data) <= 5000:
                    alldata[key] = bytes(account.data)[:200].hex()
            extra = {'ix_keys': [keys[i] for i in pump_ix[0].accounts], 'alldata': alldata}
        before = len(prev.RECORDED)
        result = super().send_transaction(tx)
        if extra is not None and len(prev.RECORDED) > before:
            prev.RECORDED[-1].update(extra)
        return result


def harvest_poolchain():
    import test_create_v2_captured as cv2
    import test_create_v2_pool_chain_captured as chain
    with mock.patch.object(cv2, 'LiteSVM', RestRecorder):
        for item in chain.fixed_cases() + chain.random_cases():
            try:
                cv2.run_captured(item)
            except Exception:
                pass
    print(json.dumps({'records': prev.RECORDED}))


def harvest_mh():
    import test_multi_hop_events_captured as ev
    import test_multi_hop_token2022_captured as t22
    t22.LiteSVM = RestRecorder
    chain = ev.Chain()
    for _label, route in t22.fixed_cases() + t22.random_cases():
        try:
            chain.run(route)
        except Exception:
            pass
    print(json.dumps({'records': prev.RECORDED}))


def own_fixture_records():
    """The v3 trade fixture of the vault-refactor packet, with the quote
    user account's stored owner replaced by a stranger's key, so the
    `check_token_account` owner check at `buy_v2.rs:121` fires."""
    import test_v3_vault_refactor_captured as vault
    from solders.account import Account
    from solders.instruction import AccountMeta
    import struct as _struct
    bogus = Pubkey.from_bytes(bytes([231]) * 32)
    start = len(prev.RECORDED)
    with mock.patch.object(vault, 'LiteSVM', RestRecorder):
        for ix in ('buy_v3', 'buy_exact_quote_in_v3'):
            case = dict(kind='v3', label=f'rest-{ix}', quote='token', ix=ix,
                        args=(10 ** 9, 10 ** 15) if ix == 'buy_v3' else (10 ** 9, 1), buyback=0,
                        accounts={vault.ata(vault.USER.pubkey(), vault.QUOTE):
                                  Account(2_039_280, vault.token(vault.QUOTE, bogus, 10 ** 12), vault.TOKEN)})
            vault.run_case(vault.PUMP_ELF, case)
        # sell_v3: mirror the base packet's hand-built sell state.
        vm = vault.new_vm(vault.PUMP_ELF)
        _, quote_mint = vault.common_state(vm, {'quote': 'token', 'buyback': 0})
        user = vault.USER.pubkey()
        volume = bytearray(137)
        volume[:8] = vault.ACCOUNT_DISC['UserVolumeAccumulator']
        volume[8:40] = bytes(user)
        vm.set_account(vault.USER_VOLUME, Account(vm.minimum_balance_for_rent_exemption(137), bytes(volume), vault.PUMP))
        vm.set_account(vault.ata(user, vault.BASE), Account(2_039_280, vault.token(vault.BASE, user, 10 ** 12), vault.TOKEN))
        vm.set_account(vault.ata(user, vault.QUOTE), Account(2_039_280, vault.token(vault.QUOTE, bogus, 0), vault.TOKEN))
        recipient = vault.ata(vault.BUYBACK, vault.QUOTE)
        vm.set_account(recipient, Account(2_039_280, b'', vault.SYSTEM))
        names = {
            'global': vault.GLOBAL, 'base_mint': vault.BASE, 'quote_mint': quote_mint,
            'base_token_program': vault.TOKEN, 'quote_token_program': vault.TOKEN,
            'bonding_curve': vault.CURVE, 'associated_base_bonding_curve': vault.ata(vault.CURVE, vault.BASE),
            'associated_quote_bonding_curve': vault.ata(vault.CURVE, quote_mint), 'user': user,
            'associated_base_user': vault.ata(user, vault.BASE),
            'associated_quote_user': vault.ata(user, quote_mint),
            'user_volume_accumulator': vault.USER_VOLUME, 'fee_config': vault.FEE_CONFIG,
            'buyback_fee_recipient': recipient, 'system_program': vault.SYSTEM,
            'event_authority': vault.EVENT_AUTHORITY, 'program': vault.PUMP,
        }
        ix = vault.IX['sell_v3']
        metas = [AccountMeta(names[a['name']], a.get('signer', False), a.get('writable', False))
                 for a in ix['accounts']]
        data = bytes(ix['discriminator']) + _struct.pack('<QQ', 10 ** 9, 0)
        vault.execute(vm, vault.PUMP, data, metas)
    return prev.RECORDED[start:]


def ata(owner, mint, program):
    seeds = [bytes(Pubkey.from_string(owner)), bytes(Pubkey.from_string(program)),
             bytes(Pubkey.from_string(mint))]
    return str(Pubkey.find_program_address(seeds, Pubkey.from_string(ATA_PROGRAM))[0])


def pda(seeds):
    return str(Pubkey.find_program_address(seeds, Pubkey.from_string(PUMP))[0])


def remaining(record):
    named = len(SLOT_NAMES[record['handler']])
    return record['ix_keys'][named:]


def stored(record, slot, start, end):
    data = bytes.fromhex(record['alldata'][record['slots'][slot]])
    return str(Pubkey.from_bytes(data[start:end]))


def holder_pair(record):
    """(passed, derived) of the first holder pair whose passed token account
    is not the derived ATA, else (None, None)."""
    rem = remaining(record)
    for index in range(0, len(rem) - 1, 2):
        derived = ata(rem[index], record['slots']['quote_mint'], record['slots']['quote_token_program'])
        if rem[index + 1] != derived:
            return rem[index + 1], derived
    return None, None


def hop_walk(record):
    """The running mint after each hop of a multi-hop route, as
    (first mint that differs from the buyback recipient's stored mint,
    final mint); (None, None) when a hop's mints do not contain the
    running mint."""
    rem = remaining(record)
    current = stored(record, 'source', 0, 32)
    target = stored(record, 'buyback_fee_recipient', 0, 32)
    first = None
    for index in range(0, len(rem) - 4, 5):
        pair = (rem[index], rem[index + 1])
        if pair[1] == current:
            other = pair[0]
        elif pair[0] == current:
            other = pair[1]
        else:
            return None, None
        if first is None and other != target:
            first = other
        current = other
    return first, current


def evaluate(form, record):
    """The value a side form reads from a record; None when the form cannot
    be evaluated on this record."""
    if form in CONSTANTS:
        return CONSTANTS[form]
    if form.startswith('slot:'):
        return record['slots'][form[5:]]
    if form.startswith('remaining:'):
        return remaining(record)[int(form[10:])]
    if form.startswith('owner-remaining:'):
        return record['owners'][remaining(record)[int(form[16:])]]
    if form.startswith('stored-mint:'):
        return stored(record, form[12:], 0, 32)
    if form.startswith('stored-token-owner:'):
        return stored(record, form[19:], 32, 64)
    if form == 'quote_ata':
        rem = remaining(record)
        return ata(record['slots']['bonding_curve'], rem[0], rem[2])
    if form == 'ancestor_curve':
        return pda([b'bonding-curve', bytes(Pubkey.from_string(remaining(record)[0]))])
    if form == 'holder_passed_ata':
        return holder_pair(record)[0]
    if form == 'holder_derived_ata':
        return holder_pair(record)[1]
    if form == 'hop_quote_mint':
        return hop_walk(record)[0]
    if form == 'route_final_mint':
        return hop_walk(record)[1]
    raise AssertionError(form)


def table():
    rows = {}
    pattern = re.compile(r'^    \("(\w+)", Kind::(\w+), "([^"]*)", (\d+), '
                         r'Side::(\w+)(?:\(((?:"[^"]*")|(?:\d+))\))?, '
                         r'Side::(\w+)(?:\(((?:"[^"]*")|(?:\d+))\))?\),$', re.M)
    for handler, kind, place, code, left, left_arg, right, right_arg in pattern.findall(MODEL_SOURCE.read_text()):
        forms = []
        for name, arg in ((left, left_arg), (right, right_arg)):
            form = FORM_NAMES[name]
            forms.append(form + (arg.strip('"') if form.endswith(':') else arg) if form.endswith(':') else form)
        rows[(handler, kind.lower(), place, int(code))] = tuple(forms)
    return rows


class ErrorLogLeftRightRestCapturedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert hashlib.sha256(PUMP_ELF.read_bytes()).hexdigest() == PUMP_SHA256
        cls.tmp = tempfile.TemporaryDirectory()
        cls.host = Path(cls.tmp.name) / 'error-log-left-right-rest-host'
        subprocess.run(['rustc', '--edition=2021', '-O', '-D', 'warnings', str(HOST_SOURCE), '-o', str(cls.host)],
                       check=True)
        cls.rows = table()

        def run(args):
            done = subprocess.run([sys.executable, '-I', '-B', __file__, *args], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, check=True)
            return json.loads(done.stdout.splitlines()[-1])
        jobs = [('suite', name) for name in SUITE_MODULES]
        with ThreadPoolExecutor(len(jobs) + 3) as pool:
            futures = [pool.submit(run, ['--harvest-suite', name]) for _kind, name in jobs]
            futures.append(pool.submit(run, ['--harvest-cases']))
            futures.append(pool.submit(run, ['--harvest-poolchain']))
            futures.append(pool.submit(run, ['--harvest-mh']))
            reports = [future.result() for future in futures]
        cls.suites = dict(zip(SUITE_MODULES, reports[:len(jobs)]))
        cls.records = [record for report in reports for record in report['records']]
        cls.records += own_fixture_records()
        cls.events = [event for record in cls.records for event in prev.events(record)]
        cls.record_of = [record for record in cls.records for _ in prev.events(record)]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def answers(self, queries):
        text = ''.join('\t'.join(map(str, query)) + '\n' for query in queries)
        result = subprocess.run([str(self.host)], input=text, capture_output=True, text=True, check=True)
        return result.stdout.splitlines()

    def target_paired(self):
        return [(site, left, right, record) for (site, left, right), record
                in zip(self.events, self.record_of) if left is not None and site in self.rows]

    def test_source_suites_still_pass(self):
        for name, report in self.suites.items():
            self.assertTrue(report['ok'], name)
        self.assertGreater(len(self.records), 900)

    def test_every_target_block_matches_the_model(self):
        paired = self.target_paired()
        self.assertGreater(len(paired), 40)
        form_queries = [('forms', *site) for site, *_ in paired]
        form_answers = self.answers(form_queries)
        block_queries = [('block', *site, left, right) for site, left, right, _ in paired]
        block_answers = self.answers(block_queries)
        self.assertEqual(len(form_answers), len(paired), 'one form answer is required per paired block')
        self.assertEqual(len(block_answers), len(paired), 'one block answer is required per paired block')
        wrong = []
        for (site, left, right, record), forms_answer, block_answer in zip(paired, form_answers, block_answers):
            if forms_answer != ','.join(self.rows[site]):
                wrong.append((site, f'forms {forms_answer} != {self.rows[site]}'))
                continue
            for form, printed in zip(self.rows[site], (left, right)):
                expected = evaluate(form, record)
                if expected is None or expected != printed:
                    wrong.append((site, f'{form} evaluates to {expected}, printed {printed}'))
            if block_answer != f'Left:\t{left}\tRight:\t{right}':
                wrong.append((site, f'block answer {block_answer!r}'))
        self.assertEqual(wrong[:6], [], f'{len(wrong)} of {len(paired)} paired blocks differ')

    def test_truncated_paired_answers_are_rejected(self):
        count = len(self.target_paired())
        for forms, blocks in (([], ['unused'] * count), (['unused'] * count, [])):
            with self.subTest(forms=len(forms), blocks=len(blocks)), \
                    mock.patch.object(self, 'answers', side_effect=[forms, blocks]), \
                    self.assertRaisesRegex(AssertionError, 'one .* answer is required'):
                self.test_every_target_block_matches_the_model()

    def test_every_target_row_is_reached(self):
        reached = {site for (site, left, _) in self.events if left is not None}
        self.assertEqual(set(self.rows) - reached, set())

    def test_target_sites_never_unpaired(self):
        unpaired = {site for site, left, _ in self.events if left is None}
        self.assertEqual(unpaired & set(self.rows), set())

    def test_host_rejects_wrong_values(self):
        site = ('create_v2', 'thrown', 'create_v2.rs:220', 6063)
        unsupported = CONSTANTS['unsupported_quote_mint']
        queries = [('block', *site, unsupported, unsupported),
                   ('block', *site, unsupported, CONSTANTS['zero']),
                   ('block', 'create_v2', 'thrown', 'create_v2.rs:348', 6075, unsupported, CONSTANTS['zero']),
                   ('forms', 'claim_cashback_v2', 'thrown', 'token_incentives/claim_token_incentives.rs:121', 6010),
                   ('forms', 'no_such_handler', 'account', 'global', 6000)]
        self.assertEqual(self.answers(queries),
                         [f'Left:\t{unsupported}\tRight:\t{unsupported}', 'unknown', 'unknown', 'unknown', 'unknown'])


if __name__ == '__main__':
    if sys.argv[1:2] == ['--harvest-cases']:
        prev.RecordingVm = RestRecorder
        prev.harvest_cases()
    elif sys.argv[1:2] == ['--harvest-suite']:
        prev.RecordingVm = RestRecorder
        prev.harvest_suite(sys.argv[2])
    elif sys.argv[1:2] == ['--harvest-poolchain']:
        harvest_poolchain()
    elif sys.argv[1:2] == ['--harvest-mh']:
        harvest_mh()
    else:
        unittest.main()
