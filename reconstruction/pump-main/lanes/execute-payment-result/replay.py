# Adapted from thegeronimo/pumpfun-source PR #1292, commit 4a8336358fd5d2fd00257ef5523202222d6c8cc5.
# Uses unchanged repository case definitions; adds strict exit status and control-log comparison.
import argparse
from base64 import b64decode
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
from pump_differential_output import PumpReport


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sources = ('scripts/pump_trade_fixture.py',
               'scripts/pump_v3_configured_fee_differential.py')
    shared = [f'evidence/{group}/{name}/{filename}'
              for group, names in (('original', ('pump', 'pump_fees')),
                                   ('dependencies', ('spl_token', 'spl_token_2022', 'associated_token')))
              for name in names for filename in ('capture.json', 'deployed.so')]
    fixture = HERE / 'fixture.json.gz'
    paths = {name: ROOT / name for name in (*sources, *shared)}
    paths.update(control=args.control, candidate=args.candidate,
                 fixture=fixture)
    try:
        publisher = PumpReport(args.output, ROOT, args.candidate, __file__,
                               extra_inputs=paths.values(), overwrite=False)
        # Read each declared input once. All program loads and the unchanged
        # fixture/suite logic below use private copies of precisely these bytes.
        snapshots = {name: path.read_bytes() for name, path in paths.items()}
        with tempfile.TemporaryDirectory(prefix='pump-v3-replay-') as scratch:
            root = Path(scratch)
            for name in (*sources, *shared):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(snapshots[name])
            images = {'original': root / 'evidence/original/pump/deployed.so',
                      'control': root / 'control.so', 'candidate': root / 'candidate.so'}
            for role in ('control', 'candidate'):
                images[role].write_bytes(snapshots[role])
            raw_fixture = gzip.decompress(snapshots['fixture'])
            # Only relocate the historical fixture; preserve its case logic.
            source = root / sources[0]
            code = snapshots[sources[0]].decode('utf-8')
            old = "x=json.load(open(R/'research/imported-lab/analysis/pump_fun/curve-fresh-trades-v3-signed-surfpool.json',encoding='utf-8'))"
            if code.count(old) != 1:
                raise ValueError('shared trade fixture relocation marker changed')
            code = code.replace(old, 'x=' + repr(json.loads(raw_fixture)))
            module = types.ModuleType('pump_trade_fixture')
            module.__file__ = str(source)
            sys.modules[module.__name__] = module
            exec(compile(code, str(source), 'exec'), module.__dict__)
            name = 'pump_v3_configured_fee_differential'
            # The existing one-case test adapter installs a suite shim. Normal
            # CLI execution compiles the captured suite bytes from the snapshot.
            suite = sys.modules.get(name)
            if suite is None:
                suite = types.ModuleType(name)
                suite.__file__ = str(root / sources[1])
                sys.modules[name] = suite
                exec(compile(snapshots[sources[1]], suite.__file__, 'exec'), suite.__dict__)
            from solders.transaction import Transaction
            cases = [c for c in suite.cases()
                     if c['operation'] in ('buy_v3', 'buy_exact_quote_in_v3')]
            fields = ['error', 'accounts', 'inner_instructions', 'event_payloads', 'return_data']
            rows, bad, changed = [], [], []

            def logs(row):
                return [line for line in row['logs'] if not re.fullmatch(
                    r'Program [1-9A-HJ-NP-Za-km-z]+ consumed \d+ of \d+ compute units', line)]

            for i, case in enumerate(cases):
                receipts = {role: suite.run(path, case) for role, path in images.items()}
                for receipt in receipts.values():
                    tx = Transaction.from_bytes(b64decode(receipt['transaction_base64']))
                    required = tx.message.header.num_required_signatures
                    verified = tx.verify_with_results()
                    if (required < 1 or len(tx.signatures) != required
                            or verified != [True] * required):
                        raise ValueError('replay transaction signature verification failed')
                diff = [key for key in fields if receipts['original'][key] != receipts['candidate'][key]]
                regression = [key for key in fields if receipts['control'][key] != receipts['candidate'][key]]
                logdiff = logs(receipts['original']) != logs(receipts['candidate'])
                rows.append({'case': case, 'receipts': receipts, 'different_fields': diff,
                             'regression_fields': regression, 'ordered_non_meter_logs_equal': not logdiff})
                if diff or logdiff:
                    bad.append(i)
                if regression or logs(receipts['control']) != logs(receipts['candidate']):
                    changed.append(i)
                if (i + 1) % 20 == 0:
                    print(json.dumps({'done': i + 1, 'total': len(cases),
                                      'differences': bad, 'regressions': changed}), flush=True)
            digest = lambda data: hashlib.sha256(data).hexdigest()
            report = {'case_count': len(cases),
                      'images': {role: digest(snapshots['evidence/original/pump/deployed.so' if role == 'original' else role])
                                 for role in images},
                      'source_inputs': {name: digest(snapshots[name]) for name in sources},
                      'fixture_sha256': digest(raw_fixture),
                      'declared_input_sha256': {name: digest(data) for name, data in snapshots.items()},
                      'rows': rows, 'differences': bad, 'regressions': changed}
            payload = gzip.compress((json.dumps(report, sort_keys=True) + '\n').encode('utf-8'), mtime=0)
            publisher.write(payload)
        print(json.dumps({key: value for key, value in report.items() if key != 'rows'}), flush=True)
        return 1 if bad or changed else 0
    except (OSError, ValueError) as error:
        parser.exit(2, f'cannot replay or publish report: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
