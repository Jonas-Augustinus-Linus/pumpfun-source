#!/usr/bin/env python3
"""Repeat the default CLI transition on retained ELF bytes; no VM execution."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

BASE = '599891304e83e853ec723dc1417550bef4e1c074'
PROGRAMS = ('pump', 'pump_amm', 'pump_fees', 'mayhem')
EXPECTED = {'pump': (158, 310), 'pump_amm': (121, 196),
            'pump_fees': (119, 187), 'mayhem': (92, 293)}
HELPERS = ('deep_section_analysis.py', 'deep_disassembly.py',
           'window_elf_reader.py', 'analyze.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(repo, args):
    result = subprocess.run([sys.executable, '-B', *map(str, args)], cwd=repo,
                            capture_output=True, text=True)
    require(result.returncode == 0, result.stdout + result.stderr)


def archive_identities(repo):
    return {p.relative_to(repo).as_posix(): digest(p.read_bytes())
            for name in ('math-register-comparisons', 'relocation-text-addresses')
            for p in sorted((repo / 'reconstruction' / name).rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts}


def without_candidates(report):
    value = copy.deepcopy(report)
    del value['windows_with_overflow_checks']
    for row in value['math_intensive_windows']:
        del row['overflow_checks']
    return value


def shift_receipt(report):
    value = copy.deepcopy(report)
    for row in value['math_intensive_windows']:
        del row['shifts']
    return digest(encoded(value))


def opcode_oracle(elf, report):
    """Decode class/operation/source bits at logical instruction boundaries."""
    immediate = register = 0
    for row in report['math_intensive_windows']:
        at = int(row['address'], 16)
        end = at + row['size']
        previous = None
        expected = 0
        while at < end:
            op = elf.b[at]
            if (previous is not None and previous & 7 == 7
                    and previous & 0xf0 in (0, 0x10, 0x20)
                    and op & 7 == 5 and op & 0xf0 in (0x20, 0x30, 0xa0, 0xb0)):
                expected += 1
                register += bool(op & 8)
                immediate += not bool(op & 8)
            previous = op
            at += 16 if op == 0x18 else 8
        require(row['overflow_checks'] == expected, f'opcode oracle at {row["address"]}')
    return {'immediate': immediate, 'register': register}


def lddw_control(repo, Elf):
    rows = []
    for capture in sorted((repo / 'evidence').glob('**/capture.json')):
        elf = Elf(capture.parent / 'deployed.so')
        at, count, nonzero = elf.lo, 0, []
        while at < elf.hi:
            if elf.b[at] == 0x18:
                count += 1
                if elf.b[at + 8]:
                    nonzero.append(hex(at + 8))
                at += 16
            else:
                at += 8
        require(not nonzero, 'unexpected nonzero continuation opcode: ' + str(capture))
        rows.append({'capture': capture.parent.relative_to(repo).as_posix(),
                     'sha256': digest(elf.b), 'lddw_count': count,
                     'nonzero_continuation_opcode_offsets': nonzero})
    require(len(rows) == 9, 'expected nine retained captures')
    return rows


def reproduce(repo, *, base=None):
    repo = Path(repo).resolve()
    sys.path.insert(0, str(repo / 'scripts'))
    from window_elf_reader import Elf
    preserved = archive_identities(repo)
    if base:
        for path, expected in preserved.items():
            require(digest(subprocess.check_output(['git', 'show', f'{base}:{path}'], cwd=repo))
                    == expected, 'archived package differs from base: ' + path)
    captures = {p: digest((repo / 'evidence/original' / p / 'deployed.so').read_bytes())
                for p in PROGRAMS}
    result = {'base': base, 'current_analyzer_sha256': digest(
        (repo / 'scripts/deep_section_analysis.py').read_bytes()),
        'method': 'Actual full default CLI and accepted source-bound CLI; static ELF reads only.',
        'programs': {}, 'archived_package_sha256': preserved}
    if base:
        result['archived_packages_match_exact_base'] = True
    with tempfile.TemporaryDirectory(prefix='math-register-default-') as temporary:
        tmp = Path(temporary)
        if base:
            original = tmp / 'base'
            (original / 'scripts').mkdir(parents=True)
            (original / 'evidence').symlink_to(repo / 'evidence', target_is_directory=True)
            identities = {}
            for name in HELPERS:
                raw = subprocess.check_output(['git', 'show', f'{base}:scripts/{name}'], cwd=repo)
                if name != 'deep_section_analysis.py':
                    require(raw == (repo / 'scripts' / name).read_bytes(), 'changed dependency ' + name)
                (original / 'scripts' / name).write_bytes(raw)
                identities[name] = digest(raw)
            result['exact_base_helper_sha256'] = identities
        for program in PROGRAMS:
            current_path = tmp / (program + '-current')
            run(repo, [repo / 'scripts/deep_section_analysis.py', '--program', program,
                       '--output', current_path])
            run(repo, [current_path / 'verify.py'])
            current = json.loads((current_path / 'layer5-math-analysis.json').read_text())
            adapter = repo / 'reconstruction/math-register-comparisons/analyze.py'
            archived = []
            for mode in ('before', 'accepted'):
                output = tmp / f'{program}-{mode}.json'
                run(repo, [adapter, '--program', program, '--output', output,
                           *(['--archived'] if mode == 'before' else [])])
                archived.append(json.loads(output.read_text())['analysis'])
            before, accepted = archived
            require(current == accepted, program + ': default CLI differs from accepted correction')
            require(without_candidates(before) == without_candidates(current), 'unrelated math field changed')
            totals = [sum(w['overflow_checks'] for w in r['math_intensive_windows']) for r in (before, current)]
            require(tuple(totals) == EXPECTED[program], 'unexpected candidate totals')
            row = {'capture_sha256': captures[program], 'candidate_totals': totals,
                   'windows_with_candidates': [r['windows_with_overflow_checks'] for r in (before, current)],
                   'math_windows': current['total_math_windows'],
                   'unrelated_math_fields_sha256': digest(encoded(without_candidates(current))),
                   'shift_receipts': [shift_receipt(r) for r in (before, current)],
                   'logical_instruction_oracle': opcode_oracle(
                       Elf(repo / 'evidence/original' / program / 'deployed.so'), current),
                   'accepted_archive_matches_current': True}
            if base:
                before_path = tmp / (program + '-base')
                run(repo, [original / 'scripts/deep_section_analysis.py', '--program', program,
                           '--output', before_path])
                run(repo, [before_path / 'verify.py'])
                require(json.loads((before_path / 'layer5-math-analysis.json').read_text()) == before,
                        'exact-base CLI differs from archived math baseline')
                names = sorted(p.name for p in current_path.iterdir())
                require(names == sorted(p.name for p in before_path.iterdir()), 'packet file set changed')
                changed = [n for n in names if (before_path / n).read_bytes() != (current_path / n).read_bytes()]
                require(changed == ['README.md', 'layer5-math-analysis.json', 'manifest.json', 'summary.json'],
                        'unexpected packet changes: ' + repr(changed))
                summaries = [json.loads((p / 'summary.json').read_text()) for p in (before_path, current_path)]
                for summary in summaries:
                    del summary['layer5_math']['overflow_protected']
                require(summaries[0] == summaries[1], 'unrelated summary field changed')
                readme = (before_path / 'README.md').read_text().replace(
                    f"Overflow-protected windows: {before['windows_with_overflow_checks']}",
                    f"Overflow-protected windows: {current['windows_with_overflow_checks']}")
                require(readme == (current_path / 'README.md').read_text(), 'unrelated README change')
                row['exact_base_default_matches_archived'] = True
                row['changed_packet_files'] = changed
                row['unchanged_packet_sha256'] = {n: digest((current_path / n).read_bytes())
                                                  for n in names if n not in changed}
            result['programs'][program] = row
        result['lddw_control'] = lddw_control(repo, Elf)
    require(archive_identities(repo) == preserved, 'archived package changed')
    for program, expected in captures.items():
        require(digest((repo / 'evidence/original' / program / 'deployed.so').read_bytes()) == expected,
                'capture changed')
    result['captures_and_archived_packages_unchanged'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--base', default=BASE)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = reproduce(args.repo, base=args.base)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
