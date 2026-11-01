#!/usr/bin/env python3
"""Compare two exact legacy-SBPF function windows; diagnostic, never a score.

The official ``score.py`` normalization is used verbatim.  Similarity and block
matching in this module are explanatory heuristics and never establish byte
identity, normalized identity, source attribution, or scorer acceptance.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from compare_scores import load_report, publish_report
from elf_symbols import function_symbols
from instruction_stream import require_instruction_range
from score import body, normalize, sections
from score_admission import report_destination


SCHEMA = 'sbpf-residual-analysis-v1'


def unique_json_fields(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f'duplicate JSON field: {key}')
        result[key] = value
    return result


def parse_window(value):
    """Parse an exact START:SIZE selector using Python-style integer prefixes."""
    try:
        start_text, size_text = value.split(':')
        start, size = int(start_text, 0), int(size_text, 0)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError('window must be START:SIZE (for example 0x22a10:27400)')
    if start < 0 or size <= 0 or start % 8 or size % 8:
        raise argparse.ArgumentTypeError('window start and size must describe positive aligned 8-byte slots')
    return start, size


def load_image(path, role):
    """Read and validate one immutable in-memory ELF snapshot."""
    path = Path(path)
    blob = path.read_bytes()
    secs = sections(blob)
    if struct.unpack_from('<H', blob, 18)[0] not in (247, 263):
        raise ValueError(f'{role} is not an EM_BPF or EM_SBPF image')
    if struct.unpack_from('<I', blob, 20)[0] != 1:
        raise ValueError(f'{role} ELF header version is not 1')
    if struct.unpack_from('<I', blob, 0x30)[0] not in (0, 1):
        raise ValueError(f'{role} is not a legacy SBPFv0/v1 image')
    symbols = function_symbols(blob)
    if role == 'candidate' and not symbols:
        raise ValueError('candidate has no function symbols; use an unstripped reconstruction ELF')
    return {
        'role': role,
        'path': path,
        'blob': blob,
        'sections': secs,
        'symbols': symbols,
        'sha256': hashlib.sha256(blob).hexdigest(),
    }


def select_window(image, exact_window=None, exact_symbol=None):
    """Resolve a selector and bind candidate ranges to a complete function symbol."""
    if (exact_window is None) == (exact_symbol is None):
        raise ValueError(f"{image['role']} requires exactly one window or symbol selector")
    symbols = image['symbols']
    if exact_symbol is not None:
        matches = [(start, size) for start, size, name in symbols if name == exact_symbol]
        ranges = sorted(set(matches))
        if not ranges:
            raise ValueError(f"{image['role']} symbol not found: {exact_symbol!r}")
        if len(ranges) != 1:
            raise ValueError(f"{image['role']} symbol has ambiguous ranges: {exact_symbol!r}")
        start, size = ranges[0]
    else:
        start, size = exact_window
    text = image['sections']['.text']
    text_raw = body(image['blob'], image['sections'], text['addr'], text['size'])
    require_instruction_range(text_raw, start - text['addr'], size)
    raw = body(image['blob'], image['sections'], start, size)
    if len(raw) != size:
        raise ValueError(f"{image['role']} window is truncated")
    symbol_names = sorted({name for address, length, name in symbols
                           if (address, length) == (start, size)})
    if image['role'] == 'candidate' and not symbol_names:
        raise ValueError('candidate window must exactly match a function symbol range')
    if exact_symbol is not None and exact_symbol not in symbol_names:
        raise ValueError(f"{image['role']} symbol identity changed while selecting its range")
    return {
        'start': start,
        'size': size,
        'end': start + size,
        'raw': raw,
        'normalized': normalize(raw, start, image['sections']),
        'symbols': symbol_names,
        'selector': {'kind': 'symbol', 'value': exact_symbol} if exact_symbol is not None else {
            'kind': 'window', 'value': f'{start:#x}:{size}'},
    }


def _receipt_candidate_digest(document):
    values = []
    if isinstance(document, dict):
        if isinstance(document.get('candidate_sha256'), str):
            values.append(document['candidate_sha256'])
        summary = document.get('summary')
        if isinstance(summary, dict) and isinstance(summary.get('candidate_sha256'), str):
            values.append(summary['candidate_sha256'])
    values = sorted(set(values))
    if len(values) != 1 or not all(len(value) == 64 for value in values):
        raise ValueError('score receipt must contain one candidate_sha256 identity')
    try:
        bytes.fromhex(values[0])
    except ValueError as error:
        raise ValueError('score receipt candidate_sha256 is not hexadecimal') from error
    return values[0]


def admit_receipt(path, candidate, original_window):
    """Bind a standard score receipt to the candidate bytes and selected original window."""
    path = Path(path)
    text = path.read_text(encoding='utf-8')
    document = json.loads(text, object_pairs_hook=unique_json_fields)
    digest = _receipt_candidate_digest(document)
    if digest != candidate['sha256']:
        raise ValueError(f'score receipt candidate_sha256 does not match candidate bytes: {path}')
    windows = load_report(path)
    start = original_window['start']
    if start not in windows:
        raise ValueError(f'score receipt does not contain selected original window {start:#x}: {path}')
    if windows[start]['bytes'] != original_window['size']:
        raise ValueError(f'score receipt window size differs at {start:#x}: {path}')
    return {
        'path': str(path.resolve()),
        'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
        'candidate_sha256': digest,
        'selected_window': {'start': start, **windows[start]},
    }


def public_image(image, window):
    return {
        'path': str(image['path'].resolve()),
        'sha256': image['sha256'],
        'bytes': len(image['blob']),
        'machine': struct.unpack_from('<H', image['blob'], 18)[0],
        'sbpf_version': struct.unpack_from('<I', image['blob'], 0x30)[0],
        'text': {key: image['sections']['.text'][key] for key in ('addr', 'offset', 'size')},
        'window': {key: window[key] for key in ('start', 'end', 'size', 'symbols', 'selector')},
    }


def admit_inputs(original_path, candidate_path, original_selector, candidate_selector, receipts=()):
    original = load_image(original_path, 'original')
    candidate = load_image(candidate_path, 'candidate')
    original_window = select_window(original, **original_selector)
    candidate_window = select_window(candidate, **candidate_selector)
    admitted_receipts = [admit_receipt(path, candidate, original_window) for path in receipts]
    return original, candidate, original_window, candidate_window, admitted_receipts


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path, help='captured original ELF')
    parser.add_argument('candidate', type=Path, help='unstripped reconstruction ELF')
    original = parser.add_mutually_exclusive_group(required=True)
    original.add_argument('--original-window', type=parse_window, metavar='START:SIZE')
    original.add_argument('--original-symbol', help='exact ELF symbol name')
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument('--candidate-window', type=parse_window, metavar='START:SIZE')
    candidate.add_argument('--candidate-symbol', help='exact ELF symbol name')
    parser.add_argument('--score-receipt', action='append', default=[], type=Path,
                        help='optional score.py JSON receipt (repeatable)')
    parser.add_argument('--json', type=Path, help='write the complete machine-readable report')
    parser.add_argument('--format', choices=('text', 'json'), default='text', help='stdout format')
    parser.add_argument('--top', type=int, default=20, help='residual rows in the text report')
    return parser


def _selector_args(args, role):
    window = getattr(args, role + '_window')
    symbol = getattr(args, role + '_symbol')
    return {'exact_window': window, 'exact_symbol': symbol}


def analyze_admission(args):
    original, candidate, ow, cw, receipts = admit_inputs(
        args.original, args.candidate, _selector_args(args, 'original'),
        _selector_args(args, 'candidate'), args.score_receipt)
    return {
        'schema': SCHEMA,
        'scope': ('Diagnostic comparison. Heuristic similarity and block correspondence are not byte identity, '
                  'normalized identity, source attribution, or official score acceptance.'),
        'inputs': {'original': public_image(original, ow), 'candidate': public_image(candidate, cw)},
        'score_receipts': receipts,
    }


def render_admission(report):
    original, candidate = report['inputs']['original'], report['inputs']['candidate']
    return '\n'.join([
        'SBPF residual analysis (input admission)',
        f"original  {original['window']['start']:#x}+{original['window']['size']}  sha256={original['sha256']}",
        f"candidate {candidate['window']['start']:#x}+{candidate['window']['size']}  sha256={candidate['sha256']}",
        f"score receipts: {len(report['score_receipts'])}",
        report['scope'],
    ]) + '\n'


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.top < 0:
        parser.error('--top must be nonnegative')
    try:
        report_destination(args.json, [args.original, args.candidate, *args.score_receipt])
        report = analyze_admission(args)
        output = json.dumps(report, indent=2, sort_keys=True) + '\n'
        if args.json:
            publish_report(args.json, output)
    except (OSError, ValueError, KeyError, struct.error, json.JSONDecodeError) as error:
        parser.exit(2, f'residual_analysis.py: error: {error}\n')
    print(output if args.format == 'json' else render_admission(report), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
