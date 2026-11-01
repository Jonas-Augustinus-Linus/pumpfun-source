#!/usr/bin/env python3
"""Compare two exact legacy-SBPF function windows; diagnostic, never a score.

The official ``score.py`` normalization is used verbatim.  Similarity and block
matching in this module are explanatory heuristics and never establish byte
identity, normalized identity, source attribution, or scorer acceptance.
"""
import argparse
from collections import Counter, defaultdict
import difflib
import hashlib
import json
import struct
from pathlib import Path

from compare_scores import load_report, publish_report
from control_flow import LEGACY_CONDITIONAL_JUMPS, analyze as analyze_control_flow
from elf_symbols import function_symbols
from instruction_stream import decode_instructions, require_instruction_range
from score import body, normalize, sections
from score_admission import report_destination


SCHEMA = 'sbpf-residual-analysis-v1'
BRANCH_OPCODES = LEGACY_CONDITIONAL_JUMPS | {0x05}


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


def _digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _call_kind(row):
    if row['opcode'] == 0x8d:
        return 'indirect'
    if row['opcode'] != 0x85:
        return None
    if row['src'] == 1 and row['immediate'] != -1:
        return 'direct'
    return 'syscall_or_relocated'


def _target_independent_token(row):
    token = bytearray(row['bytes'])
    if row['opcode'] in BRANCH_OPCODES:
        token[2:4] = b'\0\0'
    return token.hex()


def build_function_model(image, window):
    """Attach complete decoded instructions to the maintained CFG blocks."""
    raw_rows = decode_instructions(window['raw'], window['start'])
    normalized_rows = decode_instructions(window['normalized'], window['start'])
    if [row['offset'] for row in raw_rows] != [row['offset'] for row in normalized_rows]:
        raise ValueError(f"{image['role']} normalization changed instruction boundaries")
    cfg = analyze_control_flow(window['raw'], window['start'])
    predecessors = defaultdict(list)
    for block in cfg['blocks']:
        for edge in block['successors']:
            if edge['internal']:
                predecessors[edge['target']].append({'source': block['offset'], 'kind': edge['kind']})
    blocks = []
    for block in cfg['blocks']:
        end = block['offset'] + block['bytes']
        indexes = [index for index, row in enumerate(raw_rows)
                   if block['offset'] <= row['offset'] < end]
        rows = [raw_rows[index] for index in indexes]
        norm = [normalized_rows[index] for index in indexes]
        successors = [dict(edge) for edge in block['successors']]
        predecessor_rows = sorted(predecessors[block['offset']], key=lambda row: (row['kind'], row['source']))
        content_material = {
            'tokens': [_target_independent_token(row) for row in norm],
            'successor_kinds': [edge['kind'] for edge in successors],
        }
        structural_material = {
            'opcodes': [row['opcode'] for row in rows],
            'widths': [row['width'] for row in rows],
            'calls': [_call_kind(row) for row in rows if _call_kind(row)],
            'successor_kinds': [edge['kind'] for edge in successors],
            'predecessor_kinds': [row['kind'] for row in predecessor_rows],
            'reachable': block['reachable'],
        }
        blocks.append({
            **block,
            'absolute_address': window['start'] + block['offset'],
            'predecessors': predecessor_rows,
            'content_fingerprint': _digest(content_material),
            'structural_fingerprint': _digest(structural_material),
            '_instructions': rows,
            '_normalized_instructions': norm,
            '_content_material': content_material,
            '_structural_material': structural_material,
        })
    return {
        'start': window['start'],
        'size': window['size'],
        'raw_equal_sha256': hashlib.sha256(window['raw']).hexdigest(),
        'normalized_sha256': hashlib.sha256(window['normalized']).hexdigest(),
        'instructions': raw_rows,
        'normalized_instructions': normalized_rows,
        'blocks': blocks,
        'calls': cfg['calls'],
        'diagnostics': cfg['diagnostics'],
        'cyclic_regions': cfg['cyclic_regions'],
    }


def _multiset_jaccard(left, right):
    a, b = Counter(left), Counter(right)
    return sum((a & b).values()) / max(1, sum((a | b).values()))


def block_similarity(original, candidate):
    """Deterministic structural heuristic; it is never an equality predicate."""
    left = original['_structural_material']
    right = candidate['_structural_material']
    opcode_jaccard = _multiset_jaccard(left['opcodes'], right['opcodes'])
    length_ratio = min(len(left['opcodes']), len(right['opcodes'])) / max(1, len(left['opcodes']), len(right['opcodes']))
    order_ratio = difflib.SequenceMatcher(None, left['opcodes'], right['opcodes'], autojunk=False).ratio()
    successor_equal = left['successor_kinds'] == right['successor_kinds']
    predecessor_equal = left['predecessor_kinds'] == right['predecessor_kinds']
    calls_equal = left['calls'] == right['calls']
    terminal_equal = bool(left['opcodes'] and right['opcodes'] and left['opcodes'][-1] == right['opcodes'][-1])
    score = (0.25 * opcode_jaccard + 0.25 * order_ratio + 0.15 * length_ratio
             + 0.15 * successor_equal + 0.07 * predecessor_equal
             + 0.08 * calls_equal + 0.05 * terminal_equal)
    return round(score, 6)


def match_blocks(original_model, candidate_model):
    """Match blocks in reproducible stages and retain every uncertain choice."""
    originals = {block['offset']: block for block in original_model['blocks']}
    candidates = {block['offset']: block for block in candidate_model['blocks']}
    mapping, reverse, matches, ambiguities = {}, {}, [], []

    def claim(original_offset, candidate_offset, method, confidence, score, evidence):
        if original_offset in mapping or candidate_offset in reverse:
            return False
        mapping[original_offset] = candidate_offset
        reverse[candidate_offset] = original_offset
        matches.append({
            'original_offset': original_offset,
            'candidate_offset': candidate_offset,
            'method': method,
            'confidence': confidence,
            'similarity': round(score, 6),
            'evidence': evidence,
        })
        return True

    def unique_fingerprints(field, method, confidence, score):
        left, right = defaultdict(list), defaultdict(list)
        for offset, block in originals.items():
            if offset not in mapping:
                left[block[field]].append(offset)
        for offset, block in candidates.items():
            if offset not in reverse:
                right[block[field]].append(offset)
        for fingerprint in sorted(left.keys() & right.keys()):
            if len(left[fingerprint]) == len(right[fingerprint]) == 1:
                claim(left[fingerprint][0], right[fingerprint][0], method, confidence, score,
                      [f'unique_{field}'])

    unique_fingerprints('content_fingerprint', 'unique_content', 'high', 1.0)
    unique_fingerprints('structural_fingerprint', 'unique_structure', 'high', 0.95)
    if 0 in originals and 0 in candidates and 0 not in mapping and 0 not in reverse:
        claim(0, 0, 'entry_anchor', 'medium', block_similarity(originals[0], candidates[0]),
              ['function_entry_anchor'])

    # A matched predecessor can identify a changed successor without relying on
    # physical layout, but only when an edge kind is singular on both sides.
    changed = True
    while changed:
        changed = False
        for original_offset, candidate_offset in sorted(mapping.items()):
            left_edges, right_edges = defaultdict(list), defaultdict(list)
            for edge in originals[original_offset]['successors']:
                if edge['internal'] and edge['target'] not in mapping:
                    left_edges[edge['kind']].append(edge['target'])
            for edge in candidates[candidate_offset]['successors']:
                if edge['internal'] and edge['target'] not in reverse:
                    right_edges[edge['kind']].append(edge['target'])
            for kind in sorted(left_edges.keys() & right_edges.keys()):
                if len(left_edges[kind]) != 1 or len(right_edges[kind]) != 1:
                    continue
                left_offset, right_offset = left_edges[kind][0], right_edges[kind][0]
                similarity = block_similarity(originals[left_offset], candidates[right_offset])
                if similarity >= 0.55 and claim(left_offset, right_offset, 'edge_context', 'medium', similarity,
                                                [f'unique_{kind}_edge_from_matched_blocks']):
                    changed = True

    # Last resort: only accept a mutual unique best with a visible margin.
    remaining_left = [offset for offset in originals if offset not in mapping]
    remaining_right = [offset for offset in candidates if offset not in reverse]
    scores = {}
    for left_offset in remaining_left:
        left_block = originals[left_offset]
        for right_offset in remaining_right:
            right_block = candidates[right_offset]
            length_ratio = min(left_block['instructions'], right_block['instructions']) / max(
                1, left_block['instructions'], right_block['instructions'])
            if length_ratio >= 0.35 and left_block['reachable'] == right_block['reachable']:
                scores[left_offset, right_offset] = block_similarity(left_block, right_block)

    def ranked_for_left(offset):
        return sorted(((score, right) for (left, right), score in scores.items() if left == offset),
                      key=lambda row: (-row[0], row[1]))

    def ranked_for_right(offset):
        return sorted(((score, left) for (left, right), score in scores.items() if right == offset),
                      key=lambda row: (-row[0], row[1]))

    left_best, right_best = {}, {}
    for offset in remaining_left:
        ranked = ranked_for_left(offset)
        if ranked:
            margin = ranked[0][0] - (ranked[1][0] if len(ranked) > 1 else 0)
            if ranked[0][0] >= 0.58 and margin >= 0.05:
                left_best[offset] = ranked[0]
            elif ranked[0][0] >= 0.58:
                ambiguities.append({
                    'original_offset': offset,
                    'reason': 'heuristic candidate margin below 0.05',
                    'candidates': [{'candidate_offset': right, 'similarity': score}
                                   for score, right in ranked[:5]],
                })
    for offset in remaining_right:
        ranked = ranked_for_right(offset)
        if ranked:
            margin = ranked[0][0] - (ranked[1][0] if len(ranked) > 1 else 0)
            if ranked[0][0] >= 0.58 and margin >= 0.05:
                right_best[offset] = ranked[0]
    for left_offset, (score, right_offset) in sorted(left_best.items()):
        if right_best.get(right_offset) == (score, left_offset):
            confidence = 'medium' if score >= 0.8 else 'low'
            claim(left_offset, right_offset, 'mutual_best_heuristic', confidence, score,
                  ['mutual_unique_best', 'minimum_margin_0.05'])

    matches.sort(key=lambda row: (row['original_offset'], row['candidate_offset']))
    ambiguities.sort(key=lambda row: row['original_offset'])
    return {
        'matches': matches,
        'mapping': mapping,
        'reverse_mapping': reverse,
        'ambiguities': ambiguities,
        'unmatched_original': sorted(set(originals) - set(mapping)),
        'unmatched_candidate': sorted(set(candidates) - set(reverse)),
    }


def public_block(block):
    return {key: value for key, value in block.items() if not key.startswith('_')}


def compare_graphs(original, candidate):
    matching = match_blocks(original, candidate)
    return {
        'original': {
            'block_count': len(original['blocks']),
            'blocks': [public_block(block) for block in original['blocks']],
            'diagnostics': original['diagnostics'],
            'cyclic_regions': original['cyclic_regions'],
        },
        'candidate': {
            'block_count': len(candidate['blocks']),
            'blocks': [public_block(block) for block in candidate['blocks']],
            'diagnostics': candidate['diagnostics'],
            'cyclic_regions': candidate['cyclic_regions'],
        },
        'matching': {key: value for key, value in matching.items()
                     if key not in ('mapping', 'reverse_mapping')},
        '_mapping': matching['mapping'],
        '_reverse_mapping': matching['reverse_mapping'],
    }


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
    original_model = build_function_model(original, ow)
    candidate_model = build_function_model(candidate, cw)
    control_flow = compare_graphs(original_model, candidate_model)
    matching = control_flow['matching']
    report = {
        'schema': SCHEMA,
        'scope': ('Diagnostic comparison. Heuristic similarity and block correspondence are not byte identity, '
                  'normalized identity, source attribution, or official score acceptance.'),
        'inputs': {'original': public_image(original, ow), 'candidate': public_image(candidate, cw)},
        'score_receipts': receipts,
        'identity': {
            'raw_equal': ow['raw'] == cw['raw'],
            'normalized_equal': ow['normalized'] == cw['normalized'],
            'equal_size': ow['size'] == cw['size'],
        },
        'instruction_counts': {
            'original': len(original_model['instructions']),
            'candidate': len(candidate_model['instructions']),
        },
        'control_flow': {key: value for key, value in control_flow.items() if not key.startswith('_')},
    }
    report['_models'] = (original_model, candidate_model)
    report['_mapping'] = control_flow['_mapping']
    return report


def render_admission(report):
    original, candidate = report['inputs']['original'], report['inputs']['candidate']
    matching = report['control_flow']['matching']
    return '\n'.join([
        'SBPF residual analysis',
        f"original  {original['window']['start']:#x}+{original['window']['size']}  sha256={original['sha256']}",
        f"candidate {candidate['window']['start']:#x}+{candidate['window']['size']}  sha256={candidate['sha256']}",
        f"identity raw={report['identity']['raw_equal']} normalized={report['identity']['normalized_equal']}",
        (f"instructions {report['instruction_counts']['original']}/{report['instruction_counts']['candidate']}  "
         f"blocks {report['control_flow']['original']['block_count']}/{report['control_flow']['candidate']['block_count']}  "
         f"matched={len(matching['matches'])} ambiguous={len(matching['ambiguities'])} "
         f"unmatched={len(matching['unmatched_original'])}/{len(matching['unmatched_candidate'])}"),
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
        public_report = {key: value for key, value in report.items() if not key.startswith('_')}
        output = json.dumps(public_report, indent=2, sort_keys=True) + '\n'
        if args.json:
            publish_report(args.json, output)
    except (OSError, ValueError, KeyError, struct.error, json.JSONDecodeError) as error:
        parser.exit(2, f'residual_analysis.py: error: {error}\n')
    print(output if args.format == 'json' else render_admission(report), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
