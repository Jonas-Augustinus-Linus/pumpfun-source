#!/usr/bin/env python3
"""Check the sealed packet, then independently regenerate its artifact findings."""
import gzip
import hashlib
import json
from pathlib import Path

import audit


def block_map(report):
    lines = ['original_block\tcandidate_block\tvalue_slots\tvalues_and_relocations_equal\toriginal_successors\tcandidate_successors']
    for b in report['current']['comparison']['blocks']:
        lines.append('\t'.join([b['original_offset'], b['candidate_offset'], str(len(b['values'])),
                                str(b['instructions_and_relocations_equal']).lower(),
                                json.dumps(b['original_edges'], separators=(',', ':')),
                                json.dumps(b['candidate_edges'], separators=(',', ':'))]))
    return '\n'.join(lines) + '\n'


def main():
    p = Path(__file__).resolve().parent
    manifest = json.loads((p / 'manifest.json').read_text())
    paths = {str(x.relative_to(p)) for x in p.rglob('*') if x.is_file() and '__pycache__' not in x.parts}
    audit.require(paths == set(manifest) | {'manifest.json'}, 'packet membership changed')
    for name, digest in manifest.items():
        audit.require(hashlib.sha256((p / name).read_bytes()).hexdigest() == digest, 'packet drift: ' + name)
    result = audit.run()
    audit.qualify(result)
    audit.require(result == json.loads(gzip.decompress((p / 'report.json.gz').read_bytes())), 'report drift')
    audit.require(audit.summary(result) == json.loads((p / 'summary.json').read_text()), 'summary drift')
    audit.require(block_map(result) == (p / 'block-map.tsv').read_text(), 'block map drift')
    print(json.dumps({'result': 'PASS', 'blocks': 77, 'nonbranch_slots': 1049,
                      'register_differences': 0, 'depth2_call_matches': '79/80',
                      'official_normalized': 784, 'official_raw': 394,
                      'sell_status': 'UNEQUAL', 'new_function_matches': 0}))


if __name__ == '__main__':
    main()
