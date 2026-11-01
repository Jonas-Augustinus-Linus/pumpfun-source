"""Recompute source/body/call evidence and audit saved runtime receipts.

This reads the retained outputs; it does not rebuild or rerun the program.
"""
from collections import Counter
import difflib
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import runpy

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = 'programs/pump-amm/src/instructions/swap/buy.rs'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(name):
    data = (HERE / name).read_bytes()
    return gzip.decompress(data) if name.endswith('.gz') else data


def record(name):
    return json.loads(read(name))


manifest = record('MANIFEST.json')
for name, digest in manifest['files'].items():
    assert sha((HERE / name).read_bytes()) == digest, name
for name, digest in manifest['repository_inputs'].items():
    assert sha((ROOT / name).read_bytes()) == digest, name
materialize = runpy.run_path(str(HERE / 'materialize.py'))
sources = {k: materialize['source_files'](k) for k in ('baseline', 'candidate')}
before, after = sources.values()
assert before.keys() == after.keys()
assert [p for p in before if before[p] != after[p]] == [SOURCE]
assert after[SOURCE] == read('proposed/buy.rs')
patch = ''.join(difflib.unified_diff(before[SOURCE].decode().splitlines(True),
                                  after[SOURCE].decode().splitlines(True),
                                  fromfile='a/' + SOURCE, tofile='b/' + SOURCE))
assert patch.encode() == read('source.patch')
public = record('public-source.json')
assert public['ref'] == '63d108022f6be295d9e8e7f697f3024f4aa44fea'
assert all(sha(before[p]) == digest for p, digest in public['changed_inputs'].items())
builds, images = {}, {}
for label in ('baseline', 'candidate', 'repeat'):
    launch = record('builds/' + label + '/launch.json')
    result = record('builds/' + label + '/result.json')
    src = sources['candidate' if label == 'repeat' else label]
    assert launch['inputs'] == {p: sha(b) for p, b in src.items()}
    assert result['returncode'] == 0 and result['source_unchanged']
    assert not result.get('changed_prior_dependencies', [])
    assert result.get('dependencies_unchanged', True)
    assert result['actual_root_invocations'] == 1
    log = read('builds/' + label + '/build.log.gz').decode()
    assert sum(l.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in l
               for l in log.splitlines()) == 1
    assert '--network' in launch['command'] and 'none' in launch['command']
    assert '--offline' in launch['command'] and '--locked' in launch['command']
    images[label] = {}
    for kind in ('symbols', 'candidate'):
        data = read('builds/' + label + '/' + kind + '.so.gz')
        assert sha(data) == result[kind + '_sha256']
        images[label][kind] = data
    builds[label] = launch
for label in ('candidate', 'repeat'):
    assert builds[label]['tools'] == builds['baseline']['tools']
    assert all(builds[label]['dependencies_before'][p] == digest
               for p, digest in builds['baseline']['dependencies_before'].items())
    assert len(builds[label]['dependencies_before']) - len(builds['baseline']['dependencies_before']) == 30
    root = lambda k: next(line for line in read('builds/' + k + '/build.log.gz').decode().splitlines()
                          if line.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in line)
    assert re.findall(r'--extern ([^ ]+)', root(label)) == re.findall(r'--extern ([^ ]+)', root('baseline'))
assert builds['candidate']['dependencies_before'] == builds['repeat']['dependencies_before']
assert images['candidate'] == images['repeat']
assert sha(images['baseline']['candidate']) == '4e58c47139798d743c325c8ee9c3a98f4fd7cc4ceba2d6a5763e66899c4efd25'

# Recompute the actual handler edges and all seven typed operands of the new body.
static = runpy.run_path(str(HERE / 'analyze.py'))
w = static['w']
original = static['blobs']['original']
assert sha(original) == '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
originals = w.windows(original)
assert len(originals) == 785
matched = {}
for label in ('baseline', 'candidate'):
    functions = w.windows(images[label]['symbols'])
    matched[label] = [Counter(f[key] for f in originals) & Counter(f[key] for f in functions)
                      for key in ('signature', 'raw_sha256')]
assert [sum(c.values()) for c in matched['baseline']] == [726, 148]
assert [sum(c.values()) for c in matched['candidate']] == [727, 148]
gain = matched['candidate'][0] - matched['baseline'][0]
assert gain == {'52ff79c1d6069fd748261b4bc390816031fa4513160668928d817bb2635165ca': 1}
assert not matched['baseline'][0] - matched['candidate'][0]
assert matched['baseline'][1] == matched['candidate'][1]

hashes = dict(original=sha(original), **{k: sha(images[k]['candidate']) for k in ('baseline', 'candidate')})
norm = lambda logs: [x for x in logs if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units', x)]
full = record('runtime/full-candidate.json.gz')
baseline = record('runtime/full-baseline.json.gz')
focused = record('runtime/focused.json.gz')
assert len(full['cases']) == len(baseline) == 1011 and not full['mismatches']
assert full['candidate_sha256'] == hashes['candidate'] and full['original_sha256'] == hashes['original']
assert focused['case_count'] == 25 and focused['artifact_sha256'] == hashes
for scope, triples in [('full', [dict(original=a['original'], baseline=b['baseline'], candidate=a['candidate'])
                               for a, b in zip(full['cases'], baseline)]),
                       ('focused', [row['results'] for row in focused['cases']])]:
    observed = record('runtime/' + scope + '-observed.json.gz')
    assert observed['transaction_count'] == observed['signature_count'] == len(triples) * 3
    observed_rows = Counter((r['amm_program_sha256'], r['transaction_base64'], r['logs_sha256'])
                            for r in observed['transactions'] if r['all_signatures_verified'])
    expected_rows = Counter()
    gains, losses, mismatches = [], [], Counter()
    for i, triple in enumerate(triples):
        a = triple['original']
        for label, b in triple.items():
            assert {k: v for k, v in a.items() if k != 'logs'} == {k: v for k, v in b.items() if k != 'logs'}, (scope, i, label)
            expected_rows[(hashes[label], b['transaction_base64'], sha(json.dumps(b['logs'], separators=(',', ':')).encode()))] += 1
            mismatches[label] += norm(a['logs']) != norm(b['logs'])
        x, y = (norm(a['logs']) == norm(triple[k]['logs']) for k in ('baseline', 'candidate'))
        if not x and y: gains.append(i)
        if x and not y: losses.append(i)
    assert observed_rows == expected_rows and not losses
    assert (mismatches['baseline'], mismatches['candidate'], len(gains)) == ((98, 82, 16) if scope == 'full' else (17, 4, 13))
print('PASS: 726 -> 727 normalized, 148 raw retained; actual calls/data checked; 1011 full and 25 focused case triples audited.')
