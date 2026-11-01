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
SOURCE = 'programs/pump-amm/src/curve/constant_product.rs'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(name):
    data = (HERE / name).read_bytes()
    return gzip.decompress(data) if name.endswith('.gz') else data


def record(name):
    return json.loads(read(name))


manifest = record('MANIFEST.json')
assert set(manifest['files']) == {p.relative_to(HERE).as_posix() for p in HERE.rglob('*') if p.is_file() and p.name != 'MANIFEST.json'}
for name, digest in manifest['files'].items():
    assert sha((HERE / name).read_bytes()) == digest, name
for name, digest in manifest['repository_inputs'].items():
    assert sha((ROOT / name).read_bytes()) == digest, name
assert all(manifest['repository_inputs'][name] == digest for name, digest in record('runtime/inputs.json').items())
materialize = runpy.run_path(str(HERE / 'materialize.py'))
sources = {k: materialize['source_files'](k) for k in ('baseline', 'candidate')}
before, after = sources.values()
assert before.keys() == after.keys()
assert [p for p in before if before[p] != after[p]] == [SOURCE]
assert after[SOURCE] == read('proposed/constant_product.rs')
patch = ''.join(difflib.unified_diff(before[SOURCE].decode().splitlines(True),
                                  after[SOURCE].decode().splitlines(True),
                                  fromfile='a/' + SOURCE, tofile='b/' + SOURCE))
assert patch.encode() == read('source.patch')
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
    assert len(builds[label]['dependencies_before']) - len(builds['baseline']['dependencies_before']) == 0
    root = lambda k: next(line for line in read('builds/' + k + '/build.log.gz').decode().splitlines()
                          if line.strip().startswith('Running `') and '--crate-name pump_amm_recovered ' in line)
    assert re.findall(r'--extern ([^ ]+)', root(label)) == re.findall(r'--extern ([^ ]+)', root('baseline'))
assert builds['candidate']['dependencies_before'] == builds['repeat']['dependencies_before']
assert images['candidate'] == images['repeat']
assert sha(images['baseline']['candidate']) == 'c7b988c890217da33f0b77a83c7dfe833b7243ca4727df0041bac23d4163e635'

# Recompute the complete body and all of its direct call/data references.
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
assert [sum(c.values()) for c in matched['baseline']] == [727, 148]
assert [sum(c.values()) for c in matched['candidate']] == [728, 148]
assert matched['candidate'][0] - matched['baseline'][0] == {'9ca9f019fc3d5d92aaf1efda5f7b5da25be276373bce219b32636b077227723e': 1}
assert not matched['baseline'][0] - matched['candidate'][0]
assert matched['baseline'][1] == matched['candidate'][1]
assert len(static['out']['direct_calls']) == 9 and len(static['out']['typed_references']) == 11
assert [(e['caller']['address'], e['offset']) for e in static['out']['incoming']['original']] == [(0x376b0,568),(0x53350,2344)]

# Diagnostic emit/print builds reproduce the qualified stripped binary. Their
# unstripped outputs intentionally differ from the normal Cargo invocations.
for label, expected in [('baseline', sha(images['baseline']['candidate'])),
                        ('width-only', '443c83c500aa1e86e33aec0acc365a1defb12db9c4142694382cafd46aa0f281'),
                        ('named-result', 'eb1de6df22dfaeb7d0847b491f06fb249492e041bc2ff9ab20ec93f28449910e'),
                        ('candidate', sha(images['candidate']['candidate']))]:
    result = record('compiler/' + label + '/result.json')
    assert result['candidate_sha256'] == expected and result['baseline_stripped_equal']
    assert result['returncode'] == 0 and result['dependencies_unchanged']
assert b'sub nuw i64' in read('compiler/baseline/pass-250.txt')
assert b'sub nuw nsw i128' in read('compiler/candidate/pass-250.txt')
assert b'fi#9: dead' in read('compiler/width-only/pass-356.txt')
assert b'fi#9: size=24, align=8, at location [SP-304]' in read('compiler/candidate/pass-356.txt')

hashes = dict(original=sha(original), **{k: sha(images[k]['candidate']) for k in ('baseline', 'candidate')})
norm = lambda logs: [x for x in logs if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units', x)]
full = record('runtime/full-candidate.json.gz')
baseline = record('runtime/full-baseline.json.gz')
focused = record('runtime/focused.json.gz')
assert len(full['cases']) == len(baseline) == 1011 and not full['mismatches']
assert full['candidate_sha256'] == hashes['candidate'] and full['original_sha256'] == hashes['original']
assert focused['case_count'] == 24 and focused['artifact_sha256'] == hashes
for scope, triples in [('full', [dict(original=a['original'], baseline=b['baseline'], candidate=a['candidate'])
                               for a, b in zip(full['cases'], baseline)]),
                       ('focused', [row['results'] for row in focused['cases']])]:
    observed = record('runtime/' + scope + '-observed.json.gz')
    assert observed['transaction_count'] == observed['signature_count'] == len(triples) * 3
    for transaction in observed['transactions']:
        for program in transaction['loaded_programs'].values():
            if '/evidence/' in program['path']:
                relative = 'evidence/' + program['path'].split('/evidence/', 1)[1]
                assert manifest['repository_inputs'][relative] == program['sha256']
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
    assert (mismatches['baseline'], mismatches['candidate'], len(gains)) == ((82, 78, 4) if scope == 'full' else (6, 2, 4))
    assert observed['script_sha256'] == sha(read('controllers/' + ('full_final.py' if scope == 'full' else 'focused_final.py')))
print('PASS: 727 -> 728 normalized, 148 raw retained; full quote body, 9 calls and 11 references; 1011+24 case triples audited.')
