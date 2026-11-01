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
SOURCES = ['programs/pump-amm/src/'+p for p in ['instructions/swap/buy.rs','instructions/swap/mod.rs','instructions/swap/sell.rs','sweep.rs']]


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
assert [p for p in before if before[p] != after[p]] == SOURCES
patch = ''
for source in SOURCES:
    assert after[source] == read('proposed/' + source.removeprefix('programs/pump-amm/src/'))
    patch += ''.join(difflib.unified_diff(before[source].decode().splitlines(True), after[source].decode().splitlines(True), fromfile='a/'+source, tofile='b/'+source))
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
assert sha(images['baseline']['candidate']) == '37f3fdbace558971111418e34d539c0786724e9288dfec5f17e18e5452a3a497'

static = runpy.run_path(str(HERE / 'analyze.py'))
w = static['w']; original = static['blobs']['original']; originals = w.windows(original)
assert sha(original) == '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
assert len(originals) == 785
matched = {}
for label in ['baseline','candidate']:
    fs = w.windows(images[label]['symbols'])
    matched[label] = [Counter(f[key] for f in originals) & Counter(f[key] for f in fs) for key in ['signature','raw_sha256']]
assert [sum(c.values()) for c in matched['baseline']] == [728,148]
assert [sum(c.values()) for c in matched['candidate']] == [729,148]
body = static['out']['original']
assert body['address'] == 0x58e08 and body['bytes'] == 1536 and body['instructions'] == 185
assert matched['candidate'][0] - matched['baseline'][0] == {body['signature']:1}
assert not matched['baseline'][0] - matched['candidate'][0]
assert matched['baseline'][1] == matched['candidate'][1]
assert len(static['out']['direct_calls']) == 13 and len(static['out']['typed_references']) == 7
assert {e['caller']['address'] for e in static['out']['incoming']['original']} == {0x376b0,0x3a5a0,0x49b50,0x59408}
assert len(static['out']['incoming']['candidate']) == 4
for label in ['baseline','candidate']:
    result = record('compiler/'+label+'/result.json')
    assert result['candidate_sha256'] == sha(images[label]['candidate'])
    assert result['returncode'] == 0 and result['baseline_stripped_equal'] and result['dependencies_unchanged']
assert b'i1 noundef zeroext %is_mayhem_mode' in read('compiler/baseline/pass-1.txt')
assert b'i8 noundef %is_mayhem_mode' in read('compiler/candidate/pass-1.txt')
hashes = dict(original=sha(original), **{k:sha(images[k]['candidate']) for k in ['baseline','candidate']})
norm = lambda logs:[s for s in logs if not re.fullmatch(r'Program \S+ consumed \d+ of \d+ compute units',s)]

def audit(scope, triples, observed, expected_count, log_counts):
    assert observed['transaction_count'] == observed['signature_count'] == expected_count*3
    expected = Counter(); actual = Counter(); mismatches = Counter(); gains=losses=count=0
    for tx in observed['transactions']:
        assert tx['all_signatures_verified']
        actual[(tx['amm_program_sha256'],tx['transaction_base64'],tx['logs_sha256'])] += 1
        for program in tx['loaded_programs'].values():
            if '/evidence/' in program['path']:
                name = 'evidence/' + program['path'].split('/evidence/',1)[1]
                assert manifest['repository_inputs'][name] == program['sha256']
    for triple in triples:
        o=triple['original']; count+=1
        for label,result in triple.items():
            assert {k:v for k,v in o.items() if k!='logs'} == {k:v for k,v in result.items() if k!='logs'}, (scope,count,label)
            expected[(hashes[label],result['transaction_base64'],sha(json.dumps(result['logs'],separators=(',',':')).encode()))] += 1
            mismatches[label] += norm(o['logs']) != norm(result['logs'])
        x,y=(norm(o['logs']) == norm(triple[k]['logs']) for k in ['baseline','candidate'])
        gains += not x and y; losses += x and not y
    assert count == expected_count and expected == actual and losses == 0
    assert (mismatches['baseline'],mismatches['candidate']) == log_counts
    assert gains == log_counts[0]-log_counts[1]
    print(scope,count,'case triples, non-compute log mismatches',log_counts)

for family,count,counts in [('buy',1011,(78,76)),('sell',575,(89,88)),('sweep',254,(23,16))]:
    summary=record('runtime/'+family+'/summary.json')
    assert summary['artifact_sha256']==hashes and not any(summary['functional_mismatches'].values())
    observed=record('runtime/'+family+'/observed.json.gz')
    assert observed['script_sha256']==sha(read('controllers/recipient_runtime.py'))
    with gzip.open(HERE/'runtime'/family/'triples.jsonl.gz','rt') as f:
        audit(family,(json.loads(line)['results'] for line in f),observed,count,counts)
focus=record('runtime/focused.json.gz'); assert focus['artifact_sha256']==hashes and focus['fresh_vm']
observed=record('runtime/focused-observed.json.gz'); assert observed['script_sha256']==sha(read('controllers/recipient_focused.py'))
audit('focused',(r['results'] for r in focus['cases']),observed,80,(8,0))
print('PASS: 728 ->729 normalized,148 raw retained;1536B validator,13 direct calls,7 typed references;1840+80 case triples audited.')
