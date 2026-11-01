"""Recompute the paired build's saved evidence without running any binary."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tomllib
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analysis
import run as controller

ORIGINAL = 'evidence/original/pump_fees/deployed.so'
ORIGINAL_SHA = '4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def load_run(folder):
    run, artifacts = read(folder/'run.json'), read(folder/'artifacts.json')['artifacts']
    require(run['status'] == 'completed', 'Run is not terminal')
    require(len(artifacts) == 1, 'Unexpected artifact count')
    artifact, = artifacts
    archive = (folder/(str(artifact['id'])+'.zip')).read_bytes()
    require(artifact['digest'] == 'sha256:'+sha(archive), 'Provider artifact digest differs')
    files = {}; members = []
    with zipfile.ZipFile(io.BytesIO(archive)) as stream:
        for info in stream.infolist():
            name = PurePosixPath(info.filename)
            require(not name.is_absolute() and '..' not in name.parts and '\\' not in info.filename
                    and not info.is_dir() and info.file_size < 100_000_000 and info.filename not in files,
                    'Invalid artifact member')
            raw = stream.read(info); files[info.filename] = raw
            members.append(dict(path=info.filename, bytes=len(raw), sha256=sha(raw)))
    require(members == read(folder/'artifact-members.json'), 'Artifact membership differs')
    require(files['source-commit.txt'].decode().strip() == run['head_sha'], 'Controller revision differs')
    for name in files:
        if name.endswith('-commands.json'):
            for row in json.loads(files[name]):
                for stream in ('stdout', 'stderr'):
                    receipt = row[stream]; raw = files[receipt['file']]
                    require(len(raw) == receipt['bytes'] and sha(raw) == receipt['sha256'], 'Command log differs')
    return run, files


def validate_success(files, policy):
    obj = lambda name: json.loads(files[name])
    obs = obj('observation.json')
    require(obs['status'] == 'COMPLETED', 'Paired build did not finish')
    require(obs['program_executions'] == 0 and obs['target_inputs_mounted'] is False, 'Experiment scope differs')
    source = controller.source_members()
    baseline_inputs = {k: sha(v) for k,v in source.items()}
    split_source = dict(source)
    split_source[controller.SOURCE_FILE] = controller.split_guard(source[controller.SOURCE_FILE])
    split_inputs = {k: sha(v) for k,v in split_source.items()}
    require(obs['source_changed_files'] == [controller.SOURCE_FILE], 'Source delta differs')
    for phase, expected in [('fetch',baseline_inputs),('baseline',baseline_inputs),('split',split_inputs)]:
        for when in ('before','after'):
            require(obj(phase+'-source-'+when+'.json') == expected, 'Source state differs')
    require(files['split-types.rs'] == split_source[controller.SOURCE_FILE], 'Split source differs')
    require(obj('split-source-inputs.json') == split_inputs, 'Split source manifest differs')
    for phase in ('baseline','split'):
        require(analysis.identity(files[phase+'.stripped.so']) == obs[phase], 'Output digest differs')
    require(obs['baseline'] == policy['baseline'], 'Baseline does not reproduce PR73')
    require(obs['split_raw_equals_baseline'] == (files['baseline.stripped.so'] == files['split.stripped.so']),
            'Raw equality claim differs')
    argv = obj('baseline-rustc-argv.json')
    require(argv == obj('split-rustc-argv.json') and obs['identical_root_compiler_arguments'], 'Compiler arguments differ')
    require(argv[argv.index('--crate-name')+1] == 'pump_fees_candidate', 'Wrong root crate')
    require(argv[argv.index('--target')+1] == 'sbf-solana-solana', 'Wrong root target')
    require('-Zremap-cwd-prefix=' in argv, 'Remap option missing')
    host = {r['label']: r for r in obj('host-commands.json')}
    for phase in ('baseline','split'):
        docker = host['container-'+phase]['argv']
        require(docker[docker.index('--network')+1] == 'none', 'Compilation network not disabled')
        require('--read-only' in docker and docker[docker.index('--cap-drop')+1] == 'ALL', 'Isolation differs')
        require(docker[docker.index('--security-opt')+1] == 'no-new-privileges', 'Privilege setting differs')
        require('--user' in docker, 'File owner mapping absent')
        rows = obj(phase+'-commands.json')
        build = next(r for r in rows if r['label'] == phase+'-build')
        # Recreate the Linux recipe even when this read-only verifier runs on Windows.
        with patch.object(controller, 'Path', PurePosixPath):
            expected_environment = controller.environment(phase)
        require(build['environment'] == expected_environment, 'Build environment differs')
        require('--offline' in build['argv'] and '--locked' in build['argv'], 'Locked offline build options absent')
    for name in ('host','fetch','baseline','split'):
        require(all(r['exit'] == 0 for r in obj(name+'-commands.json')), 'Successful run contains failed command')
    registry = obj('registry-before.json')
    require(len(registry) == obs['registry_archives_verified'], 'Registry count differs')
    locked = {(p['name'],p['version']):p['checksum'] for p in tomllib.loads(source['Cargo.lock'].decode())['package']
              if p.get('source','').startswith('registry+')}
    require(len(registry) == len(locked) and {(p['name'],p['version']):p['sha256'] for p in registry} == locked,
            'Recorded registry archives differ from Cargo.lock')
    tools = obj('tool-identities.json')
    for path, digest in policy['compile']['selected_sha256'].items():
        require(tools['v1.44/'+path]['sha256'] == digest, 'Recorded compiler identity differs')
    require(tools['v1.52/llvm/bin/llvm-objcopy']['sha256'] == policy['strip']['objcopy_sha256'],
            'Recorded stripper identity differs')
    for name in ('run.py','rustc-wrapper.py','test_inputs.py','policy.json','source-inputs.json','proposal.patch','source.tar.gz','LICENSE'):
        require(files[name] == (HERE/name).read_bytes(), 'Published controller differs from executed controller: '+name)


def validate_references(files):
    refs = read(HERE/'references.json')
    require(refs['commit'] == '5f8f2aef2a70e43642e65e10d1db3e7476a533d6' and refs['pr'] == 75,
            'PR75 reference revision differs')
    for row in refs['files']:
        raw = (HERE/row['retained_path']).read_bytes()
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'PR75 retained file differs')
        require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == row['git_blob'],
                'PR75 Git blob identity differs')
    folder = HERE/'references/pr75'
    experiment = read(folder/'experiment.json')
    result = {}
    for phase in ('baseline','split'):
        variant = experiment['variants'][phase]
        expected = json.loads(files['source-inputs.json' if phase == 'baseline' else 'split-source-inputs.json'])
        require(variant['input_sha256'] == expected, 'PR75 source set differs')
        for kind, suffix in [('candidate','stripped'),('symbols','unstripped')]:
            prior = gzip.decompress((folder/variant['files'][kind]['path']).read_bytes())
            current = files[phase+'.'+suffix+'.so']
            require(analysis.identity(prior) == {k:variant['files'][kind][k] for k in ('bytes','sha256')},
                    'PR75 artifact descriptor differs')
            result[phase+'_'+suffix] = dict(raw_equal=current == prior, **analysis.identity(current))
            require(current == prior, 'Fresh output differs from PR75 raw bytes')
    require(files['split-types.rs'] == (folder/'sources/split-types.rs').read_bytes(), 'PR75 split source differs')
    require(result == read(HERE/'reference-comparison.json'), 'Cross-run comparison differs')
    return result


def verify(root):
    manifest = read(HERE/'manifest.json')
    actual = {p.relative_to(HERE).as_posix(): sha(p.read_bytes()) for p in HERE.rglob('*')
              if p.is_file() and p != HERE/'manifest.json' and '__pycache__' not in p.parts}
    require(actual == manifest, 'Packet membership or digest differs')
    receipts = read(HERE/'runs.json')
    success = None
    for receipt in receipts:
        run, files = load_run(HERE/'runs'/str(receipt['id']))
        require(run['id'] == receipt['id'] and run['head_sha'] == receipt['head'], 'Run identity differs')
        require(run['conclusion'] == receipt['conclusion'], 'Run conclusion differs')
        if run['conclusion'] == 'success':
            require(success is None, 'Multiple successes')
            success = files
        else:
            observation = json.loads(files['observation.json'])
            require(observation['status'] == 'FAILED' and observation['error'] == receipt['error'], 'Failure evidence differs')
            require(not any(n.endswith('.so') for n in files), 'Pre-compilation failure has output')
    require(success is not None, 'Missing successful build')
    validate_success(success, read(HERE/'policy.json'))
    validate_references(success)
    original = (root/ORIGINAL).read_bytes()
    require(sha(original) == ORIGINAL_SHA, 'Original capture differs')
    result = analysis.analyze(*(success[name] for name in ('baseline.unstripped.so','baseline.stripped.so',
                    'split.unstripped.so','split.stripped.so')), original)
    require(result == read(HERE/'analysis.json'), 'Recomputed raw analysis differs')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-root', type=Path, default=HERE.parents[1])
    args = parser.parse_args()
    result = verify(args.repository_root)
    print(json.dumps({'status':'PASS','raw_stripped':result['full_stripped_comparison'],
                      'helper':result['helper_raw_comparison']},indent=2))
