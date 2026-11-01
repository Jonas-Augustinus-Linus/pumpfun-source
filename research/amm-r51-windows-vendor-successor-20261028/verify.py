"""Authenticate this published measurement recipe without installing or compiling."""
from pathlib import Path, PurePosixPath
import gzip
import hashlib
import json
import tarfile
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def safe(name):
    path = PurePosixPath(name)
    require(name and path.as_posix() == name and not path.is_absolute()
            and '..' not in path.parts and ':' not in name and '\\' not in name,
            'unsafe member: ' + name)
    return name


def verify():
    manifest = read(HERE / 'MANIFEST.json')
    require({p.name for p in HERE.iterdir()} == set(manifest) | {'MANIFEST.json'},
            'packet membership differs')
    for name, record in manifest.items():
        path = HERE / safe(name)
        require(path.is_file() and not path.is_symlink(), 'nonregular packet input')
        data = path.read_bytes()
        require(len(data) == record['bytes'] and sha(data) == record['sha256'],
                'packet input differs: ' + name)
    review = read(HERE / 'ROOT-REVIEW.json')
    workflow = ROOT / safe(review['installed_workflow'])
    require(sha(workflow.read_bytes()) == review['installed_workflow_sha256'],
            'installed workflow differs')
    proposal = (HERE / 'workflow.proposal.yml').read_text()
    require(workflow.read_text() == '\n'.join(proposal.splitlines()[2:]) + '\n',
            'installed workflow differs from reviewed body')
    binding = read(HERE / 'source-binding.json')
    archive = HERE / 'source.tar.gz'
    require(sha(archive.read_bytes()) == binding['sha256'] ==
            'aaaf7ac67b672ca8759a898e6e56af455f72fadf2cf4dd752ecbbe232a7044f0',
            'exact checked-r51 archive differs')
    source = {}
    with tarfile.open(archive) as stream:
        for member in stream.getmembers():
            name = safe(member.name)
            require(member.isfile() and name not in source, 'nonregular/duplicate source')
            source[name] = stream.extractfile(member).read()
    require(len(source) == 69 and {n: sha(b) for n, b in source.items()} == binding['files'],
            'exact source members differ')
    lock = tomllib.loads(source['Cargo.lock'].decode())
    locked = {p['name'] + '-' + p['version']: p['checksum'] for p in lock['package']
              if p.get('source', '').startswith('registry+')}
    acquisition = read(HERE / 'vendor-acquisition.json')
    require(len(locked) == len(acquisition) == 257 and
            {p['name']: p['sha256'] for p in acquisition} == locked,
            'locked package acquisition differs')
    require(len(read(HERE / 'vendor-files.json.gz')) == 8437, 'vendor map differs')
    require(len(read(HERE / 'sdk-components.json.gz')['files']) == 1831,
            'Windows SDK map differs')
    require(len(read(HERE / 'linux-sysroot-inputs.json')['files']) == 26,
            'admitted Linux sysroot map differs')
    pins = read(HERE / 'proposal-pins.json')
    dependency = ROOT / safe(pins['preparer_helper']['path'])
    require(sha(dependency.read_bytes()) == pins['preparer_helper']['sha256'],
            'input preparation helper differs')
    require(pins['native_inputs_manifest'] ==
            '24e416c49991394bda6374439d05d8f004144a6e5c93492fc5541a78c472a36e',
            'reviewed native pin differs')
    print(json.dumps({'status': 'PASS', 'packet_files': len(manifest),
                      'source_inputs': len(source), 'locked_packages': len(locked),
                      'compiler_executions': 0, 'coverage_awarded': 0}))


if __name__ == '__main__':
    verify()
