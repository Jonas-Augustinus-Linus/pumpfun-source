"""Verify a source-to-object raw function match offline, without starting processes."""
import difflib
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as c

HERE = Path(__file__).resolve().parent
ORIGINAL_SHA = '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'
BODY_SHA = 'cd1639db833841b5299e37ae8ba4d5978cc9ee8db1988ebfe8881cd6634c564d'
SDK_SHA = '9e778abd95ff8bdac6eb033d9ff0ef49c7710c9c916e0e28b6f1b626a972fbfd'

def raw(path):
    data = path.read_bytes()
    return gzip.decompress(data) if path.suffix == '.gz' else data

def read(path):
    return json.loads(raw(path))

def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def member(data, suffix):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        entries = [entry for entry in archive.getmembers() if entry.isfile() and entry.name.endswith(suffix)]
        c.require(len(entries) == 1, 'unique source archive member')
        return archive.extractfile(entries[0]).read()

def verify(root=HERE):
    root = Path(root)
    manifest = read(root / 'manifest.json')
    actual = {p.relative_to(root).as_posix(): c.sha(p.read_bytes()) for p in root.rglob('*')
              if p.is_file() and p.name != 'manifest.json' and '__pycache__' not in p.parts}
    c.require(actual == manifest, 'packet manifest')
    original = raw(root / 'inputs/original.so.gz')
    c.require(c.sha(original) == ORIGINAL_SHA, 'original capture identity')
    acquisitions = {row['local']: row for row in read(root / 'input-acquisition.json')}
    for local, path, decompress in [('source.tar.gz', 'inputs/union3-source.tar.gz', False),
                                    ('source-symbols.so.gz', 'inputs/union3-symbols.so.gz', False),
                                    ('reader.py', 'elf_reader.py', False),
                                    ('original.so', 'inputs/original.so.gz', True)]:
        data = raw(root / path) if decompress else (root / path).read_bytes()
        row = acquisitions[local]
        c.require(blob(data) == row['git_blob'] and c.sha(data) == row['sha256'] and len(data) == row['bytes'], 'Git input binding: ' + local)
        c.require(row['revision'] == '8c1a7bf6d94a8aa49b8836dc2c57b6402fef3ad8', 'input revision')
    source = (root / 'sources/baseline.rs').read_bytes()
    suffix = 'crates/native-transfer-fee/src/lib.rs'
    c.require(member((root / 'inputs/union3-source.tar.gz').read_bytes(), suffix) == source, 'union3 source member')
    union4 = (root / 'inputs/union4-source.tar.gz').read_bytes()
    binding = read(root / 'union4-source-binding.json')
    c.require(blob(union4) == 'e69c8ec0dbd9a838e59792be7a66b7297f333c20' and c.sha(union4) == binding['sha256'], 'union4 archive identity')
    c.require(member(union4, suffix) == source, 'union4 source member')
    recovered = (root / 'sources/recovered.rs').read_bytes()
    patch = ''.join(difflib.unified_diff(source.decode().splitlines(True), recovered.decode().splitlines(True),
                    fromfile='a/' + suffix, tofile='b/' + suffix))
    c.require((root / 'source.patch').read_bytes() == patch.encode(), 'source patch binding')
    scope = read(root / 'scope.json')
    c.require(scope['original_address'] == '0xf28b8' and scope['original_bytes'] == 1192
              and scope['original_sha256'] == BODY_SHA and not scope['whole_amm_build']
              and scope['target_executions'] == 0 and not scope['historical_provenance'], 'bounded scope')
    sdk = read(root / 'sdk-components.json.gz')
    c.require(sdk['archive_sha256'] == SDK_SHA and len(sdk['files']) == 1831, 'SDK archive identity')
    compiler_hash = next(row['sha256'] for row in sdk['files'] if row['path'] == 'rust/bin/rustc.exe')
    spec = importlib.util.spec_from_file_location('amm_original_reader', root / 'elf_reader.py')
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    with tempfile.TemporaryDirectory() as directory:
        original_path = Path(directory) / 'original.so'; original_path.write_bytes(original)
        candidate_path = Path(directory) / 'candidate.so'; candidate_path.write_bytes(raw(root / 'inputs/union3-symbols.so.gz'))
        o, linked = reader.Elf(original_path), reader.Elf(candidate_path)
    start = 0xf28b8
    c.require(o.entries[o.entries.index(start) + 1] == 0xf2d60, 'original function boundary')
    reference = original[start:0xf2d60]
    c.require(c.sha(reference) == BODY_SHA and not o.callsites(start, 1192) and not o.pattern(start, 1192), 'original leaf window')
    linked_functions = [f for f in linked.funcs if 'supported_mint_data' in f['name']]
    c.require(len(linked_functions) == 1, 'linked candidate symbol')
    f = linked_functions[0]; linked_body = linked.b[f['start']:f['start'] + f['size']]
    c.require(f['start'] == 0xf7018 and f['size'] == 1168, 'linked baseline extent')
    cases = read(root / 'cases.json')
    c.require(len(cases) == 8 and sum(row['exact'] for row in cases.values()) == 4, 'positive and negative controls')
    objects, results, relocations = {}, {}, {}
    for name, case in cases.items():
        directory = root / 'evidence' / name
        src = raw(directory / 'lib.rs.gz'); launch = read(directory / 'launch.json.gz'); result = read(directory / 'result.json.gz')
        c.require(c.sha(src) == case['source_sha256'] == launch['source_sha256'], 'compiler source binding')
        if case['source']:
            c.require(src == (root / case['source']).read_bytes(), 'published source binding')
        c.require(launch['returncode'] == 0 and launch['target_executions'] == 0 and launch['compiler_sha256'] == compiler_hash, 'compiler identity and success')
        args = launch['command']; template = c.command(args[0], args[4], args[args.index('--out-dir') + 1])
        c.require(args == template and args[0].replace('\\', '/').endswith('/rust/bin/rustc.exe'), 'standard compiler flags')
        c.require(launch['environment']['TEMP'] == launch['environment']['TMP'], 'isolated compiler temp')
        if name.startswith('controller-'):
            c.require(launch['fresh_output'] and launch['sdk_verified_files'] == 1831, 'fresh controller SDK binding')
        obj = raw(directory / 'crate.o.gz'); archive = raw(directory / (c.ARCHIVE + '.gz'))
        c.require(c.sha(obj) == result['object_sha256'] and c.sha(archive) == result['archive_sha256'], 'compiler artifacts')
        c.require(c.archive_members(archive)[result['object_member']] == obj, 'archive object binding')
        functions = c.functions(obj); function = functions[c.SYMBOL]; body = function['data']
        c.require(body == raw(directory / 'supported_mint_data.bin.gz') and c.sha(body) == result['sha256'] and len(body) == result['bytes'], 'function extraction')
        rows, _ = c.sections(obj)
        c.require(not any(row[1] in (4, 9) and row[7] == function['section'] and row[5] for row in rows), 'no scanner relocations')
        c.require(not any(body[i] == 0x85 for i in range(0, len(body), 8)), 'no scanner calls')
        c.require((body == reference) == case['exact'], 'raw original function identity')
        if 'baseline' in name:
            c.require(body == linked_body, 'archived baseline equality')
        objects[name] = functions
        relocations[name] = c.relocation_patterns(obj)
        results[name] = dict(bytes=len(body), sha256=c.sha(body), original_equal=body == reference,
                             unequal_instruction_slots=sum(body[i:i+8] != reference[i:i+8] for i in range(0, max(len(body),len(reference)),8)))
    baseline = objects['baseline']; names = set(baseline) - {c.SYMBOL}
    c.require(len(names) == 3, 'three companion functions')
    for functions in objects.values():
        c.require(set(functions) == set(baseline) and all(functions[name]['data'] == baseline[name]['data'] for name in names), 'unchanged companion functions')
    c.require(all(pattern == relocations['baseline'] for pattern in relocations.values()), 'unchanged relocation targets')
    for left,right in [('initial-readable','initial-repeat'),('controller-recovered','controller-repeat')]:
        for file in ('crate.o.gz', c.ARCHIVE+'.gz'):
            c.require(raw(root/'evidence'/left/file) == raw(root/'evidence'/right/file), 'complete output repeat')
    c.require(results['controller-negative']['bytes'] == 1192 and results['controller-negative']['unequal_instruction_slots'] == 2, 'near-match negative control')
    return dict(cases=results, original_address=hex(start), original_bytes=1192,
                original_sha256=BODY_SHA, unchanged_companion_functions=3,
                whole_amm_build=False, target_executions=0, historical_provenance=False)

if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
