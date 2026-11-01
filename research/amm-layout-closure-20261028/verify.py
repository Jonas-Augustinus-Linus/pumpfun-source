#!/usr/bin/env python3
"""Bind maintained source, two actual builds, literal ELF closure and fresh replay."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile

P = Path(__file__).resolve().parent
ROOT = P.parents[1]
CANDIDATE = '86dbc2c64e81988dead173039b61fa01ba5f68a00fbb6f6dd49f2cda0afec37f'
SYMBOLS = '7271aaf8afe13b6c8f13a6cf0e9534896a66650dda13a2aa1b32e41edd46426d'
PARENT = 'd05b92a344e1e095e6f68276eb50ddc64a36a0792ac20cb0e7c31c6f6f384489'
HARNESS = {
    'build.py': '7b4972fb618c27c1d306526d570d11c4f8f30b5b2fdbb885879bc9c47cd90abf',
    'workspace_recipe.py': '66108c658683bc82437323d0fbefb4ba4921dd66ec79c00ec64c3cfd19498656',
    'rustc_wrapper.py': 'bf904c11ec37ea0882c6e93b9c4835e4ea73a3d9d1c2cfb81500995a26455a32',
    'linker_wrapper.py': '6c191c34a706582683c64298c50938983b6878877405ca9722024698f68aa88f',
    'ordered.ld': 'b8a3588949d5721fb3c8ba42c68d3ae23d502dda0bed1d6cb37ce8e8f9ae1633',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def raw(path):
    path = Path(path)
    if not path.exists():
        path = path.with_name(path.name+'.gz')
    data = path.read_bytes()
    return gzip.decompress(data) if path.suffix == '.gz' else data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def doc(path):
    return json.loads(raw(path))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def archive(path):
    result = {}
    with tarfile.open(path) as source:
        for item in source:
            name = Path(item.name)
            require(item.isfile() and not name.is_absolute() and '..' not in name.parts and item.name not in result, 'Unsafe source archive')
            result[item.name] = source.extractfile(item).read()
    return result


def inventory(packet=P):
    paths = [p for p in packet.rglob('*') if '__pycache__' not in p.parts]
    require(not any(p.is_symlink() for p in paths), 'Packet symlink')
    return {p.relative_to(packet).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
            for p in paths if p.is_file() and p != packet/'manifest.json'}


def derivation(repo, parent):
    baseline = parent/'results/build-a/candidate.so'
    old = module('layout_original_reader', parent/'tools/elf_reader.py').Elf(repo/'evidence/original/pump_amm/deployed.so')
    image = baseline.read_bytes()
    sections = doc(P/'results/derivation/input-sections.json.gz')
    text = {r['address']: r for r in sections if r['section'].startswith('.text')}
    assignment = {int(k, 16): int(v, 16) for k, v in doc(parent/'results/r31-physical-closure-audit.json')['assignment'].items()}
    assignment[0x4c750] = 0x4c4e8
    require(len(text) == len(assignment) == 785 and set(assignment.values()) == set(text), 'Incomplete physical text assignment')
    data = sorted((r for r in doc(P/'results/derivation/data-section-proposal.json.gz') if r['section'].startswith('.rodata')), key=lambda r:r['expected'])
    require(len(data) == 772, 'Incomplete data section order')
    for row in data:
        a, z, target = row['address'], row['address']+row['size'], row['expected']
        require(target % row['align'] == 0 and image[a:z] == old.b[target:target+row['size']], 'Source data payload differs')
    def selector(row):
        obj = row['object'].rsplit('/', 1)[-1].replace('(', ':').removesuffix(')')
        require('"' not in row['section'] and not any(c.isspace() for c in obj), 'Unsafe section selector')
        return '    '+('*' if obj == '<internal>' else '*'+obj)+'("'+row['section']+'")'
    default = raw(P/'default.ld').decode()
    require(sha(default.encode()) == '5e8370b9380f55411d827721e2e43c8cfd1eac71d1383e20b938397bc0bd82c3', 'Default SDK recipe changed')
    expected = default.replace('.text : { *(.text*) } :text', '.text : {\n'+'\n'.join(selector(text[c]) for o,c in sorted(assignment.items()))+'\n    *(.text*)\n  } :text')
    expected = expected.replace('.rodata : { *(.rodata*) } :rodata', '.rodata : {\n'+'\n'.join(map(selector,data))+'\n    *(.rodata*)\n  } :rodata')
    require(expected.encode() == (P/'ordered.ld').read_bytes(), 'Linker recipe changes more than recorded section ordering')
    return {'text_sections': 785, 'rodata_sections': 772, 'source_or_object_bytes_modified': False}


def verify(repo=ROOT, runtime=None, signatures=False, source_root=None):
    repo = Path(repo).resolve()
    require(doc(P/'manifest.json') == inventory(P), 'Layout qualification inventory changed')
    for name, digest in HARNESS.items():
        require(sha((P/name).read_bytes()) == digest, 'Executed build controller changed: '+name)
    parent = repo/'repro/pump_amm/canonical-frontier-20261028'
    require(sha((parent/'MANIFEST.json').read_bytes()) == PARENT, 'Parent packet changed')
    prior = module('archived_canonical_amm', parent/'verify.py').verify(repo, signatures=signatures, current_source=False)
    require(prior['candidate_sha256'] == '15aadc37c6a4fb2148895eafa22a969f7ad28a363c8972a8fe526a015fa85d21', 'Parent image changed')
    recipe = module('layout_current_source_recipe', P/'workspace_recipe.py')
    canonical = archive(P/'results/build-a/canonical-source.tar.gz')
    previous = archive(parent/'results/build-a/canonical-source.tar.gz')
    name = 'programs/pump-amm/src/instructions/swap/sell.rs'
    require(set(canonical) == set(previous) and [n for n in canonical if canonical[n] != previous[n]] == [name], 'Unreviewed source difference')
    require(previous[name].replace(b'Account::<UserVolumeAccumulator>::try_from_unchecked(', b'Account::<UserVolumeAccumulator>::try_from(') == canonical[name], 'Checked constructor source differs')
    current = Path(source_root).resolve() if source_root is not None else repo
    require(recipe.source_inputs(current) == canonical, 'Maintained source differs from actual compiler inputs')
    _, workspace = recipe.expected_workspace(current)
    canonical_hashes = {n: sha(b) for n,b in canonical.items()}
    workspace_hashes = {n: sha(b) for n,b in workspace.items()}
    require(len(canonical) == 68 and len(workspace) == 69, 'Source input census differs')
    sdks = []
    for label, cold in (('build-a', False), ('build-b', True)):
        base = P/'results'/label
        record = doc(base/'build-record.json')
        require(record['returncode'] == 0 and record['clean_all'] is cold, 'Actual build scope differs')
        require(record['canonical_sha256'] == canonical_hashes, 'Compiler source binding differs')
        require(record['source_sha256'] == record['source_after_sha256'] == workspace_hashes, 'Compiled workspace differs')
        require(archive(base/'canonical-source.tar.gz') == canonical, 'Actual source archive differs')
        binding = doc(base/'source-binding.json')
        require(binding['input_sha256'] == canonical_hashes and binding['workspace_sha256'] == workspace_hashes and binding['rust_transformations'] == 0, 'Mapper transformation differs')
        require(record['candidate_sha256'] == sha((base/'candidate.so').read_bytes()) == CANDIDATE, 'Actual compiler output differs')
        require(record['symbols_sha256'] == sha((base/'symbols.so').read_bytes()) == SYMBOLS, 'Actual symbol output differs')
        require(record['harness_sha256'] == record['harness_after_sha256'] == HARNESS, 'Build controller changed during execution')
        require(all(sha((base/'harness'/n).read_bytes()) == h for n,h in HARNESS.items()), 'Executed controller snapshot differs')
        require(all(record[k] is True for k in ('source_unchanged','dependency_inputs_unchanged','sdk_unchanged')), 'Actual input drift')
        require(record['registry_packages'] == 257 and record['archive_files'] == 8180, 'Registry input census differs')
        log = raw(base/'build.log')
        require(b'--crate-name pump_amm_recovered ' in log and b'Compiling pump-amm-recovered' in log, 'Fresh root source compilation missing')
        require(log.count(b'overwrites values in the frame') == 3, 'Retained backend diagnostic census differs')
        if cold:
            cleanup = doc(base/'target-clean.json')
            require(cleanup['empty_before_compilation'] is True and cleanup['remaining_entries'] == [] and b'Fresh ' not in log, 'Cold dependency build reused an artifact')
        compiler = doc(base/'root-rustc-invocation.json')
        require(compiler['effective_arguments'] == compiler['original_arguments']+['-C','linker=/out/linker_wrapper.py'], 'Compiler code-generation arguments modified')
        linker = doc(base/'linker-invocation.json')
        arguments = list(linker['original_arguments'])
        require(arguments.count('--script') == 1, 'Unexpected built-in script selection')
        arguments[arguments.index('--script')+1] = '/out/ordered.ld'
        arguments += ['--Map=/out/link.map', '--reproduce=/out/link.tar']
        require(linker['effective_arguments'] == arguments and linker['object_bytes_changed'] is False, 'Unreviewed linker argument or object change')
        require(linker['ordered_script_sha256'] == HARNESS['ordered.ld'], 'Actual linker script differs')
        sdks.append(doc(base/'sdk-sha256.json'))
    require(sdks[0] == sdks[1], 'Independent builds used different SDK bytes')
    layout = derivation(repo, parent)
    literal = module('layout_literal_elf_audit', P/'audit_elf.py').audit(repo, P/'results/build-a/candidate.so', P/'results/build-a/symbols.so')
    require(literal == doc(P/'results/literal-elf-audit.json'), 'Saved literal comparison differs')
    audit = module('layout_runtime_audit', P/'audit_runtime.py')
    require(sha((P/'audit_runtime.py').read_bytes()) == sha((parent/'audit_runtime.py').read_bytes()), 'Runtime comparison policy changed')
    replay = audit.audit(Path(runtime) if runtime else P/'results/runtime', CANDIDATE, signatures=signatures)
    loader = module('layout_loader_audit', parent/'verify_loader.py').verify(P, repo/'evidence/original/pump_amm/deployed.so', P/'results/build-a/candidate.so', signatures=signatures)
    return {'status':'PASS', 'program':'pump_amm', 'candidate_sha256':CANDIDATE, 'symbols_sha256':SYMBOLS,
        'canonical_inputs':68, 'workspace_inputs':69, 'current_source_verified':True,
        'independent_source_builds':2, 'cold_dependency_build':True, 'normalized':784, 'raw':784,
        'layout_recipe':layout, 'literal_elf':literal, 'loader_controls':loader,
        'retained_backend_frame_diagnostics_per_build':3, 'broad_frame_safety_claimed':False,
        'whole_elf_identical':False, 'goal_complete':False, **replay}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--signatures', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.repo, args.runtime, args.signatures, args.source_root), indent=2))
