"""Real offline SDK builds of a generic crate; never execute the resulting image."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE = '599891304e83e853ec723dc1417550bef4e1c074'
FILES = ['scripts/build_supported_sbpf_candidate.py', 'scripts/build_source_manifest.py',
         'scripts/supported_sbpf_policies/v1.53.json']
TOML = ('[package]\nname="declared-directory-probe"\nversion="0.1.0"\nedition="2021"\n'
        '[lib]\nname="declared_directory_probe"\ncrate-type=["cdylib"]\n'
        '[profile.release]\npanic="abort"\noverflow-checks=true\nlto=false\ncodegen-units=1\n[workspace]\n')
SOURCE = ('#![no_std]\ninclude!(concat!(env!("OUT_DIR"),"/generated.rs"));\n'
          '#[no_mangle]pub extern "C" fn entrypoint(_: *const u8)->u64{VALUE}\n'
          '#[panic_handler]fn panic(_: &core::panic::PanicInfo)->!{loop{}}\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(source):
    return {'files': {p.relative_to(source).as_posix(): digest(p.read_bytes())
                      for p in sorted(source.rglob('*')) if p.is_file()},
            'directories': sorted(p.relative_to(source).as_posix()
                                  for p in source.rglob('*') if p.is_dir())}


def reproduce(repo, tools, revision=None):
    sdk = tools/'v1.53/platform-tools'
    stripper = tools/'v1.52/platform-tools/llvm/bin/llvm-objcopy'
    rows = {}
    with tempfile.TemporaryDirectory(prefix='supported-directory-inputs-') as temporary:
        root = Path(temporary).resolve()
        code = root/'code'
        for name in FILES:
            data = (subprocess.check_output(['git', '-C', str(repo), 'show', revision+':'+name])
                    if revision else (repo/name).read_bytes())
            destination = code/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        spec = importlib.util.spec_from_file_location('supported_directory_probe', code/FILES[0])
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        cohort = root/'repo'
        (cohort/'scripts').mkdir(parents=True)
        shutil.copyfile(code/FILES[1], cohort/FILES[1])
        reference = cohort/'evidence/original/pump/deployed.so'
        reference.parent.mkdir(parents=True)
        shutil.copyfile(repo/'evidence/original/pump/deployed.so', reference)
        registry = root/'cargo-home'
        (registry/'registry').mkdir(parents=True)
        env = {'PATH': os.environ['PATH'], 'CARGO_HOME': str(registry)}

        def clean(value):
            return value.replace(str(root), 'OWNED').replace(str(tools), 'SDK_CACHE')

        for label in ('empty_root', 'empty_nested', 'populated', 'file_only',
                      'undeclared', 'changed_after_plan', 'changed_during_compile'):
            source = cohort/label
            (source/'src').mkdir(parents=True)
            relative = 'assets/config/empty' if label in ('empty_nested', 'populated') else 'assets'
            (source/relative).mkdir(parents=True)
            if label in ('populated', 'file_only', 'changed_after_plan', 'changed_during_compile'):
                (source/relative/'value.txt').write_text('control\n')
            (source/'Cargo.toml').write_text(TOML)
            (source/'Cargo.lock').write_text('version=3\n\n[[package]]\nname="declared-directory-probe"\nversion="0.1.0"\n')
            (source/'src/lib.rs').write_text(SOURCE)
            read = ('std::fs::read("assets/value.txt").unwrap().len()' if label == 'file_only' else
                    'std::fs::read_dir('+json.dumps(relative)+').expect("declared input directory").count()')
            mutation = ('std::fs::create_dir_all("assets/generated-empty").unwrap();'
                        if label == 'changed_during_compile' else '')
            (source/'build.rs').write_text('fn main(){let count='+read+';'+mutation+
                'std::fs::write(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("generated.rs"),'
                'format!("pub const VALUE: u64={};\\n",count)).unwrap();}\n')
            out = root/(label+'-adapter')
            arguments = ['--manifest', str(source/'Cargo.toml'), '--program', 'pump', '--artifact-name',
                         'probe.so', '--output', str(out), '--tools-version', 'v1.53']
            if label != 'undeclared':
                arguments += ['--extra-input', str(source/('assets/value.txt' if label == 'file_only' else 'assets'))]
            planned = builder.plan(builder.parser().parse_args(arguments), cohort, env, cache_root=tools)
            if label == 'changed_after_plan':
                (source/'assets/added-empty').mkdir()
            before = snapshot(source)
            # Direct builds use a separate identical source tree, so a build
            # script's deliberate mutation cannot contaminate the caller input.
            control = root/(label+'-control')
            control_source = control/'source'
            shutil.copytree(source, control_source)
            control_env = dict(env, **planned['environment'])
            control_env.update(CARGO_HOME=str(registry), CARGO_TARGET_DIR=str(control/'target'))
            command = [str(sdk/'rust/bin/cargo'), 'build', '--manifest-path', str(control_source/'Cargo.toml'),
                       '--release', '--target', 'sbpf-solana-solana', '--locked', '--offline']
            run = subprocess.run(command, cwd=control_source, env=control_env, capture_output=True, text=True, timeout=90)
            control_hash = None
            if run.returncode == 0:
                compiled = control/'target/sbpf-solana-solana/release/declared_directory_probe.so'
                subprocess.run([str(stripper), '--strip-all', str(compiled), str(control/'candidate.so')],
                               check=True, capture_output=True)
                control_hash = digest((control/'candidate.so').read_bytes())
            status = builder.execute(planned, env)
            attempt = json.loads((out/'build-attempt.json').read_text())
            row = {'direct_returncode': run.returncode, 'direct_candidate_sha256': control_hash,
                   'adapter_returncode': status, 'adapter_stage': attempt['stage'],
                   'adapter_compile_returncode': attempt['compile_returncode'],
                   'source_unchanged': attempt.get('source_unchanged'), 'caller_source_preserved': before == snapshot(source),
                   'source_snapshot': before, 'plan_file_paths': list(planned['source_sha256']),
                   'plan_directories': planned.get('extra_input_directories'),
                   'caller_directories_after': attempt.get('caller_extra_input_directories_after'),
                   'staged_directories_after': attempt.get('extra_input_directories_after'),
                   'staged_requested_directory_exists': (out/'source'/source.relative_to(cohort)/relative).is_dir(),
                   'build_log': clean((out/'build.log').read_text()) if (out/'build.log').exists() else None,
                   'direct_stderr': clean(run.stderr),
                   'error': clean(json.dumps(attempt.get('error'), sort_keys=True)),
                   'comparison_published': (out/'build-comparison.json').exists()}
            if (out/'artifacts/probe.so').exists():
                row['adapter_candidate_sha256'] = digest((out/'artifacts/probe.so').read_bytes())
            rows[label] = row
        result = {'revision': revision or 'working-tree', 'base': BASE,
                  'source_hashes': {name: digest((code/name).read_bytes()) for name in FILES},
                  'tool_hashes': {name: digest((tools/name).read_bytes()) for name in (
                      'v1.53/platform-tools/rust/bin/rustc', 'v1.53/platform-tools/rust/bin/cargo',
                      'v1.52/platform-tools/llvm/bin/llvm-objcopy')},
                  'rustc_version': subprocess.check_output([str(sdk/'rust/bin/rustc'), '--version', '--verbose'], text=True),
                  'cargo_version': subprocess.check_output([str(sdk/'rust/bin/cargo'), '--version'], text=True),
                  'rows': rows,
                  'scope': 'Actual offline generic Cargo builds through the supported plan/execute API. No compiled image, VM, native model or protocol execution. Captured reference bytes are only compared after compilation as this adapter requires; no reconstruction or equivalence claim.'}
    return result


def check(record, expected):
    rows = record['rows']
    for row in rows.values():
        assert row['direct_returncode'] == 0, row
        assert row['caller_source_preserved'], row
    for name in ('populated', 'file_only'):
        row = rows[name]
        assert row['adapter_returncode'] == 0 and row['source_unchanged'] is True, row
        assert row['adapter_candidate_sha256'] == row['direct_candidate_sha256'], row
    undeclared = rows['undeclared']
    assert undeclared['adapter_returncode'] == 101 and not undeclared['comparison_published'], undeclared
    for name in ('empty_root', 'empty_nested'):
        row = rows[name]
        if expected == 'base':
            assert row['adapter_compile_returncode'] == 101 and row['adapter_returncode'] == 1, row
            assert not row['staged_requested_directory_exists'], row
        else:
            assert row['adapter_returncode'] == 0 and row['source_unchanged'] is True, row
            assert row['adapter_candidate_sha256'] == row['direct_candidate_sha256'], row
    for name in ('changed_after_plan', 'changed_during_compile'):
        row = rows[name]
        if expected == 'base':
            assert row['adapter_returncode'] == 0 and row['source_unchanged'] is True, row
        else:
            assert row['adapter_returncode'] == 1 and not row['comparison_published'], row
    if expected == 'fixed':
        assert rows['changed_after_plan']['adapter_compile_returncode'] is None
        assert rows['changed_during_compile']['adapter_compile_returncode'] == 0
        assert rows['changed_during_compile']['source_unchanged'] is False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--tools', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--revision')
    parser.add_argument('--expect', choices=('base', 'fixed'), required=True)
    args = parser.parse_args()
    result = reproduce(args.repo.resolve(), args.tools.resolve(), args.revision)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    check(result, args.expect)
    print(json.dumps({'expected': args.expect, 'cases': len(result['rows']),
                      'adapter_returncodes': {k: v['adapter_returncode'] for k, v in result['rows'].items()}}))
