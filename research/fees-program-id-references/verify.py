"""Verify two Rust-origin program-ID references without weakening the parent proof."""
from pathlib import Path
from functools import lru_cache
import argparse, contextlib, difflib, gzip, hashlib, importlib.util, io, json, re, struct, sys, tarfile
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT = ROOT / 'research/fees-readonly-order-recovery'
VENDOR = 'anchor-attribute-program-0.31.2'
ARCHIVE_SHA = '801aa0c02c94cd3456ed336e1a178d3311f0822c5c4b0f1eb59be4c686accbee'
LABEL = 'id578-program-ids-qualified'

def read(path):
    return path.read_bytes() if path.is_file() else gzip.decompress(path.with_name(path.name + '.gz').read_bytes())

def load(path): return json.loads(read(path))
def sha(data): return hashlib.sha256(data).hexdigest()
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

@lru_cache(maxsize=1)
def parent_state():
    parent = module('program_id_parent', PARENT / 'verify.py')
    with contextlib.redirect_stdout(io.StringIO()): parent.verify()
    ancestor = module('program_id_ancestor', parent.PARENT / 'verify.py')
    p2 = module('program_id_p2', ROOT / 'research/fees-common-quote-data-order/verify.py')
    return parent, p2, parent.recover_sources(ancestor, p2)

def sources():
    _, _, old = parent_state()
    result = dict(old)
    # Keep public static allocation identity at explicit borrows and at the
    # owner comparison. Values still come from the reconstructed IDL modules.
    changed = []
    for name, raw in old.items():
        if not name.endswith('.rs'): continue
        text = raw.decode()
        updated = text.replace('&PUMP)', '&crate::pump::ID)').replace('&AMM)', '&crate::pump_amm::ID)')
        updated = updated.replace('&PUMP,', '&crate::pump::ID,').replace('&AMM,', '&crate::pump_amm::ID,')
        updated = updated.replace('!= &AMM ', '!= &crate::pump_amm::ID ')
        if name.endswith('/create_donation_fee_pda.rs'):
            updated = updated.replace('require_keys_eq!(*info.owner, AMM,', 'require_keys_eq!(*info.owner, crate::pump_amm::ID,')
        if updated != text:
            assert updated.count('\n') == text.count('\n')
            result[name] = updated.encode()
            changed.append(name)
    assert len(changed) == 5
    assert '[patch.crates-io]' not in result['Cargo.toml'].decode()
    result['Cargo.toml'] += b'\n[patch.crates-io]\nanchor-attribute-program = { path = "/work/next637/vendor/used-public" }\n'
    lock = result['Cargo.lock'].decode()
    pattern = r'(\[\[package\]\]\nname = "anchor-attribute-program"\nversion = "0\.31\.2"\n)source = "registry\+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + ARCHIVE_SHA + '"\n'
    lock, count = re.subn(pattern, r'\1', lock)
    assert count == 1
    result['Cargo.lock'] = lock.encode()
    overrides = {n: b for n, b in result.items() if b != old[n]}
    assert set(overrides) == {str(p.relative_to(HERE / 'overrides')) for p in (HERE / 'overrides').rglob('*') if p.is_file()}
    for name, data in overrides.items(): assert read(HERE / 'overrides' / name) == data, name
    patch = ''.join(line for name in sorted(overrides) for line in difflib.unified_diff(
        old[name].decode().splitlines(True), result[name].decode().splitlines(True),
        fromfile='parent/' + name, tofile='recovered/' + name))
    assert patch.encode() == read(HERE / 'source.patch')
    assert {n: sha(b) for n, b in result.items()} == load(HERE / 'source-inputs.json')
    assert len(result) == 46
    return result

def vendor_sources():
    archive = read(HERE / 'provenance' / (VENDOR + '.crate'))
    assert sha(archive) == ARCHIVE_SHA
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        entries = {p.name.split('/', 1)[1]: tar.extractfile(p).read() for p in tar.getmembers() if p.isfile()}
    assert len(entries) == 17
    key = 'src/declare_program/mod.rs'
    before = entries[key]
    needle = b'    quote! {\n        #[doc = #doc]\n        pub static ID: Pubkey = __ID;'
    assert before.count(needle) == 1
    entries[key] = before.replace(needle, needle.replace(b'        #[doc', b'        #[used]\n        #[doc'))
    # Cargo registry bookkeeping is not crate source.
    entries['.cargo-ok'] = read(HERE / 'vendor' / '.cargo-ok')
    assert json.loads(entries['.cargo-ok']) == {'v': 1}
    actual = {str(p.relative_to(HERE / 'vendor')): p.read_bytes() for p in (HERE / 'vendor').rglob('*') if p.is_file()}
    assert actual == entries
    assert {n: sha(b) for n, b in actual.items()} == load(HERE / 'vendor-inputs.json')
    return actual

def verify():
    actual = {str(p.relative_to(HERE)): sha(p.read_bytes()) for p in HERE.rglob('*') if p.is_file() and p != HERE / 'manifest.json'}
    assert not any(p.is_symlink() for p in HERE.rglob('*'))
    assert actual == load(HERE / 'manifest.json')
    for name, digest in load(HERE / 'external-inputs.json').items(): assert sha(read(ROOT / name)) == digest
    assert load(HERE / 'parent.json') == {'path': str(PARENT.relative_to(ROOT)), 'manifest_sha256': sha(read(PARENT / 'manifest.json'))}
    parent, p2, _ = parent_state()
    source = sources()
    vendor = vendor_sources()
    w = module('program_id_windows', ROOT / 'research/fees-composed-frontier188/window_map.py')
    w.m.elf_layout = lru_cache(maxsize=8)(w.m.elf_layout)
    before = read(PARENT / 'builds/candidate/symbols.so')
    candidate = read(HERE / 'builds/candidate/symbols.so')
    stripped = read(HERE / 'builds/candidate/candidate.so')
    original = read(ROOT / 'evidence/original/pump_fees/deployed.so')
    assert candidate == read(HERE / 'builds/repeat/symbols.so')
    assert stripped == read(HERE / 'builds/repeat/candidate.so')
    assert stripped != original and stripped != original[:w.m.elf_layout(original)['elf_extent']]
    assert w.m.elf_layout(stripped)['elf_extent'] == len(stripped)
    old_sections = {s['name']: s for s in w.m.elf_layout(before)['sections'] if s['flags'] & 2 and s['type'] != 8}
    new_sections = {s['name']: s for s in w.m.elf_layout(candidate)['sections'] if s['flags'] & 2 and s['type'] != 8}
    assert old_sections.keys() == new_sections.keys()
    for name in old_sections:
        assert all(old_sections[name][k] == new_sections[name][k] for k in ['address', 'size', 'flags', 'type'])
        assert w.m.section_data(candidate, name) == w.m.section_data(stripped, name)
        if name != '.text': assert w.m.section_data(before, name) == w.m.section_data(candidate, name), name
    expected = bytearray(w.m.section_data(before, '.text'))
    ro_old = next(s for s in w.m.elf_layout(original)['sections'] if s['name'] == '.rodata')
    ro_new = new_sections['.rodata']
    corrections = []
    for address in [73544, 74712]:
        old = w.m.instructions(before, address + 144, 16)[0]
        new = w.m.instructions(candidate, address + 144, 16)[0]
        target = w.m.instructions(original, address + 144, 16)[0]['lddw_value']
        assert old['opcode'] == new['opcode'] == 0x18 and old['destination'] == new['destination'] == 2
        assert old['source'] == new['source'] == old['displacement'] == new['displacement'] == 0
        assert new['lddw_value'] == ro_new['address'] + target - ro_old['address'] == old['lddw_value'] + 32
        assert w.m.at_address(before, old['lddw_value'], 32) == w.m.at_address(candidate, new['lddw_value'], 32)
        struct.pack_into('<I', expected, address + 144 - new_sections['.text']['address'] + 4, new['lddw_value'])
        corrections.append({'function': address, 'offset': 144, 'before_target': old['lddw_value'], 'after_target': new['lddw_value'], 'original_readonly_offset': target - ro_old['address']})
    assert bytes(expected) == w.m.section_data(candidate, '.text')
    assert sum(a != b for a, b in zip(w.m.section_data(before, '.text'), bytes(expected))) == 2
    assert corrections == load(HERE / 'corrections.json')
    assert len(w.m.section_data(candidate, '.rodata')) == 21079
    assert w.m.section_data(candidate, '.rodata') == w.m.section_data(original, '.rodata')
    original_sections = {s['name']: s for s in w.m.elf_layout(original)['sections']}
    original_relocs = dict(w.m.relocations(original))
    references = []
    def same_relative(left, right):
        if ro_old['address'] <= left < ro_old['address'] + ro_old['size']:
            assert ro_new['address'] <= right < ro_new['address'] + ro_new['size']
            assert left - ro_old['address'] == right - ro_new['address']
            references.append((left, right))
    for at, kind in original_relocs.items():
        old_data, new_data = original_sections['.data.rel.ro'], new_sections['.data.rel.ro']
        if kind & 0xffffffff == 8 and old_data['address'] <= at < old_data['address'] + old_data['size']:
            target = at - old_data['address'] + new_data['address']
            same_relative(struct.unpack('<II', w.m.at_address(original, at, 8))[1], struct.unpack('<II', w.m.at_address(candidate, target, 8))[1])
    for pair in w.compare(w.windows(original), w.windows(candidate))['unique_pairs']:
        a, b = pair['original'], pair['candidate']
        for left, right in zip(w.m.instructions(original, a['address'], a['bytes']), w.m.instructions(candidate, b['address'], b['bytes'])):
            if original_relocs.get(a['address'] + left['offset'], 0) & 0xffffffff == 8 and 'lddw_value' in left:
                same_relative(left['lddw_value'], right['lddw_value'])
    assert len(references) == 1608
    old_map = read(PARENT / 'builds/candidate/link.map').decode()
    new_map = read(HERE / 'builds/candidate/link.map').decode()
    layout = read(HERE / 'layout/ordered.ld').decode()
    clean = lambda s: re.sub(r'\S+\("[^"\n]+"\)', '@INPUT_SECTION@', s)
    assert clean(layout) == clean(read(PARENT / 'layout/ordered.ld').decode())
    total = 0
    for name in ['.text', '.rodata', '.data.rel.ro']:
        old_rows, new_rows = [p2.input_sections(m, name) for m in [old_map, new_map]]
        assert [(r['address'], r['size']) for r in old_rows] == [(r['address'], r['size']) for r in new_rows]
        body = re.search(r'  ' + re.escape(name) + r' : \{(.*?)\n  \}', layout, re.S).group(1)
        assert re.findall(r'(\S+)\("([^"\n]+)"\)', body) == [('*' if r['owner'] == '<internal>' else p2.owner(r['owner']), r['section']) for r in new_rows]
        total += len(new_rows)
    assert total == 1474
    for role, suffix in [('candidate', ''), ('repeat', '-repeat')]:
        folder = HERE / 'builds' / role
        launch, result = load(folder / 'launch.json'), load(folder / 'result.json')
        log = read(folder / 'build.log')
        label = LABEL + suffix
        assert result['exit_code'] == 0 and result['source_unchanged'] is True and result['vendor_unchanged'] is True
        assert result['candidate_sha256'] == sha(stripped) and result['symbols_sha256'] == sha(candidate) and result['log_sha256'] == sha(log)
        assert launch['inputs'] == {**{n: sha(b) for n, b in source.items()}, 'ordered.ld': sha(layout.encode()), 'linker.sh': sha(read(folder / 'linker.sh'))}
        assert launch['vendor_inputs'] == {n: sha(b) for n, b in vendor.items()}
        command = launch['command']
        assert command[:2] == ['podman', 'exec'] and '--locked' in command and '--offline' in command
        assert command[command.index('--target') + 1] == 'sbpf-solana-solana'
        assert command[command.index('--manifest-path') + 1] == '/work/next641/' + label + '/programs/pump-fees/Cargo.toml'
        assert 'linker=/work/next641/' + label + '/linker.sh' in command
        assert log.count(b'--crate-name pump_fees_candidate ') == 1 and b'Finished `release`' in log
        assert b'anchor-attribute-program v0.31.2 (/work/next637/vendor/used-public)' in log
        wrapper = read(PARENT / 'builds/candidate/linker.sh').decode().replace('next633', 'next641').replace('data578-qualified', label)
        assert read(folder / 'linker.sh') == wrapper.encode()
    runtime = load(HERE / 'runtime.json')
    prior = module('program_id_runtime', ROOT / 'research/fees-qualified-linker-layout/verify.py')
    prior.check_runtime(runtime, parent.load(PARENT / 'runtime.json'), sha(original), sha(stripped))
    execution = load(HERE / 'runtime-execution.json')
    assert execution['jobs'] == 4 and execution['candidate_sha256'] == sha(stripped)
    assert execution['canonical_runner_sha256'] == sha(read(ROOT / 'scripts/fees_validate_all.py'))
    assert len(execution['suites']) == 18 and runtime['case_count'] == 17331
    for receipt in execution['suites'].values():
        assert receipt['exit_code'] == 0
        assert receipt['script_sha256'] == sha(read(ROOT / 'scripts' / Path(receipt['command'][2]).name))
    return dict(corrected_program_id_references=2, readonly_bytes=21079, relative_readonly_references_equal=1608,
                normalized_functions_preserved=578, raw_local_functions_preserved=198,
                all_allocated_bytes_unchanged_except_two_id_pointer_bytes=True,
                runtime_cases=17331, runtime_suites=18, candidate_sha256=sha(stripped),
                whole_elf_equal=False, whole_capture_equal=False)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialize', type=Path)
    args = parser.parse_args()
    result = verify()
    if args.materialize:
        assert not args.materialize.exists()
        material = {**sources(), 'ordered.ld': read(HERE / 'layout/ordered.ld'), 'linker.sh': read(HERE / 'builds/candidate/linker.sh')}
        material.update({'vendor/' + n: b for n, b in vendor_sources().items()})
        for name, data in material.items():
            dest = args.materialize / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        (args.materialize / 'linker.sh').chmod(0o755)
    print(json.dumps(result, indent=2))
