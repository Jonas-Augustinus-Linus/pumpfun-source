#!/usr/bin/env python3
"""Recompute the callee-identity check for the Fees first-account attribution.

Independently re-derives PR #74 (research/fees-account-parser) callee claims with
the corrected local-CALL encoding from repro/pump_fees/first-account-boundary-admission:
target_vaddr = call_vaddr + 8 + 8 * signed_imm32 (Anza sbpf elf.rs PC-relative fixup,
ebpf.rs INSN_SIZE=8). Reads only the three pinned ELF inputs; no REA session needed
for the arithmetic, every input byte is hashed against the pins below.

Review correction: #42's candidate receipts were read from the Linux build
(fees-current-linux-v144.so), whose wrappers are at 82232/82800/83184, not at the
selected candidate's 83152/83352/83552. The checks below locate the wrappers in
both builds instead of carrying one build's labels into the other.
"""
import hashlib
import json
import argparse
import struct
import sys
from pathlib import Path

PARENT = Path(__file__).resolve().parent
ROOT = PARENT.parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze import elf_layout  # noqa: E402

ORIG = ROOT / 'evidence/original/pump_fees/deployed.so'
CAND = ROOT / 'repro/pump_fees/sharing-authorize-main-v144/main/candidate.so'
LCS = ROOT / 'repro/pump_fees/linux-current-source-build/fees-current-linux-v144.so'

ORIG_SHA = '4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
CAND_SHA = '2387f8139a13918a5c9c523f140ecdd72db7243c8e2ed9cd7e1ff9d42ad6c8af'
LCS_SHA = '6c44d9f2ffe9b18c79a6344b256d8acd7a34c10e77b894c51f46512a447b8ce6'
DISCRIMINATOR = bytes.fromhex('8f3492bbdb7b4c9b')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def text_section(image):
    return next(s for s in elf_layout(image)['sections'] if s['name'] == '.text')


def vread(image, section, vaddr, nbytes):
    off = section['offset'] + vaddr - section['address']
    return image[off:off + nbytes]


def resolve_call(image, section, call_vaddr):
    insn = vread(image, section, call_vaddr, 8)
    if insn[:4] != bytes([0x85, 0x10, 0, 0]):
        raise AssertionError(f'not a src=1 local CALL at {call_vaddr:#x}: {insn.hex()}')
    return call_vaddr + 8 + 8 * struct.unpack('<i', insn[4:])[0]


def lddw_payloads(image, section, start, size):
    """(vaddr, imm64) for every lddw in [start, start+size)."""
    out = []
    v = start
    while v < start + size:
        insn = vread(image, section, v, 16)
        if insn[0] == 0x18:
            imm = int.from_bytes(insn[4:8], 'little') | (int.from_bytes(insn[12:20], 'little') << 32)
            out.append((v, imm))
            v += 16
        else:
            v += 8
    return out


def masked_window(image, section, start, size):
    """Instruction bytes with only src=1 local CALL immediates zeroed."""
    raw = bytearray(vread(image, section, start, size))
    v = 0
    while v < size:
        if raw[v] == 0x85 and raw[v + 1] >> 4 == 1:
            raw[v + 4:v + 8] = bytes(4)
        v += 16 if raw[v] == 0x18 else 8
    return bytes(raw)


def wrapper_matches(image, section, reference):
    """Every 8-byte-aligned 200-byte .text window equal to `reference` after CALL masking."""
    text = vread(image, section, section['address'], section['size'])
    first, hits, i = reference[:8], [], text.find(reference[:8])
    while i != -1:
        if i % 8 == 0 and masked_window(image, section, section['address'] + i, 200) == reference:
            hits.append(section['address'] + i)
        i = text.find(first, i + 1)
    return hits


def main():
    orig, cand, lcs = ORIG.read_bytes(), CAND.read_bytes(), LCS.read_bytes()
    assert sha(orig) == ORIG_SHA, 'original deployed.so pin'
    assert sha(cand) == CAND_SHA, 'candidate.so pin'
    assert sha(lcs) == LCS_SHA, 'linux-current-source candidate pin'

    ot, ct, lt = text_section(orig), text_section(cand), text_section(lcs)

    # 1. Query first CALLs (PR74 numbers, corrected encoding).
    assert resolve_call(orig, ot, 519024) == 71256, 'original query first CALL'
    assert resolve_call(cand, ct, 127384) == 83552, 'candidate query first CALL'

    # 2. Candidate wrapper helper CALLs (corrected encoding: helper CALL sits one
    #    instruction before the wrapper's jne block; PR74's wrapper numbering is kept).
    assert resolve_call(cand, ct, 83208) == 706160   # wrapper A error path: Error::from
    assert resolve_call(cand, ct, 83336) == 35856    # wrapper A helper
    assert resolve_call(cand, ct, 83408) == 706160   # wrapper B error path: Error::from
    assert resolve_call(cand, ct, 83536) == 30752    # wrapper B helper
    assert resolve_call(cand, ct, 83608) == 706160   # wrapper C error path: Error::from
    assert resolve_call(cand, ct, 83736) == 26680    # wrapper C helper

    # 3. Original wrapper: helper CALL at 71440 -> 36,072.
    assert resolve_call(orig, ot, 71440) == 36072

    # 4. FeeConfig discriminator via lddw immediates.
    o_payloads = {v: imm for v, imm in lddw_payloads(orig, ot, 36072, 1248)}
    c_payloads = {v: imm for v, imm in lddw_payloads(cand, ct, 26680, 1144)}
    a_payloads = {v: imm for v, imm in lddw_payloads(cand, ct, 35856, 1024)}
    b_payloads = {v: imm for v, imm in lddw_payloads(cand, ct, 30752, 1024)}
    lit = int.from_bytes(DISCRIMINATOR, 'little')
    assert any(imm == lit for imm in o_payloads.values()), 'original helper carries FeeConfig discriminator'
    assert any(imm == lit for imm in c_payloads.values()), 'candidate C helper carries FeeConfig discriminator'
    assert not any(imm == lit for imm in a_payloads.values()), 'candidate A helper lacks it'
    assert not any(imm == lit for imm in b_payloads.values()), 'candidate B helper lacks it'
    orig_site = next(v for v, imm in o_payloads.items() if imm == lit)
    c_site = next(v for v, imm in c_payloads.items() if imm == lit)
    assert orig_site == 36696, f'original literal site {orig_site}'
    assert c_site == 27320, f'candidate C literal site {c_site}'

    # 5. Wrapper identity in both builds (review correction). In the selected
    #    candidate the three wrappers equal the original after masking only CALL
    #    immediates; in the Linux build the equal windows are elsewhere.
    # pass 36's retained parser windows (raw hashes in repro/layered-passes/pass-36)
    # come from the original and the selected candidate, not from the Linux build.
    pass36 = '492ae4b35541047f2b4f85e7cd49182ebcffdde0aa5d46e90decd3b5b99d97cc'
    assert sha(orig[518976:520760]) == '03dd46919605eee4acfa8e67cccb342589f63c8ad019dcc7e20380a3658ebd9b'
    assert sha(cand[127336:129120]) == pass36 != sha(lcs[127336:129120]), 'pass-36 window owner'
    reference = masked_window(orig, ot, 71256, 200)
    assert wrapper_matches(cand, ct, reference) == [83152, 83352, 83552], 'selected wrappers'
    linux_wrappers = wrapper_matches(lcs, lt, reference)
    assert linux_wrappers == [82232, 82800, 83184], f'Linux wrappers {linux_wrappers}'
    assert resolve_call(lcs, lt, 127384) == 82232, 'Linux query first CALL'
    linux_helpers = {w: resolve_call(lcs, lt, w + 184) for w in linux_wrappers}
    assert linux_helpers == {82232: 28728, 82800: 35856, 83184: 33840}, linux_helpers
    # Helper extents (1144/1024/1024) are the symbol sizes of the identical Linux build.
    linux_sites = {h: [v for v, imm in lddw_payloads(lcs, lt, h, size) if imm == lit]
                   for h, size in ((28728, 1144), (35856, 1024), (33840, 1024))}
    assert linux_sites == {28728: [29368], 35856: [], 33840: []}, linux_sites

    # 6. #42's Linux-build sites are CALL/exit pairs, not wrapper entries; the two
    #    corrected store-immediate readings lie outside every Linux-build wrapper.
    for site in (83168, 83368, 83552):
        resolve_call(lcs, lt, site)
        assert vread(lcs, lt, site + 8, 8) == bytes([0x95]) + bytes(7), f'exit after {site}'
    assert 83184 in linux_wrappers
    for start in (83384, 83568):
        assert masked_window(lcs, lt, start, 200) != reference, f'{start} is not a wrapper'
    b_store = vread(lcs, lt, 83480, 8)
    c_store = vread(lcs, lt, 83664, 8)
    assert b_store == bytes.fromhex('7a06000000000000'), f'83480 store {b_store.hex()}'
    assert c_store == bytes.fromhex('7206040102000000'), f'83664 store {c_store.hex()}'
    for store in (83480, 83664):
        assert not any(w <= store < w + 200 for w in linux_wrappers), f'{store} inside a wrapper'

    # 7. REA receipts: every saved read resolves against the pinned subject it names,
    #    at the address it names, and equals the bytes the binary holds there.
    P = Path(__file__).resolve().parent
    subjects = {sha(orig): (orig, ot), sha(cand): (cand, ct), sha(lcs): (lcs, lt)}
    receipts = sorted((P / 'rea-evidence').glob('ev_*.json'))
    assert receipts, 'no REA receipts'
    for path in receipts:
        rec = json.loads(path.read_text())
        assert rec['provider']['id'] == 'ghidra', f'{path.name}: provider'
        image, section = subjects[rec['subject']['sha256']]
        params = rec['parameters']
        assert params['address'] == hex(int(params['address'], 16)), f'{path.name}: address form'
        assert params['length'] == len(bytes.fromhex(rec['bytes_hex'])), f'{path.name}: length'
        observed = vread(image, section, int(params['address'], 16), params['length'])
        assert observed.hex() == rec['bytes_hex'], f'{path.name}: receipt bytes'

    manifest = json.loads((P / 'manifest-sha256.json').read_text())
    for name, pin in manifest.items():
        assert sha((P / name).read_bytes()) == pin, f'manifest pin: {name}'

    print(json.dumps({
        'rea_receipts_checked': len(receipts),
        'verified': True,
        'check': 'callee-identity attribution (PR #74 claim, corrected CALL encoding)',
        'call_targets': {
            'original_query_first': 71256,
            'candidate_query_first': 83552,
            'candidate_wrapper_A_helper': 35856,
            'candidate_wrapper_B_helper': 30752,
            'candidate_wrapper_C_helper': 26680,
        },
        'feeconfig_discriminator_lddw_sites': {
            'original_helper': orig_site,
            'candidate_A_helper': None,
            'candidate_B_helper': None,
            'candidate_C_helper': c_site,
        },
        'linux_build': {
            'query_first_call_target': 82232,
            'wrappers_equal_to_original_after_call_masking': linux_wrappers,
            'feeconfig_wrapper_helper': 28728,
            'feeconfig_discriminator_lddw_site': 29368,
            'site_42_calls_followed_by_exit': [83168, 83368, 83552],
        },
        'corrected_store_shapes_linux_build': {
            '83480_after_42_site_B': 'stdw [r6+0], imm 0 (0x7a op, store-immediate); outside every wrapper',
            '83664_after_42_site_C': 'stb [r6+260], imm 2 (0x72 op, store-immediate byte); outside every wrapper',
        },
        'attribution': 'in each candidate build the query first CALL reaches the only wrapper whose '
                       'helper carries the FeeConfig discriminator, matching the original helper; '
                       'attribution follows the callee (selected 83,552 -> 26,680; Linux 82,232 -> 28,728)',
    }, indent=2))


if __name__ == '__main__':
    main()
