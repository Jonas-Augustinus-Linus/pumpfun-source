#!/usr/bin/env python3
"""Offline verifier for the Fees call-conflict resolution package.

Re-checks every headline claim against the evidence retained in this
folder. Reads no repo files and no network. For byte-level re-derivation
from the ELFs themselves, see evidence/rederive.py.
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.join(HERE, 'evidence')
GROUP = '5064629c0b173ec75a08a105975751990109ead5c78610174e373612d9c53026'
fails = []

def check(cond, msg):
    print(('PASS ' if cond else 'FAIL ') + msg)
    if not cond:
        fails.append(msg)

def load(name):
    with open(os.path.join(EV, name)) as f:
        return json.load(f)

reg = json.load(open(os.path.join(HERE, 'register.json')))
bodies = load('window_bodies.json')['windows']
edges = load('call_edges.json')
inv = load('inventory_extract.json')

# 1. The four duplicate bodies are byte-identical and hash to the group hash.
hs = {}
for key, w in bodies.items():
    raw = bytes.fromhex(w['hex'])
    check(len(raw) == 272 and w['bytes'] == 272, f'{key} is 272 bytes')
    hs[key] = hashlib.sha256(raw).hexdigest()
    check(hs[key] == GROUP and w['sha256'] == GROUP, f'{key} hashes to the group hash')
check(len(set(bytes.fromhex(w['hex']) for w in bodies.values())) == 1,
      'all four bodies are byte-identical')

# 2. Inventory state: exactly the two conflict rows, one unresolved offset each.
check(inv['summary']['original_status'] == {'mapped_pattern': 461, 'unattributed': 122, 'call_conflict': 2},
      'inventory original summary is 461 / 122 / 2')
for start, cand in (('725664', 710688), ('726064', 711088)):
    row = inv['original_rows'][start]
    check(row['status'] == 'call_conflict', f'original {start} carries call_conflict')
    m = row['candidate_matches']
    check(len(m) == 1 and m[0]['candidate_start'] == cand, f'original {start} has the single candidate match {cand}')
    check(m[0]['normalized_equal'] and m[0]['size_equal'] and m[0]['relocation_pattern_equal'],
          f'original {start} pair is normalized / size / relocation equal')
    check(m[0]['unresolved_call_offsets'] == [232], f'original {start} has offset 232 as its only unresolved call')
    dep = [d for d in row['dependencies']['direct'] if d['offset'] == 232]
    check(len(dep) == 1 and dep[0]['target'] == 799664 and dep[0]['target_candidate_patterns'] == [],
          f'original {start} offset-232 call targets 799664 with no strict candidate pattern')

# 3. The terminal window: unattributed only through the strict-index exclusion.
t = inv['original_rows']['799664']
check(t['status'] == 'unattributed' and t['raw_sha256'] == GROUP, 'original 799664 is the unattributed group body')
check(t['boundary_basis'].startswith('terminal text end'), 'original 799664 boundary basis is the terminal text end')
check(t['dependencies'] == {'direct': [], 'indirect': [], 'external': [], 'relocated_targets': []},
      'original 799664 body has no calls or relocations (raw hash is its normalized hash)')
res = inv['immediate_call_residuals_for_offset_232']
check(len(res) == 2 and all(r['status'] == 'terminal_boundary_only_match' for r in res),
      'both offset-232 residuals are the inventory\u2019s terminal_boundary_only_match entries')

# 4. Terminal extents are hard section bounds, from the recorded ELF identity.
ident = edges['elf_identity']
check(799664 + 272 == ident['original']['text'][1] == 799936, 'original 799664 ends exactly at the original .text end')
check(789432 + 272 == ident['candidate']['text'][1] == 789704, 'candidate 789432 ends exactly at the candidate .text end')
check(ident['original']['sha256'] == reg['inputs']['original_elf']['sha256'] and
      ident['candidate']['sha256'] == reg['inputs']['candidate_elf']['sha256'] and
      ident['symbols']['sha256'] == reg['inputs']['symbols_elf']['sha256'],
      'ELF identities in call_edges.json match register.json')

# 5. Call-edge bijection: offsets align per caller pair, and the group edges
#    select 799664 to 787152 and 799392 to 789432 in both callers.
calls = edges['rent_window_calls']
for o, c in (('original:725664', 'candidate:710688'), ('original:726064', 'candidate:711088')):
    oc, cc = calls[o], calls[c]
    check([x[0] for x in oc] == [x[0] for x in cc], f'{o} and {c} call at identical offsets')
    om, cm = dict(oc), dict(cc)
    check(om[232] == 799664 and cm[232] == 787152, f'{o} offset 232: 799664 paired with 787152')
    off2 = 304 if '725664' in o else 312
    check(om[off2] == 799392 and cm[off2] == 789432, f'{o} offset {off2}: 799392 paired with 789432')
scan = edges['whole_text_caller_scan']
check(scan['original_target_799664'] == [[725896, 232], [726296, 232]] and
      scan['candidate_target_787152'] == [[710920, 232], [711320, 232]],
      'closed caller set for the offset-232 pair (whole-.text scan)')
check(scan['original_target_799392'] == [[725968, 304], [726376, 312]] and
      scan['candidate_target_789432'] == [[710992, 304], [711400, 312]],
      'closed caller set for the second group pair (whole-.text scan)')

# 6. Slot diffs fall only in the classes the inventory normalization masks.
for k, v in edges['rent_slot_diff'].items():
    if not isinstance(v, dict):
        continue
    check(v['other'] == 0 and v['equal'] + v['call_imm_only'] + v['lddw'] == v['slots'],
          f'slot diff {k}: differences confined to call immediates and LDDW slots')

# 7. Register verdicts match the evidence.
check(reg['pin']['commit'] == 'dfe4411d8a390348666025296d4b563813bd41c9', 'register pin is dfe4411')
check(all(r['verdict'] == 'resolved' and r['confidence'] == 'established' for r in reg['conflict_rows']),
      'register records both rows resolved at established confidence')
check(reg['attribution_within_group']['799664']['candidate'] == 787152 and
      reg['attribution_within_group']['799392']['candidate'] == 789432,
      'register attribution matches the call-edge bijection')

print()
if fails:
    print(f'{len(fails)} CHECK(S) FAILED')
    sys.exit(1)
print('ALL CHECKS PASSED')
