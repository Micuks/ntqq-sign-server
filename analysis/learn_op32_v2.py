"""For each op 0x32 ib pattern, find:
   target = TABLE[reg[idx_reg] & 0xFF] for some TABLE.

Try ALL possible source registers as the index, and learn the TABLE empirically.
The TABLE must be CONSISTENT across all instances and all input traces.
"""
import json
import hashlib
from collections import defaultdict

NREGS = 150
MASK = 0xFFFFFFFF

print("Loading 16 traces...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))

n_steps = len(traces[0])
sbox = open('/mnt/data1/wuql/services/ntqq-sign-server/custom_sbox.bin','rb').read()
md5s = {sb: hashlib.md5(bytes([sb])).digest() for sb in range(16)}

# All op 0x32 instances
by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or ib[0] != 0x32: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

print(f"op 0x32 ibs: {len(by_ib)}")

solved_count = 0
discovered_tables = {}  # idx_reg → table

# For each ib pattern, find idx_reg
for ib, steps in sorted(by_ib.items()):
    target = ib[1]
    if target >= NREGS: continue
    
    # Build list of (reg_state_at_step, target_after) tuples
    obs = []
    for s in steps:
        for sb in range(16):
            obs.append((traces[sb][s][2], traces[sb][s+1][2][target]))
    
    # CONST check: target_after same across all
    consts = set(t for _, t in obs)
    if len(consts) == 1:
        # Pure constant
        # print(f"  ib={ib}: CONST 0x{list(consts)[0]:02x}")
        solved_count += 1
        continue
    
    # Try each register as index
    found = None
    for idx_reg in range(NREGS):
        # Build (idx, target) pairs
        idx_to_val = {}
        ok = True
        for state, target_val in obs:
            idx = state[idx_reg] & 0xFF
            if idx in idx_to_val and idx_to_val[idx] != target_val:
                ok = False
                break
            idx_to_val[idx] = target_val
        if ok and len(idx_to_val) >= 4:  # need enough distinct indices
            # Match against known tables
            sbox_match = all(v == sbox[i] for i, v in idx_to_val.items() if i < 256)
            if sbox_match:
                found = (idx_reg, 'SBOX')
                break
            else:
                # Unknown table, but CONSISTENT
                if found is None:
                    found = (idx_reg, idx_to_val.copy())
    
    if found:
        idx_reg, info = found
        if info == 'SBOX':
            # print(f"  ib={ib}: target = SBOX[r{idx_reg}]")
            pass
        # print(f"  ib={ib}: target = TABLE_{idx_reg}[r{idx_reg}] (size {len(info) if isinstance(info,dict) else 0})")
        solved_count += 1
        discovered_tables[ib] = (idx_reg, info)

print(f"\nSolved (CONST or table-lookup): {solved_count}/{len(by_ib)}")

# Show discovered SBOX patterns
sbox_pats = [(ib, idx) for ib, (idx, info) in discovered_tables.items() if info == 'SBOX']
print(f"SBOX patterns: {len(sbox_pats)}")
for ib, idx in sbox_pats[:10]:
    print(f"  ib={ib} → SBOX[r{idx}]")

# Show non-SBOX table patterns
table_pats = [(ib, idx, info) for ib, (idx, info) in discovered_tables.items() if info != 'SBOX']
print(f"\nUnknown tables: {len(table_pats)}")
for ib, idx, info in table_pats[:10]:
    if isinstance(info, dict):
        items = sorted(info.items())[:8]
        print(f"  ib={ib} → TABLE[r{idx}] = {[(hex(i), hex(v)) for i, v in items]}")

# Save
saved = {}
for ib, (idx, info) in discovered_tables.items():
    if info == 'SBOX':
        saved[str(ib)] = ['SBOX', idx]
    elif isinstance(info, dict):
        saved[str(ib)] = ['TABLE', idx, {str(k): v for k, v in info.items()}]
json.dump(saved, open('/tmp/op32_v2.json','w'))
print(f"\nSaved /tmp/op32_v2.json")
