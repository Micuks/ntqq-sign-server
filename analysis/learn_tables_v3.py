"""Try more table-lookup variants:
- target = TABLE[(reg[idx_reg] >> SH) & 0xFF]  (byte extraction)
- target = TABLE[reg[idx_reg]]  (full reg as index, large table)
- target = TABLE[reg[A] ^ reg[B]] (XOR'd index)
- target = TABLE[(reg[A] + reg[B]) & 0xFF]
"""
import json
from collections import defaultdict

NREGS = 150
MASK = 0xFFFFFFFF

print("Loading...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))
n_steps = len(traces[0])

by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

# Already solved set
v5 = json.load(open('/tmp/learned_v5.json'))
already = set(eval(k) for k in v5['solved'])
more = json.load(open('/tmp/more_solved.json'))
already.update(eval(k) for k in more)
nops = json.load(open('/tmp/nop_patterns.json'))
already.update(tuple(ib) for ib in nops)
v6 = json.load(open('/tmp/v6_solved.json'))
already.update(eval(k) for k in v6)
bb = json.load(open('/tmp/byte_solved.json'))
already.update(eval(k) for k in bb)

print(f"Already: {len(already)}")
unsolved = [(ib, steps) for ib, steps in by_ib.items() if ib not in already]
print(f"Unsolved: {len(unsolved)}")

new_solved = {}

for ib, steps in unsolved:
    op, b1, b2, b3 = ib
    
    # Find target reg
    target_changes = defaultdict(list)
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    target_changes[r].append((before, after))
    if not target_changes: continue
    target = max(target_changes, key=lambda r: len(target_changes[r]))
    
    obs = []
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            obs.append((before, after[target]))
    
    # Try: target = TABLE[(reg[X] >> SH) & 0xFF]
    found = None
    for idx_reg in range(NREGS):
        if idx_reg == target: continue
        for sh in [0, 8, 16, 24]:
            tbl = {}
            ok = True
            for state, val in obs:
                idx = (state[idx_reg] >> sh) & 0xFF
                if idx in tbl and tbl[idx] != val:
                    ok = False
                    break
                tbl[idx] = val
            if ok and len(tbl) >= 8:
                found = ('byte_table', idx_reg, sh, tbl)
                break
        if found: break
    
    if not found:
        # Try: target = TABLE[(reg[X] + reg[Y]) & 0xFF]
        for r1 in range(NREGS):
            if r1 == target: continue
            for r2 in range(NREGS):
                if r2 == target or r2 <= r1: continue
                tbl = {}
                ok = True
                for state, val in obs:
                    idx = (state[r1] + state[r2]) & 0xFF
                    if idx in tbl and tbl[idx] != val:
                        ok = False
                        break
                    tbl[idx] = val
                if ok and len(tbl) >= 12:
                    found = ('add_table', r1, r2, tbl)
                    break
            if found: break
    
    if not found:
        # Try: target = TABLE[reg[X] ^ reg[Y] & 0xFF]
        for r1 in range(NREGS):
            if r1 == target: continue
            for r2 in range(NREGS):
                if r2 == target or r2 <= r1: continue
                tbl = {}
                ok = True
                for state, val in obs:
                    idx = (state[r1] ^ state[r2]) & 0xFF
                    if idx in tbl and tbl[idx] != val:
                        ok = False
                        break
                    tbl[idx] = val
                if ok and len(tbl) >= 12:
                    found = ('xor_table', r1, r2, tbl)
                    break
            if found: break
    
    if found:
        new_solved[ib] = (target, found)

print(f"New table-solved: {len(new_solved)}")
from collections import Counter
op_solve = Counter(ib[0] for ib in new_solved)
for op, cnt in sorted(op_solve.items(), key=lambda x: -x[1])[:10]:
    print(f"  op 0x{op:02x}: {cnt}")

# Save
saved = {}
for ib, (target, info) in new_solved.items():
    kind = info[0]
    if kind == 'byte_table':
        idx_reg, sh, tbl = info[1], info[2], info[3]
        saved[str(ib)] = ['BYTE_TABLE', target, idx_reg, sh, {str(k): v for k, v in tbl.items()}]
    elif kind == 'add_table':
        r1, r2, tbl = info[1], info[2], info[3]
        saved[str(ib)] = ['ADD_TABLE', target, r1, r2, {str(k): v for k, v in tbl.items()}]
    elif kind == 'xor_table':
        r1, r2, tbl = info[1], info[2], info[3]
        saved[str(ib)] = ['XOR_TABLE', target, r1, r2, {str(k): v for k, v in tbl.items()}]
json.dump(saved, open('/tmp/tables_v3.json','w'))
print(f"Saved /tmp/tables_v3.json")
