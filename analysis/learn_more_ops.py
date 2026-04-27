"""For each unsolved (op, ib), try TABLE[reg[X] & 0xFF] hypothesis.
Also try memory-load hypothesis with multiple index/offset combos.
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

# All ib patterns
by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

# Load existing solved
v5 = json.load(open('/tmp/learned_v5.json'))
already_solved = set()
for ib_str in v5['solved']:
    already_solved.add(eval(ib_str))

# Find unsolved
unsolved = [(ib, steps) for ib, steps in by_ib.items() if ib not in already_solved]
print(f"Unsolved: {len(unsolved)}")

# Try table-lookup for unsolved with target reg = ib[1]
table_solved = {}
for ib, steps in unsolved:
    target = ib[1]
    if target >= NREGS: continue
    
    # First check if target ever changes
    changes = False
    for s in steps:
        for sb in range(16):
            if traces[sb][s][2][target] != traces[sb][s+1][2][target]:
                changes = True
                break
        if changes: break
    if not changes: continue
    
    # Build observations
    obs = []
    for s in steps:
        for sb in range(16):
            obs.append((traces[sb][s][2], traces[sb][s+1][2][target]))
    
    # Try table-lookup with each reg as index
    found = False
    for idx_reg in range(NREGS):
        if idx_reg == target: continue
        idx_to_val = {}
        ok = True
        for state, target_val in obs:
            idx = state[idx_reg] & 0xFF
            if idx in idx_to_val and idx_to_val[idx] != target_val:
                ok = False
                break
            idx_to_val[idx] = target_val
        if ok and len(idx_to_val) >= 8:
            table_solved[ib] = (idx_reg, idx_to_val)
            found = True
            break
    
    # Try with full word index (not just &0xFF)
    if not found:
        for idx_reg in range(NREGS):
            idx_to_val = {}
            ok = True
            for state, target_val in obs:
                idx = state[idx_reg] & 0xFFFF  # 16-bit index
                if idx in idx_to_val and idx_to_val[idx] != target_val:
                    ok = False
                    break
                idx_to_val[idx] = target_val
            if ok and len(idx_to_val) >= 8:
                table_solved[ib] = (idx_reg, idx_to_val, '16bit')
                found = True
                break

print(f"Newly table-solved: {len(table_solved)}")

# Show breakdown by op
from collections import Counter
op_solve = Counter()
for ib in table_solved:
    op_solve[ib[0]] += 1
print("\n=== New table solves by op ===")
for op, cnt in sorted(op_solve.items(), key=lambda x: -x[1])[:20]:
    print(f"  op 0x{op:02x}: {cnt}")

# Save
saved = {}
for ib, info in table_solved.items():
    if len(info) == 2:
        idx, table = info
        saved[str(ib)] = ['TABLE_8', idx, {str(k): v for k, v in table.items()}]
    else:
        idx, table, _ = info
        saved[str(ib)] = ['TABLE_16', idx, {str(k): v for k, v in table.items()}]
json.dump(saved, open('/tmp/more_solved.json','w'))
print(f"\nSaved /tmp/more_solved.json")
print(f"Total now: {len(already_solved) + len(table_solved)}/{len(by_ib)}")
