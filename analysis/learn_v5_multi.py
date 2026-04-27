"""Multi-trace opcode learner.

Using 16 same-process traces eliminates pointer noise. Now register diffs
correlate cleanly with input.
"""
import json
from collections import defaultdict

NREGS = 150
MASK = 0xFFFFFFFF

def rotl32(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & MASK

def rotr32(x, n):
    n = n & 31
    return ((x >> n) | (x << (32 - n))) & MASK

print("Loading 16 traces (same process)...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))
    print(f"  src=0x{sb:02x}: {len(traces[sb])} samples")

n_steps = len(traces[0])

# Group instances
groups = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    if not all(list(traces[sb][s][1]) == list(ib) for sb in range(16)): continue
    groups[tuple(ib)].append(s)

print(f"\n(op,ib) groups: {len(groups)}")

# For each group, find changed registers and try formulas
solved = {}
unsolved_changes = {}

for ib, steps in groups.items():
    op, b1, b2, b3 = ib
    
    # Find which registers change (consistent across all instances and all 16 traces)
    if not steps: continue
    
    # Collect (before, after) for each (step, src) pair
    changed_per_step = []
    for s in steps:
        before = traces[0][s][2]
        after = traces[0][s+1][2]
        c = [r for r in range(NREGS) if before[r] != after[r]]
        changed_per_step.append(set(c))
    
    # The "always-changed" register set
    always_changed = set.intersection(*changed_per_step) if changed_per_step else set()
    any_changed = set.union(*changed_per_step) if changed_per_step else set()
    
    target = None
    if b1 < NREGS and b1 in any_changed:
        target = b1
    elif always_changed:
        target = list(always_changed)[0]
    elif any_changed:
        target = list(any_changed)[0]
    
    if target is None:
        continue
    
    # Build observations
    obs = []
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            obs.append((before, after))
    
    # Try formulas
    src_a = b2 if b2 < NREGS else None
    src_b = b3 if b3 < NREGS else None
    
    formulas = []
    formulas.append(('target = b3', lambda b, a: b3))
    formulas.append(('target = b2', lambda b, a: b2))
    formulas.append(('target = b3 - b2', lambda b, a: (b3 - b2) & MASK))
    if src_a is not None:
        formulas.append(('target = src_a', lambda b, a, sa=src_a: b[sa]))
        formulas.append(('target = src_a ^ b3', lambda b, a, sa=src_a: b[sa] ^ b3))
        formulas.append(('target = src_a + b3', lambda b, a, sa=src_a: (b[sa] + b3) & MASK))
        formulas.append(('target = src_a - b3', lambda b, a, sa=src_a: (b[sa] - b3) & MASK))
        formulas.append(('target = b3 - src_a', lambda b, a, sa=src_a: (b3 - b[sa]) & MASK))
        formulas.append(('target = src_a & b3', lambda b, a, sa=src_a: b[sa] & b3))
        formulas.append(('target = src_a | b3', lambda b, a, sa=src_a: b[sa] | b3))
        formulas.append(('target = src_a >> b3', lambda b, a, sa=src_a: (b[sa] >> b3) & MASK if b3 < 32 else 0))
        formulas.append(('target = src_a << b3', lambda b, a, sa=src_a: (b[sa] << b3) & MASK if b3 < 32 else 0))
        formulas.append(('target = rotl(src_a, b3)', lambda b, a, sa=src_a: rotl32(b[sa], b3)))
        formulas.append(('target = rotr(src_a, b3)', lambda b, a, sa=src_a: rotr32(b[sa], b3)))
        formulas.append(('target ^= src_a', lambda b, a, sa=src_a, tg=target: b[tg] ^ b[sa]))
        formulas.append(('target += src_a', lambda b, a, sa=src_a, tg=target: (b[tg] + b[sa]) & MASK))
        formulas.append(('target -= src_a', lambda b, a, sa=src_a, tg=target: (b[tg] - b[sa]) & MASK))
        formulas.append(('target = src_a (low 16)', lambda b, a, sa=src_a: b[sa] & 0xFFFF))
        formulas.append(('target = src_a (low 8)', lambda b, a, sa=src_a: b[sa] & 0xFF))
        formulas.append(('target = ~src_a', lambda b, a, sa=src_a: (~b[sa]) & MASK))
        formulas.append(('target = -src_a', lambda b, a, sa=src_a: (-b[sa]) & MASK))
        # Sign extend variants
        formulas.append(('target = sign_ext_8(src_a)', lambda b, a, sa=src_a: ((b[sa] & 0xFF) ^ 0x80) - 0x80 & MASK))
        formulas.append(('target = sign_ext_16(src_a)', lambda b, a, sa=src_a: ((b[sa] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK))
        # Insert byte b3 at byte position controlled by what?
    if src_a is not None and src_b is not None:
        formulas.append(('target = src_a ^ src_b', lambda b, a, sa=src_a, sb=src_b: b[sa] ^ b[sb]))
        formulas.append(('target = src_a + src_b', lambda b, a, sa=src_a, sb=src_b: (b[sa] + b[sb]) & MASK))
        formulas.append(('target = src_a - src_b', lambda b, a, sa=src_a, sb=src_b: (b[sa] - b[sb]) & MASK))
        formulas.append(('target = src_b - src_a', lambda b, a, sa=src_a, sb=src_b: (b[sb] - b[sa]) & MASK))
        formulas.append(('target = src_a & src_b', lambda b, a, sa=src_a, sb=src_b: b[sa] & b[sb]))
        formulas.append(('target = src_a | src_b', lambda b, a, sa=src_a, sb=src_b: b[sa] | b[sb]))
        formulas.append(('target = src_a * src_b', lambda b, a, sa=src_a, sb=src_b: (b[sa] * b[sb]) & MASK))
        formulas.append(('target = src_a >> src_b', lambda b, a, sa=src_a, sb=src_b: (b[sa] >> (b[sb]&31)) & MASK))
        formulas.append(('target = src_a << src_b', lambda b, a, sa=src_a, sb=src_b: (b[sa] << (b[sb]&31)) & MASK))
        formulas.append(('target = rotl(src_a, src_b)', lambda b, a, sa=src_a, sb=src_b: rotl32(b[sa], b[sb])))
        # XOR-three regs
        formulas.append(('target = src_a ^ src_b ^ tgt', lambda b, a, sa=src_a, sb=src_b, tg=target: b[sa] ^ b[sb] ^ b[tg]))
    
    formula_found = None
    for name, fn in formulas:
        ok = True
        for before, after in obs:
            try:
                expected = fn(before, after) & MASK
                if expected != after[target]:
                    ok = False
                    break
            except Exception:
                ok = False
                break
        if ok:
            formula_found = (name, target)
            break
    
    if formula_found:
        solved[ib] = formula_found
    else:
        # Note the changed regs
        unsolved_changes[ib] = (sorted(any_changed), len(steps))

print(f"\nSolved with simple formulas: {len(solved)}")
print(f"Unsolved: {len(unsolved_changes)}")

# Per-op summary
op_stats = defaultdict(lambda: [0, 0])
for ib in groups:
    op_stats[ib[0]][1] += 1
for ib in solved:
    op_stats[ib[0]][0] += 1

print("\n=== Per-opcode solve rate ===")
for op in sorted(op_stats.keys()):
    s, t = op_stats[op]
    print(f"  op 0x{op:02x}: {s}/{t} ({100*s/t:.0f}%)")

# Save
out = {
    'solved': {str(k): list(v) for k, v in solved.items()},
    'unsolved': {str(k): list(v) for k, v in unsolved_changes.items()},
}
json.dump(out, open('/tmp/learned_v5.json','w'))
print(f"\nSaved /tmp/learned_v5.json")
