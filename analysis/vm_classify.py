#!/usr/bin/env python3
"""Classify each of 16,186 steps: is its diff input-dependent or identical across 4 srcs?

Input-independent steps can be oracle-replayed (diff is fixed).
Input-dependent steps need implementation to handle new inputs.
"""
import json
from collections import defaultdict

MASK = 0xFFFFFFFF
def u32(v): return v & MASK

TRACES = {s: json.load(open(f'/tmp/complete_trace_{s}.json')) for s in ['00','01','02','ff']}
N = min(len(t) for t in TRACES.values())

# Classify each step
indep_steps = []  # step indices where all 4 diffs are identical
dep_steps = []    # step indices where diffs differ

for i in range(N):
    diffs = tuple(frozenset(tuple(sorted({int(k): u32(v) for k,v in TRACES[s][i][3].items()}.items())) for s in ['00','01','02','ff']))
    if len(set(diffs)) == 1:
        indep_steps.append(i)
    else:
        dep_steps.append(i)

print(f"Total steps: {N}")
print(f"Input-independent (diff same across srcs): {len(indep_steps)} ({100*len(indep_steps)/N:.1f}%)")
print(f"Input-dependent (diff varies): {len(dep_steps)} ({100*len(dep_steps)/N:.1f}%)")

# Which OPs appear in input-dependent steps?
dep_op_counts = defaultdict(lambda: {'count': 0, 'first_step': None, 'ibs': set()})
for i in dep_steps:
    e = TRACES['00'][i]
    step, op, pc, diff, ib = e
    dep_op_counts[op]['count'] += 1
    if dep_op_counts[op]['first_step'] is None or i < dep_op_counts[op]['first_step']:
        dep_op_counts[op]['first_step'] = i
    dep_op_counts[op]['ibs'].add(tuple(ib))

print(f"\nInput-dependent ops ({len(dep_op_counts)} distinct):")
for op in sorted(dep_op_counts, key=lambda o: -dep_op_counts[o]['count']):
    info = dep_op_counts[op]
    print(f"  0x{op:02x}: {info['count']} calls, {len(info['ibs'])} ib patterns, first at step {info['first_step']}")

# Save input-dependent steps for further analysis
with open('/tmp/dep_steps.json', 'w') as f:
    json.dump(dep_steps, f)
print(f"\nSaved /tmp/dep_steps.json")
