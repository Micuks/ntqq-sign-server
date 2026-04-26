#!/usr/bin/env python3
"""For each (opcode, ib_pattern) in the trace, classify it as:
  - PURE_REG: same input regs always produce same output regs (no memory dependence)
  - MEMORY_READ: same input regs produce DIFFERENT outputs across traces (memory varies)
  - INDEPENDENT: output is the same value across all 4 traces (constant)

Use cross-trace comparison: if an op at step S has same input regs across traces
but different output regs → memory-dependent.
If output values vary by trace but inputs also vary → could be pure register.
"""
import json
from collections import defaultdict
MASK = 0xFFFFFFFF

names = ['00', '01', '02', 'ff']
traces = {n: json.load(open(f'/tmp/complete_trace_{n}.json')) for n in names}

def reconstruct(trace):
    regs = {}
    states = []
    for entry in trace:
        diff = entry[3]
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        states.append(dict(regs))
    return states

states = {n: reconstruct(t) for n, t in traces.items()}
n_steps = len(traces['00'])

# For each step, classify
classifications = []
op_class_count = defaultdict(lambda: defaultdict(int))

for i in range(n_steps):
    op_ref = traces['00'][i][1]
    ib_ref = tuple(traces['00'][i][4])
    # Collect changed registers across 4 traces
    after_vals = {n: set() for n in names}
    diff_keys = set()
    for n in names:
        diff = traces[n][i][3]
        for k, v in diff.items():
            diff_keys.add(int(k))
            after_vals[n].add((int(k), v & MASK))
    # If diffs are identical across all traces, INPUT_INDEPENDENT
    is_indep = all(after_vals[names[0]] == after_vals[n] for n in names[1:])
    # Get input register values (registers referenced in ib that exist before this step)
    # We don't know which ib byte is reg vs imm, so check all
    before_states = {n: states[n][i-1] if i > 0 else {} for n in names}
    # Same input regs across traces?
    inputs_match_count = 0
    for ib_byte in ib_ref[1:]:
        vals = [before_states[n].get(ib_byte) for n in names]
        if all(v == vals[0] for v in vals):
            inputs_match_count += 1

    # Check for memory dependence: outputs differ but ALL ib-referenced inputs match
    if not is_indep and inputs_match_count == 3:  # all 3 ib operands have identical values
        cls = 'MEMORY_DEP'
    elif is_indep:
        cls = 'INDEP'
    else:
        cls = 'REG_DEP'

    classifications.append((i, op_ref, ib_ref, cls))
    op_class_count[op_ref][cls] += 1

# Summary
print(f"{'op':>4} {'INDEP':>8} {'REG_DEP':>8} {'MEMORY_DEP':>10} {'total':>6}")
for op in sorted(op_class_count):
    classes = op_class_count[op]
    indep = classes['INDEP']
    reg = classes['REG_DEP']
    mem = classes['MEMORY_DEP']
    total = indep + reg + mem
    print(f"{hex(op):>5} {indep:>8} {reg:>8} {mem:>10} {total:>6}")

# Count totals
total_steps = sum(sum(v.values()) for v in op_class_count.values())
total_indep = sum(v.get('INDEP', 0) for v in op_class_count.values())
total_reg = sum(v.get('REG_DEP', 0) for v in op_class_count.values())
total_mem = sum(v.get('MEMORY_DEP', 0) for v in op_class_count.values())
print(f"\nTotal: {total_steps} steps")
print(f"  INDEP:      {total_indep} ({100*total_indep/total_steps:.1f}%)")
print(f"  REG_DEP:    {total_reg} ({100*total_reg/total_steps:.1f}%)")
print(f"  MEMORY_DEP: {total_mem} ({100*total_mem/total_steps:.1f}%)")

# Save classifications
with open('/tmp/step_classifications.json', 'w') as f:
    json.dump([(s, op, list(ib), cls) for s, op, ib, cls in classifications], f)
print("Saved /tmp/step_classifications.json")
