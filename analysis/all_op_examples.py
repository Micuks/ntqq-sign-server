#!/usr/bin/env python3
"""For each opcode, dump diverse examples across all 4 traces.
Save to /tmp/op_examples.json for systematic analysis.
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

# For each (op, ib_pattern), collect cross-trace data:
#   { (op, ib): [
#       { 'step': step_idx,
#         'before_regs': {reg_idx: value} (only refs in ib),
#         'after_diff': {reg_idx: value} } ... ]
#   }
op_examples = defaultdict(list)
n_steps = len(traces['00'])

for i in range(n_steps):
    s, op, pc, diff, ib = traces['00'][i]
    key = (op, tuple(ib))
    if len(op_examples[key]) >= 8:  # enough examples
        continue
    sample = {'step': i}
    for n in names:
        before = states[n][i-1] if i > 0 else {}
        diff_n = traces[n][i][3]
        # Get values at ib operand positions (might be reg index or immediate)
        before_vals = {idx: before.get(idx) for idx in ib[1:]}
        after_diff = {int(k): v & MASK for k, v in diff_n.items()}
        sample[n] = {'before': before_vals, 'after': after_diff}
    op_examples[key].append(sample)

# Convert to json-serializable
out = {}
for (op, ib), examples in op_examples.items():
    key = f'{op:#x}/{",".join(str(x) for x in ib)}'
    out[key] = examples

with open('/tmp/op_examples.json', 'w') as f:
    json.dump(out, f)

print(f"Saved {len(out)} (op, ib) patterns to /tmp/op_examples.json")
print(f"Distinct opcodes: {len(set(k.split('/')[0] for k in out))}")
