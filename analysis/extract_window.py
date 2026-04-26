#!/usr/bin/env python3
"""Extract precise VM trace data for the X_b1_init construction window (steps 6900-7180)
across all 4 traces. This gives us the complete data to learn each opcode's semantics.

Output:
  /tmp/window_xb1_build.json — list of step entries with (step, op, ib, full_regs_before, full_regs_after)
  4 entries: one per trace (00, 01, 02, ff)
"""
import json
MASK = 0xFFFFFFFF

def reconstruct(trace, end):
    regs = {}
    states = []
    for i in range(end + 1):
        diff = trace[i][3]
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        states.append(dict(regs))
    return states

start, end = 6900, 7180
window = {}
for name in ['00','01','02','ff']:
    trace = json.load(open(f'/tmp/complete_trace_{name}.json'))
    states = reconstruct(trace, end)
    steps = []
    for i in range(start, end+1):
        step, op, pc, diff, ib = trace[i]
        before = states[i-1] if i > 0 else {}
        after = states[i]
        # which regs changed
        changed = {k: after[k] for k in after if before.get(k) != after.get(k)}
        steps.append({'step': i, 'op': op, 'pc': pc, 'ib': ib,
                      'before': dict(before), 'after': dict(after),
                      'changed': changed})
    window[name] = steps

with open('/tmp/window_xb1_build.json', 'w') as f:
    json.dump(window, f)
print(f"Saved window data: {end-start+1} steps × 4 traces")

# Quick analysis: count distinct (op, ib) patterns in the window
from collections import Counter
patterns = Counter()
for step in window['00']:
    key = (step['op'], tuple(step['ib']))
    patterns[key] += 1
print(f"\n{len(patterns)} distinct (op, ib) patterns in window:")
for (op, ib), cnt in sorted(patterns.items(), key=lambda x: -x[1])[:30]:
    print(f"  op={op:#x}({op:>3}) ib={list(ib)}  count={cnt}")

# For each unique opcode (regardless of ib), summarize
op_count = Counter()
for step in window['00']:
    op_count[step['op']] += 1
print(f"\nOpcodes used in window ({len(op_count)} distinct):")
for op, cnt in sorted(op_count.items(), key=lambda x: -x[1]):
    print(f"  op={op:#x}({op:>3}) count={cnt}")
