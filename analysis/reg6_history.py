#!/usr/bin/env python3
"""Trace reg[6] across the X_b1_init construction window (steps 7000-7200).
Log each step where reg[6] changes + the op/ib. Do this for all 4 traces side-by-side.
"""
import json
MASK = 0xFFFFFFFF

names = ['00','01','02','ff']
traces = {n: json.load(open(f'/tmp/complete_trace_{n}.json')) for n in names}

def reg_value(trace, step_i, reg_idx):
    """Reconstruct reg at step_i (value AFTER step_i executes)."""
    v = 0
    for i in range(step_i + 1):
        diff = trace[i][3]
        if str(reg_idx) in diff:
            v = diff[str(reg_idx)] & MASK
    return v

# We don't want O(n^2). Instead reconstruct all steps once.
def rebuild(trace):
    regs = {}
    result = []
    for i, entry in enumerate(trace):
        diff = entry[3]
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        result.append(dict(regs))
    return result

states = {n: rebuild(t) for n, t in traces.items()}

# Track reg[6] changes across steps 6900..7200 and pair with op info
print(f"{'step':>5}  {'op ib':<28}  " + '  '.join(f'reg[6][{n}]'.ljust(12) for n in names))
prev = {n: None for n in names}
for i in range(6900, 7200):
    e00 = traces['00'][i]
    op, ib = e00[1], e00[4]
    vals = []
    changed = False
    for n in names:
        v = states[n][i].get(6, 0)
        if v != prev[n]:
            changed = True
            vals.append(f"{v:08x}*")
        else:
            vals.append(f"{v:08x} ")
        prev[n] = v
    if changed:
        print(f"{i:>5}  op={op:#x} ib={ib}  " + '  '.join(v.ljust(12) for v in vals))
