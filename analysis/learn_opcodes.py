#!/usr/bin/env python3
"""For each opcode, show diverse instances with input regs (referenced via ib) + output reg.
Use this to deduce the opcode semantics by inspection.
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

def show_op_examples(op, n_examples=5, ib_pattern=None):
    """Show n_examples instances of op, annotating before/after for ib operands."""
    print(f"\n=== op {hex(op)} examples ===")
    seen_patterns = defaultdict(list)
    for i in range(len(traces['00'])):
        s, op_, pc, diff, ib = traces['00'][i]
        if op_ != op: continue
        if ib_pattern is not None and tuple(ib) != tuple(ib_pattern): continue
        key = tuple(ib)
        if len(seen_patterns[key]) >= n_examples: continue
        seen_patterns[key].append(i)

    for ib_key, step_list in seen_patterns.items():
        print(f"  ib={list(ib_key)}:")
        for step_idx in step_list[:n_examples]:
            for n in names:
                before = states[n][step_idx-1] if step_idx > 0 else {}
                diff = traces[n][step_idx][3]
                # Get values of ib operand registers
                operand_vals = [(idx, before.get(idx)) for idx in ib_key[1:]]
                changed = {int(k): v & MASK for k, v in diff.items()}
                op_str = ', '.join(f'r[{k}]={v:#x}' if v is not None else f'r[{k}]=?' for k, v in operand_vals)
                ch_str = ', '.join(f'r[{k}]={v:#x}' for k, v in changed.items())
                print(f"    [{n}] step={step_idx}: BEFORE {op_str} | CHANGED {ch_str}")
            print()

# Examine PURE REG_DEP opcodes (no memory dep)
for op in [0x38, 0x3a, 0x55, 0x2a, 0x16, 0x2f]:
    show_op_examples(op, n_examples=2)
