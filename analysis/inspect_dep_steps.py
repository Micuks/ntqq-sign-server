#!/usr/bin/env python3
"""Inspect early input-dependent steps across 4 traces to identify semantics."""
import json

MASK = 0xFFFFFFFF
def u32(v): return v & MASK

TRACES = {s: json.load(open(f'/tmp/complete_trace_{s}.json')) for s in ['00','01','02','ff']}

def reconstruct(trace):
    regs = {}
    states = [dict(regs)]
    for entry in trace:
        _, _, _, diff, _ = entry
        for k, v in diff.items():
            regs[int(k)] = u32(v)
        states.append(dict(regs))
    return states

states = {s: reconstruct(TRACES[s]) for s in TRACES}

# For each early input-dependent step, show all 4 traces' diffs
# and identify pattern
print("=== Early input-dependent steps ===")
n_shown = 0
for i in range(2300):
    # Get diff for each src
    diffs = {}
    for s in ['00','01','02','ff']:
        step, op, pc, diff, ib = TRACES[s][i]
        diffs[s] = {int(k): u32(v) for k, v in diff.items()}
    # Check if input-dependent (any diff differs)
    unique_diffs = set(tuple(sorted(d.items())) for d in diffs.values())
    if len(unique_diffs) == 1:
        continue
    # Only show steps with small diffs (easier to analyze)
    max_diff_size = max(len(d) for d in diffs.values())
    if max_diff_size > 3:
        continue
    # Show this step
    step, op, pc, _, ib = TRACES['00'][i]
    print(f"\nstep={i} (trace step #{step}) op=0x{op:02x} ib={ib}")
    for s in ['00','01','02','ff']:
        # Show values of registers in ib
        d = diffs[s]
        before = states[s][i]
        r_ib = {ib[j]: before.get(ib[j]) for j in range(1,4)}
        r_ib_str = {k: (hex(v) if v is not None else 'None') for k, v in r_ib.items()}
        d_str = {k: hex(v) for k, v in d.items()}
        print(f"  src={s}: ib_regs={r_ib_str} diff={d_str}")
    n_shown += 1
    if n_shown >= 20:
        break
