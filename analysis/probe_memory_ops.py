#!/usr/bin/env python3
"""Probe: identify which opcodes are memory loads/stores vs pure register ops.

Heuristic: for each (op, ib), check if the DIFF is a deterministic function
of register state BEFORE the op. If yes across all 4 traces, it's a pure
register op. If the diff varies given same register state, memory is involved.
"""
import json
from collections import defaultdict

MASK = 0xFFFFFFFF
def u32(v): return v & MASK

def reconstruct(trace):
    regs = {}
    states = [dict(regs)]
    for entry in trace:
        _, _, _, diff, _ = entry
        for k, v in diff.items():
            regs[int(k)] = u32(v)
        states.append(dict(regs))
    return states

all_traces = {s: json.load(open(f'/tmp/complete_trace_{s}.json')) for s in ['00','01','02','ff']}
all_states = {s: reconstruct(all_traces[s]) for s in all_traces}

# For each (op, ib_sig), collect (step_i, src, rel_registers, diff) tuples across all 4 srcs
# Only track registers referenced by ib (since those are the most likely "input") plus low regs 0-50.
INTERESTING_REGS = set(range(64))

print("=== Opcode determinism analysis ===\n")
op_stats = defaultdict(lambda: {'ibs': set(), 'data': [], 'total': 0})

for s in ['00','01','02','ff']:
    trace = all_traces[s]
    states = all_states[s]
    for i, entry in enumerate(trace):
        step, op, pc, diff, ib = entry
        before = states[i]
        # Only track relevant register subset
        rel = tuple((r, before.get(r, 0)) for r in [ib[1], ib[2], ib[3]] + sorted(INTERESTING_REGS))
        op_stats[op]['ibs'].add(tuple(ib))
        op_stats[op]['data'].append((tuple(ib), tuple(sorted((int(k), u32(v)) for k, v in diff.items())),
                                      tuple(before.get(r, 0) for r in ib[1:4])))
        op_stats[op]['total'] += 1

# For each op, test: is the diff a deterministic function of (ib, reg[ib[1..3]])?
print(f"{'Op':>5} {'Calls':>6} {'IBs':>4} {'Deterministic':>15} {'Details':>10}")
for op in sorted(op_stats, key=lambda o: -op_stats[o]['total']):
    data = op_stats[op]
    # group by (ib, (input reg values)) and check diff uniqueness
    groups = defaultdict(set)
    for ib, d, ir in data['data']:
        groups[(ib, ir)].add(d)
    deterministic = sum(1 for k, v in groups.items() if len(v) == 1)
    total = len(groups)
    is_det = deterministic == total
    pct = 100 * deterministic / total if total else 0
    print(f"  0x{op:02x}  {data['total']:5d}  {len(data['ibs']):3d}  {pct:13.1f}%  {'PURE' if is_det else 'MEM?'}")
    # Show non-deterministic examples for spot-check
    if not is_det and data['total'] >= 100:
        for (ib, ir), diffs in list(groups.items())[:2]:
            if len(diffs) > 1:
                print(f"    non-det: ib={list(ib)} in_regs={[hex(x) for x in ir]}")
                for d in list(diffs)[:3]:
                    print(f"      diff: {d}")
