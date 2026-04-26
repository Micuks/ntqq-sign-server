#!/usr/bin/env python3
"""Catalog all distinct opcodes and their ib patterns in the VM trace."""
import json
from collections import defaultdict, Counter

TRACE = json.load(open('/tmp/complete_trace_00.json'))
print(f"Total steps: {len(TRACE)}")

op_counts = Counter()
op_ib_patterns = defaultdict(Counter)

for entry in TRACE:
    step, op, pc, diff, ib = entry
    op_counts[op] += 1
    op_ib_patterns[op][tuple(ib)] += 1

print(f"\nDistinct opcodes: {len(op_counts)}")
print(f"Opcode frequencies:")
for op, cnt in op_counts.most_common():
    # Show ib signatures
    ib_sigs = op_ib_patterns[op]
    n_sigs = len(ib_sigs)
    print(f"  0x{op:02x}: {cnt:5d} calls, {n_sigs} distinct ib patterns")

# Look at what each opcode typically writes to (which regs get updated)
print("\n=== Reg writes per opcode (top 3 per op) ===")
for op in sorted(op_counts):
    reg_writes = Counter()
    for entry in TRACE:
        if entry[1] == op:
            for k in entry[3]:
                reg_writes[int(k)] += 1
    top3 = reg_writes.most_common(3)
    print(f"  0x{op:02x}: {top3}")
