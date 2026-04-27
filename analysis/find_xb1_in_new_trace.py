#!/usr/bin/env python3
"""In the new full-trace, find which register holds X_b1_init[2] (the fully-variable u32).

Targets:
  src=00: X_b1_init[2] = 0xfc57448f
  src=01: X_b1_init[2] = 0x30d351c6
  src=02: X_b1_init[2] = 0x170f594a
  src=ff: X_b1_init[2] = 0x830a9c17
"""
import json

NREGS = 150
TARGETS = {
    '00': 0xfc57448f,
    '01': 0x30d351c6,
    '02': 0x170f594a,
    'ff': 0x830a9c17,
}

traces = {}
for n, target in TARGETS.items():
    traces[n] = json.load(open(f'/tmp/full_trace_{n}.json'))

# At each step, find which register holds the target value for each trace
# A register R holds X_b1_init[2] consistently if for trace[name][step][2][R] == TARGETS[name]
# for ALL names at the same step.
n_steps = len(traces['00'])
print(f"n_steps = {n_steps}")

# For each step, check if any register R has the right value across all 4 traces
matching_per_step = []
for s in range(n_steps):
    matches = []
    for r in range(NREGS):
        all_match = True
        for name in TARGETS:
            if traces[name][s][2][r] != TARGETS[name]:
                all_match = False
                break
        if all_match:
            matches.append(r)
    if matches:
        matching_per_step.append((s, matches))

print(f"Found X_b1_init[2] at {len(matching_per_step)} step/reg combinations")
print(f"First 10 matches:")
for s, regs in matching_per_step[:10]:
    print(f"  step {s}: regs {regs}")
print(f"Last 10:")
for s, regs in matching_per_step[-10:]:
    print(f"  step {s}: regs {regs}")

# Also find where X_b1_init[3] low byte appears (= 0x87, 0x39, 0x3b, 0x9f for the 4 srcs)
TARGETS_X3_LO = {
    '00': 0x87,
    '01': 0x39,
    '02': 0x3b,
    'ff': 0x9f,
}
print("\nFinding X_b1_init[3] low byte across traces (for narrowing search):")
matching_x3 = []
for s in range(n_steps):
    matches = []
    for r in range(NREGS):
        all_match = True
        for name in TARGETS_X3_LO:
            if (traces[name][s][2][r] & 0xFF) != TARGETS_X3_LO[name]:
                all_match = False
                break
        if all_match:
            matches.append(r)
    if matches:
        matching_x3.append((s, matches))
print(f"Found X_b1[3] low8 in regs at {len(matching_x3)} steps")
for s, regs in matching_x3[:5]:
    print(f"  step {s}: regs {regs}")
