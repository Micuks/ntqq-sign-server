#!/usr/bin/env python3
"""Find the trace step where X_b1_init[0..3] values first appear in any register.

Known X_b1_init for the 4 trace inputs (captured from native):
  src=00: [0x114d0b11, 0xaffc818b, 0xfc57448f, 0x11d0687]
  src=01: [0x114d0b11, 0xe099818b, 0x30d351c6, 0x11d0639]
  src=02: [0x114d0b11, 0x72b3818b, 0x170f594a, 0x11d063b]
  src=ff: [0x114d0b11, 0x4c4b818b, 0x830a9c17, 0x11d069f]

Strategy:
  For each trace, reconstruct register state step by step.
  Record FIRST step where each of the 4 X_b1 u32 values appears in ANY register.
  Report register index + step + the full opcode context of that write.
"""
import json
MASK = 0xFFFFFFFF

X_B1_INITS = {
    '00': [0x114d0b11, 0xaffc818b, 0xfc57448f, 0x011d0687],
    '01': [0x114d0b11, 0xe099818b, 0x30d351c6, 0x011d0639],
    '02': [0x114d0b11, 0x72b3818b, 0x170f594a, 0x011d063b],
    'ff': [0x114d0b11, 0x4c4b818b, 0x830a9c17, 0x011d069f],
}

for name, xb1 in X_B1_INITS.items():
    trace = json.load(open(f'/tmp/complete_trace_{name}.json'))
    regs = {}
    found = {val: None for val in xb1}
    for i, entry in enumerate(trace):
        step, op, pc, diff, ib = entry
        for k, v in diff.items():
            vv = v & MASK
            regs[int(k)] = vv
            if vv in found and found[vv] is None:
                found[vv] = (i, int(k), op, ib)
    print(f"\n=== src={name} ===")
    for val in xb1:
        loc = found[val]
        if loc is None:
            print(f"  {val:08x}: NOT FOUND")
        else:
            step_i, reg_idx, op, ib = loc
            print(f"  {val:08x}: first-seen step={step_i} reg={reg_idx} op={op:#x} ib={ib}")

# Also: dump register values at step just before cipher starts (~7181) for src=00
print("\n=== src=00 register snapshot around the cipher entry ===")
trace = json.load(open('/tmp/complete_trace_00.json'))
regs = {}
for i, entry in enumerate(trace):
    _, _, _, diff, _ = entry
    for k, v in diff.items():
        regs[int(k)] = v & MASK
    if i in (7179, 7180, 7181, 7182, 7183):
        step, op, pc, diff_, ib = entry
        print(f"\nstep={i} op={op:#x} ib={ib}")
        # Print registers that hold X_b1 values
        for val in X_B1_INITS['00']:
            hits = [k for k, v in regs.items() if v == val]
            if hits:
                print(f"  value {val:08x} is in reg(s) {hits}")
