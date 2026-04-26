#!/usr/bin/env python3
"""Decode operations 0x01, 0x2d around the X_b1_init construction sites.

For each of 4 traces, print:
  - state of all registers at step N-1 (before the op)
  - state of all registers at step N (after)
  - report which regs changed and candidate semantic mappings

Key sites:
  step=7059: op 0x01 ib=[1,16,45,6]   -> writes X_b1_init[1] to reg[6]
  step=7107: op 0x2d ib=[45,6,12,18]  -> writes X_b1_init[3] to reg[6]
  step=7132: op 0x2d ib=[45,6,12,17]  -> writes X_b1_init[2] to reg[6]
  step=7181: op 0x31 ib=[49,5,9,4]    -> likely moves reg[5] somewhere
"""
import json
MASK = 0xFFFFFFFF

def build_states(trace):
    regs = {}
    states = [dict(regs)]
    for entry in trace:
        _, _, _, diff, _ = entry
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        states.append(dict(regs))
    return states

def probe(name, target_step):
    trace = json.load(open(f'/tmp/complete_trace_{name}.json'))
    states = build_states(trace)
    before = states[target_step]
    after  = states[target_step + 1]
    entry = trace[target_step]
    step, op, pc, diff, ib = entry
    print(f"\n  src={name} step={target_step} op={op:#x} ib={ib}")
    print(f"    diff: {diff}")
    # Print values of the 3 ib operand indices
    for idx in ib[1:]:
        v = before.get(idx, 0)
        print(f"    reg[{idx}] before = {v:#x}")

for target in [7059, 7107, 7132, 7181]:
    print(f"\n\n========== STEP {target} ==========")
    for name in ['00','01','02','ff']:
        probe(name, target)

# For op 0x2d we hypothesize array-load: result = mem[reg[src1] + index]
# Let's check if reg[12] before step 7107 is a consistent address/pointer across traces
# and if the reading pattern matches element 17 vs 18 being loaded.
# The VM is 32-bit so reg values are 32-bit. mem[ptr + 17*4] type access would need dereference.
# Since our trace only records u32 reg values, the pointer is a u32 (low bits of a real pointer).

# Secondary check: is X_b1_init[2] = f(reg[12])? If it's an indirect memory read, we
# won't see the data in the reg array — only in memory. That's fine — we just need to
# find what table the values come from.
print("\n\n=== X_b1_init[2] and X_b1_init[3] values from 4 traces ===")
print("These are the values for cmd='wtlogin.login' with different src inputs")
print(" idx=2 (step 7132, ib=[45,6,12,17]):  fc57448f / 30d351c6 / 170f594a / 830a9c17")
print(" idx=3 (step 7107, ib=[45,6,12,18]):  011d0687 / 011d0639 / 011d063b / 011d069f")
print()
print("For idx=3: high 24 bits are constant (0x011d06), low 8 bits vary (87/39/3b/9f)")
print("For idx=2: all 32 bits vary")
print()
# Check if idx=3 low byte correlates with some known quantity
low8 = {'00': 0x87, '01': 0x39, '02': 0x3b, 'ff': 0x9f}
import hashlib
for name, v in low8.items():
    src = bytes([int(name,16)])
    md5 = hashlib.md5(src).digest()
    print(f"  src={name}: X_b1_init[3] low 8 = 0x{v:02x}   MD5[0..3]={md5[:4].hex()}   MD5 parity byte: {md5[0]^md5[1]^md5[2]^md5[3]:02x}")
