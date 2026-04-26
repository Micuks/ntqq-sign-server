#!/usr/bin/env python3
"""Trace backward from X_b1_init bytes to MD5 bytes.

For src=00, X_b1_init[2] = 0xfc57448f. The 4 bytes (0xfc, 0x57, 0x44, 0x8f) get
written to reg[6] at specific steps. For each byte-write, identify the SOURCE
register and trace WHEN that source register received its value, repeating
backward until we reach the MD5 byte XOR steps (2237..2503).
"""
import json
MASK = 0xFFFFFFFF

trace = json.load(open('/tmp/complete_trace_00.json'))
states = []
regs = {}
for entry in trace:
    diff = entry[3]
    for k, v in diff.items():
        regs[int(k)] = v & MASK
    states.append(dict(regs))

def find_last_write(reg_idx, before_step):
    """Find the most recent step BEFORE before_step where reg_idx was written
    to its current value."""
    for i in range(before_step - 1, -1, -1):
        if str(reg_idx) in trace[i][3]:
            return i
    return None

# Start: at step 7038, reg[16] = 0xfc. Trace back.
def trace_back(reg_idx, step, depth=0, max_depth=20):
    if depth > max_depth:
        return
    last = find_last_write(reg_idx, step + 1)
    if last is None:
        return
    s, op, pc, diff, ib = trace[last]
    val = diff[str(reg_idx)] & MASK
    indent = '  ' * depth
    print(f"{indent}step={last} op={op:#x} ib={ib} -> reg[{reg_idx}] = 0x{val:08x}")
    # Identify source registers from ib (heuristic: ib[1..3] are likely operand reg indices)
    # Print state of those source registers BEFORE this op
    before = states[last - 1] if last > 0 else {}
    for src_idx in ib[1:]:
        if src_idx in before:
            print(f"{indent}  reg[{src_idx}] before = 0x{before[src_idx]:08x}")

# X_b1_init[2] = 0xfc57448f built into reg[6] at step 7132
# Let's trace back the sources
print("=== Tracing X_b1_init[2] byte 0 (0xfc) source ===")
print(f"At step 7038: reg[16] = 0x{states[7037].get(16, 0):08x} (this is 0xfc, the source byte)")
print()
trace_back(16, 7037, max_depth=5)
print()

print("=== Tracing X_b1_init[2] byte 1 (0x57) source ===")
print(f"At step 7112 (op 0x2 ib=[2,0,16,0]): reg[16] before = 0x{states[7111].get(16, 0):08x}")
print()
trace_back(16, 7111, max_depth=5)
print()

print("=== Tracing X_b1_init[2] byte 2 (0x44) source — step 7126 reads reg[15] ===")
print(f"reg[15] before step 7126 = 0x{states[7125].get(15, 0):08x}")
trace_back(15, 7125, max_depth=5)
print()

print("=== Tracing X_b1_init[2] byte 3 (0x8f) source — step 7132 reads reg[12] = 0x4e (mem) and reg[17]=2 ===")
# This is the mem-load opcode. We need to know what memory at 0x4e+offset contains.
# Let's see when reg[12] was set to 0x4e
print(f"reg[12] before step 7132 = 0x{states[7131].get(12, 0):08x}")
trace_back(12, 7131, max_depth=5)
print()

print("=== Tracing reg[16] source at step 7113 (after the byte 0x57 was loaded) ===")
print("Specifically: reg[16] was written at some step before 7113 to value 0x57. Trace it.")
last = find_last_write(16, 7112)
if last is not None:
    s, op, pc, diff, ib = trace[last]
    print(f"  step={last} op={op:#x} ib={ib} -> reg[16] = 0x{diff[str(16)] & MASK:08x}")

# Find the chain of reg[16] writes near the X_b1 build window
print("\n=== All writes to reg[16] in steps 6800-7140 ===")
for i in range(6800, 7140):
    if str(16) in trace[i][3]:
        s, op, pc, diff, ib = trace[i]
        print(f"  step={i} op={op:#x} ib={ib} -> reg[16] = 0x{diff[str(16)] & MASK:08x}")
