#!/usr/bin/env python3
"""For each of the 20 op 0x16 ib=[22,119,129,0] calls, show:
  - step#, pc offset
  - r7 BEFORE (pre-XOR input)
  - r7 AFTER  (post-XOR output)
  - delta = before XOR after

If r7_before changes with src across 4 traces, the XORed thing is input-derived.
If r7_before is constant, then the XOR is mixing a constant with a constant
(which tells us the cipher INPUT is fully pre-computable).

Also dump the r7_after values — those are the actual cipher-input bytes,
which should match MD5(src) ^ XOR_stream or similar.
"""
import json
MASK = 0xFFFFFFFF

def reconstruct(trace):
    regs = {}
    states = []
    for entry in trace:
        _, _, _, diff, _ = entry
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        states.append(dict(regs))
    return states

traces = {name: json.load(open(f'/tmp/complete_trace_{name}.json')) for name in ['00','01','02','ff']}
states = {name: reconstruct(t) for name, t in traces.items()}

# Find the 20 positions of op 0x16 ib=[22,119,129,0]
key_steps = []
for i, e in enumerate(traces['00']):
    step, op, pc, diff, ib = e
    if op == 0x16 and tuple(ib) == (22, 119, 129, 0):
        key_steps.append(i)
print(f"Found {len(key_steps)} key ops at indices {key_steps[:5]}..{key_steps[-5:]}")

print(f"\n{'step':>5} {'pcOff':>6} {'r7_before[00,01,02,ff]':<50} {'r7_after[00,01,02,ff]':<50} delta(const?)")
for ks in key_steps:
    e = traces['00'][ks]
    step, op, pc, diff, ib = e
    befores = []
    afters = []
    for name in ['00','01','02','ff']:
        st_before = states[name][ks-1] if ks > 0 else {}
        st_after = states[name][ks]
        befores.append(st_before.get(7, 0))
        afters.append(st_after.get(7, 0))
    b_str = ','.join(f'{b:08x}' for b in befores)
    a_str = ','.join(f'{a:08x}' for a in afters)
    delta = befores[0] ^ afters[0]
    all_same_delta = all(befores[i] ^ afters[i] == delta for i in range(4))
    tag = '' if all_same_delta else '!!'
    print(f"{ks:>5} {pc:>6} {b_str:<50} {a_str:<50} {delta:08x} {tag}")

# Check if r7_before equals MD5(src)[i*?] for small-input traces
print("\n=== Check r7_before vs MD5(src) ===")
import hashlib
for name in ['00','01','ff']:
    src_byte = int(name, 16)
    md5 = hashlib.md5(bytes([src_byte])).digest()
    md5_u32_le = [int.from_bytes(md5[i:i+4], 'little') for i in range(0, 16, 4)]
    md5_u32_be = [int.from_bytes(md5[i:i+4], 'big') for i in range(0, 16, 4)]
    r7_before = [states[name][ks-1].get(7, 0) for ks in key_steps]
    print(f"src={name}: r7_before first 4 = {[hex(x) for x in r7_before[:4]]}")
    print(f"         MD5(src) LE u32 = {[hex(x) for x in md5_u32_le]}")
    print(f"         MD5(src) BE u32 = {[hex(x) for x in md5_u32_be]}")
    print(f"         MD5(src) bytes  = {md5.hex()}")
