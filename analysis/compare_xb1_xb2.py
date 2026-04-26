#!/usr/bin/env python3
"""For each of 4 traces, recover X_b1_init + X_b2_init from the trace's
final sign bytes, and print them side by side. Also print the 20 post-XOR
r7_after bytes (= MD5(src)^xor_stream || xor_stream[16..19]).

Goal: see which bits of X_b1_init and X_b2_init are input-dependent and
how they map to the 20 post-XOR bytes.
"""
import json, sys, os
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher
import hashlib

MASK = 0xFFFFFFFF
XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

def reconstruct(trace):
    regs = {}
    states = []
    for entry in trace:
        _, _, _, diff, _ = entry
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        states.append(dict(regs))
    return states

# The 4 traces have input bytes 00, 01, 02, ff — but we don't have their sign outputs directly.
# We DO have the final VM state — but sign is 32 bytes read from register array (in specific slots).
# Let's compute MD5 of each src + XOR stream to get the "cipher input" 20 bytes.
for name in ['00','01','02','ff']:
    src = bytes([int(name, 16)])
    md5 = hashlib.md5(src).digest()
    xor20 = bytes(a ^ b for a, b in zip(md5 + b'\x00\x00\x00\x00', XOR_STREAM))
    xor20 = bytes(a ^ b for a, b in zip(md5, XOR_STREAM[:16])) + XOR_STREAM[16:20]
    print(f"src={name}: MD5={md5.hex()}")
    print(f"         XOR={xor20.hex()}")

# Now pull the r7_after values directly from traces to confirm
print("\n=== r7_after across 4 traces (the 20 post-XOR bytes) ===")
traces = {n: json.load(open(f'/tmp/complete_trace_{n}.json')) for n in ['00','01','02','ff']}
states = {n: reconstruct(t) for n, t in traces.items()}
key_steps = [i for i, e in enumerate(traces['00']) if e[1] == 0x16 and tuple(e[4]) == (22,119,129,0)]
assert len(key_steps) == 20
for name in ['00','01','02','ff']:
    b = bytes(states[name][ks].get(7, 0) & 0xFF for ks in key_steps)
    print(f"  {name}: {b.hex()}")

# Now let's print what X_b1_init looks like for each input, by computing MD5(src) XOR xor_stream
# and checking if it matches any of the known cmd=wtlogin.login constants.
print("\n=== Compute expected 20-byte 'cipher input' and compare to X_b1_init invariants ===")
print("Known X_b1_init invariants for wtlogin.login:")
print("  X_b1[0] = 0x114D0B11 (full const)")
print("  X_b1[1] & 0xFFFF = 0x818B")
print("  X_b1[3] >> 8 = 0x011D06")

# Try simple packings of the 20-byte XOR output to X_b1_init[0..3]
for name in ['00','01','02','ff']:
    b = bytes(states[name][ks].get(7, 0) & 0xFF for ks in key_steps)
    le = [int.from_bytes(b[i:i+4], 'little') for i in range(0, 16, 4)]
    be = [int.from_bytes(b[i:i+4], 'big') for i in range(0, 16, 4)]
    print(f"\n  src={name} 20 bytes = {b.hex()}")
    print(f"    LE u32: {[hex(x) for x in le]}")
    print(f"    BE u32: {[hex(x) for x in be]}")
