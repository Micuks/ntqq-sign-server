#!/usr/bin/env python3
"""Identify what produces the XOR constant stream 0x55, 0x05, 0x04, 0xa2, ..."""
import json, hashlib, struct

MASK = 0xFFFFFFFF
def u32(v): return v & MASK

trace = json.load(open('/tmp/complete_trace_00.json'))

# Reconstruct states
regs = {}
states = [dict(regs)]
for entry in trace:
    _, _, _, diff, _ = entry
    for k, v in diff.items():
        regs[int(k)] = u32(v)
    states.append(dict(regs))

# Collect all 20 MD5 read XOR amounts (ops 0x16 ib=[22,119,129,0])
xor_amts = []
for i, entry in enumerate(trace):
    step, op, pc, diff, ib = entry
    if op == 0x16 and tuple(ib) == (22, 119, 129, 0):
        r7_before = states[i].get(7)
        r7_after = u32(diff.get('7', 0))
        if r7_before is not None:
            xor_amts.append(r7_before ^ r7_after)

print(f"Total op 0x16 ib=[22,119,129,0] calls: {len(xor_amts)}")
print(f"XOR amounts: {[hex(x) for x in xor_amts]}")
print(f"As bytes: {bytes(xor_amts).hex()}")

# Look at MD5/SHA of various candidates
candidates = [
    b"wtlogin.login",
    b"wtlogin.login\x00",
    b"wtlogin.login\x01",
    b"wtlogin.login\x00\x00\x00\x01",
    struct.pack('>I', 1) + b"wtlogin.login",
    b"\x0dwtlogin.login",
    b"\x0dwtlogin.login\x01",
    b"\x0dwtlogin.login\x00\x00\x00\x01",
    b"com.tencent.qq",
    b"SSO_LOGIN",
    b"ntqq",
]

target_bytes = bytes(xor_amts)[:16]
print(f"\nTarget first 16 XOR bytes: {target_bytes.hex()}")

for c in candidates:
    m = hashlib.md5(c).digest()
    s = hashlib.sha1(c).digest()
    print(f"  MD5({c!r}) = {m.hex()} ({'MATCH' if m[:len(target_bytes)]==target_bytes else '-'})")
    # Also check 16 bytes anywhere
    if target_bytes in m:
        print(f"    target found at MD5 offset {m.find(target_bytes)}")
    if target_bytes in s:
        print(f"    target found at SHA1 offset {s.find(target_bytes)}")

# Also check with 20 bytes (the full xor_amts)
target_full = bytes(xor_amts)
print(f"\nFull {len(target_full)} bytes of XOR: {target_full.hex()}")
for c in candidates:
    m = hashlib.md5(c).digest()
    if target_full[:16] == m:
        print(f"  FOUND: MD5({c!r}) matches first 16 XOR bytes")
        break

# What about MD5 of itself iteratively? (common hash construction)
print("\n=== Iterative MD5 test ===")
seed_candidates = [b"wtlogin.login", b"wtlogin.login\x00"]
for sc in seed_candidates:
    h = hashlib.md5(sc).digest()
    # Check if xor_amts = MD5(h) or iterated
    print(f"  MD5(MD5({sc!r})) = {hashlib.md5(h).hexdigest()}")
    print(f"    match: {hashlib.md5(h).digest()[:16] == target_bytes}")
