#!/usr/bin/env python3
"""Exhaustive search for a simple relation between X_b2[1] and cipher_forward state
(or cipher_forward of another input).

Try:
  1. X_b2[1] = X_b1_full[k] ^ const for k in 0..35
  2. X_b2[1] = X_b1_init[k] ^ X_b1_full[k'] ^ const for k, k' in 0..35 (too many — skip)
  3. X_b2[1] = permute_word(X_b1_full[k]) ^ const
"""
import sys, json
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher

samples = json.load(open('/tmp/xb_samples.json'))
# Precompute x_b1_full for all samples
data = []
for s in samples:
    x1 = [int(v, 16) for v in s['xb1']]
    x2_1 = int(s['xb2'][1], 16)
    x1_full = pure_cipher.cipher_forward(x1, pure_cipher.RK_B1)
    data.append((s['src'], x1_full, x2_1))

print("=== X_b2[1] = X_b1_full[k] ^ const ===")
for k in range(36):
    deltas = set()
    for src, x1_full, x2_1 in data:
        deltas.add(x1_full[k] ^ x2_1)
    if len(deltas) == 1:
        print(f"  k={k}: const = 0x{list(deltas)[0]:08x}")

print("\n=== X_b2[1] = permute_word(X_b1_full[k]) ^ const ===")
for k in range(36):
    deltas = set()
    for src, x1_full, x2_1 in data:
        deltas.add(pure_cipher.permute_word(x1_full[k]) ^ x2_1)
    if len(deltas) == 1:
        print(f"  k={k}: const = 0x{list(deltas)[0]:08x}")

print("\n=== X_b2[1] = sbox_word(X_b1_full[k]) ^ const ===")
for k in range(36):
    deltas = set()
    for src, x1_full, x2_1 in data:
        deltas.add(pure_cipher.sbox_word(x1_full[k]) ^ x2_1)
    if len(deltas) == 1:
        print(f"  k={k}: const = 0x{list(deltas)[0]:08x}")

print("\n=== X_b2[1] = L(X_b1_full[k]) ^ const ===")
for k in range(36):
    deltas = set()
    for src, x1_full, x2_1 in data:
        deltas.add(pure_cipher.L(x1_full[k]) ^ x2_1)
    if len(deltas) == 1:
        print(f"  k={k}: const = 0x{list(deltas)[0]:08x}")

print("\n=== X_b2[1] = L(sbox_word(X_b1_full[k])) ^ const ===")
for k in range(36):
    deltas = set()
    for src, x1_full, x2_1 in data:
        deltas.add(pure_cipher.L(pure_cipher.sbox_word(x1_full[k])) ^ x2_1)
    if len(deltas) == 1:
        print(f"  k={k}: const = 0x{list(deltas)[0]:08x}")

# Hunt 2: check if X_b2[1] ^ X_b1_full[k] has a pattern that could be rk + linear
# For k=34 (the one with low byte=0xC9 invariant):
print("\n=== Details for X_b2[1] ^ X_b1_full[34] (low byte always 0xC9) ===")
hi24_list = []
for src, x1_full, x2_1 in data:
    delta = x1_full[34] ^ x2_1
    hi24 = (delta >> 8) & 0xFFFFFF
    hi24_list.append((src, hi24, x1_full[34], x2_1))
# Show first 5
for i in range(5):
    src, hi24, x1_34, x2_1 = hi24_list[i]
    print(f"  src={src}: hi24=0x{hi24:06x} X_b1_full[34]=0x{x1_34:08x} X_b2[1]=0x{x2_1:08x}")

# Check if hi24 = f(X_b1_full[some_other_k])
print("\n=== Is (X_b2[1] ^ X_b1_full[34]) >> 8 a function of X_b1_full[k]? ===")
for k in range(36):
    group = {}
    consistent = True
    for src, x1_full, x2_1 in data:
        key = x1_full[k] & 0xFFFFFF  # try low 24 bits
        hi24 = ((x1_full[34] ^ x2_1) >> 8) & 0xFFFFFF
        if key in group and group[key] != hi24:
            consistent = False
            break
        group[key] = hi24
    if consistent and len(group) > 100:  # sufficient entropy
        print(f"  k={k}: consistent with {len(group)} groups")
