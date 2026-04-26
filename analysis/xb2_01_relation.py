#!/usr/bin/env python3
"""Characterize the X_b2[0] and X_b2[1] relations to X_b1_full.

Findings we're verifying:
  - X_b2[2] = X_b1[33] ^ C_B1[33]  (verified on 256 samples)
  - X_b2[3] = X_b1[32] ^ C_B1[32]  (verified on 256 samples)
  - X_b2[1] ^ X_b1[34] low byte is always 0xC9 — maybe there's a byte permutation

Let me explore:
  (a) X_b2[0] vs X_b1[35]: compute delta; is there a pattern?
  (b) X_b2[1] vs X_b1[34]: check if it's a byte-permute + XOR const
"""
import sys, json
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher
C_B1 = pure_cipher.C_B1

samples = json.load(open('/tmp/xb_samples.json'))

# Compute X_b1_full for each sample
cached = []
for s in samples:
    x1 = [int(v, 16) for v in s['xb1']]
    x2 = [int(v, 16) for v in s['xb2']]
    x1_full = pure_cipher.cipher_forward(x1, pure_cipher.RK_B1)
    cached.append((s['src'], x1_full[32], x1_full[33], x1_full[34], x1_full[35], x2[0], x2[1], x2[2], x2[3]))

# (a) X_b2[0] vs X_b1[35]: try all 24 byte-permutations + offset XOR
def permute(w, p):
    b = [(w >> (8*(3-i))) & 0xFF for i in range(4)]
    return (b[p[0]] << 24) | (b[p[1]] << 16) | (b[p[2]] << 8) | b[p[3]]

from itertools import permutations
# Try: X_b2[0] = permute(X_b1[35], p) ^ constant
print("=== X_b2[0] vs X_b1[35] ===")
# Compute delta for each sample, see if byte-delta pattern is consistent
deltas_raw = [x2_0 ^ x1_35 for _, _, _, _, x1_35, x2_0, _, _, _ in cached]
bytewise = [tuple((d >> (8*(3-i))) & 0xFF for i in range(4)) for d in deltas_raw]
from collections import Counter
cnt = Counter(bytewise)
print(f"Top 5 XOR patterns (out of {len(cnt)} distinct): {cnt.most_common(5)}")

# Also check byte-permutation hypothesis
for p in permutations(range(4)):
    ok_count = 0
    xors = set()
    for _, _, _, _, x1_35, x2_0, _, _, _ in cached:
        xors.add(permute(x1_35, p) ^ x2_0)
    if len(xors) == 1:
        print(f"  X_b2[0] = permute(X_b1[35], {p}) ^ 0x{list(xors)[0]:08x}  (BIJECTION)")

# (b) Same for X_b2[1] vs X_b1[34]
print("\n=== X_b2[1] vs X_b1[34] ===")
deltas_raw = [x2_1 ^ x1_34 for _, _, _, x1_34, _, _, x2_1, _, _ in cached]
bytewise = [tuple((d >> (8*(3-i))) & 0xFF for i in range(4)) for d in deltas_raw]
cnt = Counter(bytewise)
# Is low byte always 0xc9?
lows = Counter(t[3] for t in bytewise)
print(f"Low byte of delta: {lows.most_common(5)}")
for p in permutations(range(4)):
    xors = set()
    for _, _, _, x1_34, _, _, x2_1, _, _ in cached:
        xors.add(permute(x1_34, p) ^ x2_1)
    if len(xors) == 1:
        print(f"  X_b2[1] = permute(X_b1[34], {p}) ^ 0x{list(xors)[0]:08x}  (BIJECTION)")

# Try a different thing for X_b2[0]: maybe X_b2[0] = X_b1[35] with some byte swapped
# e.g., maybe byte permutation similar to emit_block_bytes
# Also try: X_b2[0] ^ C_B1[X] for various X
print("\n=== X_b2[0] vs X_b1[35] ^ C_B1[X] for X=0..35 ===")
for x_idx in range(36):
    c = C_B1.get(x_idx, None)
    if c is None: continue
    xors = set()
    for _, _, _, _, x1_35, x2_0, _, _, _ in cached:
        xors.add(x1_35 ^ c ^ x2_0)
    if len(xors) == 1:
        print(f"  X_b2[0] = X_b1[35] ^ C_B1[{x_idx}=0x{c:08x}] ^ 0x{list(xors)[0]:08x}")

# Maybe X_b2[0] involves X_b1_full[34] or X_b1_full[33], etc.
print("\n=== Try X_b2[0] = X_b1_full[k] ^ const, k=30..35 ===")
# Need all of x1_full. Let's rebuild with more slots.
for s_idx, s in enumerate(samples[:10]):
    x1 = [int(v, 16) for v in s['xb1']]
    x1_full = pure_cipher.cipher_forward(x1, pure_cipher.RK_B1)
    x2 = [int(v, 16) for v in s['xb2']]
    print(f"  src={s['src']} X_b2[0]={x2[0]:08x} X_b1_full[32..35]={[hex(x) for x in x1_full[32:36]]}")
