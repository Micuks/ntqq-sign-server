#!/usr/bin/env python3
"""Verify derive_x_b2_from_block1 against 256 samples. Also characterize X_b2_init[1].

If X_b2[0,2,3] = deterministic function of X_b1_final, we only need to figure out:
  1. How to compute X_b1_init from MD5(src) + cmd constants
  2. How to compute X_b2_init[1] from inputs
"""
import sys, json
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher

samples = json.load(open('/tmp/xb_samples.json'))
print(f"Loaded {len(samples)} samples")

# For each sample, run cipher forward on X_b1_init to get X_b1[32..35]
# Compare X_b2[0,2,3] to (X_b1[35] ^ C_B1[35], X_b1[33] ^ C_B1[33], X_b1[32] ^ C_B1[32])
C_B1 = pure_cipher.C_B1
mismatch0 = mismatch2 = mismatch3 = 0
xb2_1_vals = []
for s in samples:
    x1 = [int(v, 16) for v in s['xb1']]
    x2 = [int(v, 16) for v in s['xb2']]
    x1_full = pure_cipher.cipher_forward(x1, pure_cipher.RK_B1)
    expected_0 = (x1_full[35] ^ C_B1[35]) & 0xFFFFFFFF
    expected_2 = (x1_full[33] ^ C_B1[33]) & 0xFFFFFFFF
    expected_3 = (x1_full[32] ^ C_B1[32]) & 0xFFFFFFFF
    if x2[0] != expected_0: mismatch0 += 1
    if x2[2] != expected_2: mismatch2 += 1
    if x2[3] != expected_3: mismatch3 += 1
    xb2_1_vals.append((s['src'], s['md5'], x2[1], x1_full[34]))

print(f"X_b2[0] = X_b1[35]^C_B1[35]: mismatches={mismatch0}/{len(samples)}")
print(f"X_b2[2] = X_b1[33]^C_B1[33]: mismatches={mismatch2}/{len(samples)}")
print(f"X_b2[3] = X_b1[32]^C_B1[32]: mismatches={mismatch3}/{len(samples)}")

# Characterize X_b2[1]: is it a function of x1_full[34]? Or of MD5(src)?
# Check if X_b2[1] == X_b1[34] ^ some constant
delta_34 = set()
for _, _, x2_1, x1_34 in xb2_1_vals:
    delta_34.add(x1_34 ^ x2_1)
print(f"\nX_b2[1] ^ X_b1[34] distinct values: {len(delta_34)}")
if len(delta_34) == 1:
    print(f"  X_b2[1] = X_b1[34] ^ 0x{list(delta_34)[0]:08x}")

# Also check pairwise delta relative to src=00
base_x2_1 = next(v[2] for v in xb2_1_vals if v[0] == '00')
base_x1_34 = next(v[3] for v in xb2_1_vals if v[0] == '00')
# Is X_b2[1] simply X_b1[34] modified somehow?
# Print first few to inspect
print("\nFirst 10 samples (src, X_b2[1], X_b1_final[34]):")
for src, md5, x2_1, x1_34 in xb2_1_vals[:10]:
    print(f"  src={src} md5={md5[:8]}... X_b2[1]={x2_1:08x}  X_b1_final[34]={x1_34:08x}  xor={x2_1^x1_34:08x}")
