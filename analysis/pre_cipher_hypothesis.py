#!/usr/bin/env python3
"""Test hypothesis: X_b1_init[1..3] + X_b2[1] = 4 u32 outputs of the SAME cipher_forward
run on MD5(src) (or derivative) with known round keys.

If the pre-cipher is the same SM4-like with RK_B1 keys, the 4 variable outputs should
appear as some slots in the 36-entry output. 4 slots out of 36 C(36, 4) = 58905 combos —
but the natural slots would be the last 4 (32,33,34,35) or byte-combinations.

Try multiple input formulations and see if ANY produces matching outputs.
"""
import sys, json, hashlib
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher

XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

# Load 256 samples
samples = json.load(open('/tmp/xb_samples.json'))

# For each sample, build candidate cipher inputs:
#   (a) MD5(src) as 4 u32 BE
#   (b) MD5(src) as 4 u32 LE
#   (c) MD5(src) ^ XOR_STREAM[0:16] as 4 u32 BE
#   (d) same as (c) LE
# Run cipher_forward with RK_B1 and RK_B2. Check if any slot matches X_b1_init[2] (fully variable)
# AND X_b2[1] (fully variable).

def try_input(input_u32, rk, label):
    matches = []
    mismatches = 0
    for s in samples:
        src_bytes = bytes.fromhex(s['src'])
        md5 = hashlib.md5(src_bytes).digest()
        # Rebuild input for this sample
        inp = input_u32(md5, bytes.fromhex(s['src']))
        try:
            state = pure_cipher.cipher_forward(inp, rk)
        except Exception:
            mismatches += 1
            continue
        x2_1 = int(s['xb2'][1], 16)
        x1_2 = int(s['xb1'][2], 16)
        # Find positions in state where x1_2 and x2_1 appear
        positions_12 = [i for i, v in enumerate(state) if v == x1_2]
        positions_21 = [i for i, v in enumerate(state) if v == x2_1]
        matches.append((s['src'], positions_12, positions_21))
    # Print first 10 + summary
    print(f"\n=== {label} (rk={'RK_B1' if rk is pure_cipher.RK_B1 else 'RK_B2'}) ===")
    for m in matches[:10]:
        print(f"  src={m[0]}: X_b1[2] at positions {m[1]}, X_b2[1] at positions {m[2]}")

# Build inputs
def input_md5_be(md5, src):
    return [int.from_bytes(md5[i:i+4], 'big') for i in range(0, 16, 4)]

def input_md5_le(md5, src):
    return [int.from_bytes(md5[i:i+4], 'little') for i in range(0, 16, 4)]

def input_post_xor_be(md5, src):
    p = bytes(a ^ b for a, b in zip(md5, XOR_STREAM[:16]))
    return [int.from_bytes(p[i:i+4], 'big') for i in range(0, 16, 4)]

def input_post_xor_le(md5, src):
    p = bytes(a ^ b for a, b in zip(md5, XOR_STREAM[:16]))
    return [int.from_bytes(p[i:i+4], 'little') for i in range(0, 16, 4)]

for rk, rk_label in [(pure_cipher.RK_B1, 'RK_B1'), (pure_cipher.RK_B2, 'RK_B2')]:
    try_input(input_md5_be, rk, "MD5(src) BE")
    try_input(input_md5_le, rk, "MD5(src) LE")
    try_input(input_post_xor_be, rk, "(MD5 ^ XOR) BE")
    try_input(input_post_xor_le, rk, "(MD5 ^ XOR) LE")

# More targeted: for src=00, check if any combination of cipher_forward outputs
# EQUALS 0xfc57448f (X_b1_init[2]). With just 256 samples and 4 different inputs,
# if none match, the pre-cipher uses a different input or different keys.
s0 = samples[0]
md5_0 = hashlib.md5(bytes.fromhex(s0['src'])).digest()
target_x1_2 = int(s0['xb1'][2], 16)
target_x2_1 = int(s0['xb2'][1], 16)
print(f"\n=== For src=00: look for {target_x1_2:08x} in any cipher state ===")
for input_fn, label in [(input_md5_be, "MD5 BE"), (input_md5_le, "MD5 LE"),
                         (input_post_xor_be, "post-XOR BE"), (input_post_xor_le, "post-XOR LE")]:
    for rk, rk_label in [(pure_cipher.RK_B1, 'RK_B1'), (pure_cipher.RK_B2, 'RK_B2')]:
        inp = input_fn(md5_0, bytes.fromhex(s0['src']))
        state = pure_cipher.cipher_forward(inp, rk)
        hits_12 = [i for i, v in enumerate(state) if v == target_x1_2]
        hits_21 = [i for i, v in enumerate(state) if v == target_x2_1]
        if hits_12 or hits_21:
            print(f"  {label}/{rk_label}: X_b1[2] at {hits_12}, X_b2[1] at {hits_21}")

# If still no hits, maybe the pre-cipher uses a DIFFERENT set of round keys
# (cmd-specific). Try various input/key combos with cipher_backward too.
