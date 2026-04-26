#!/usr/bin/env python3
"""Deep brute-force on pre-cipher hypotheses.

For each combination of:
  - Input transformation (MD5, post-XOR, ROT-shifted, byte-reversed, etc.)
  - Round key set (RK_B1, RK_B2, REVERSED, identity-zero, RK_B1 ^ const)
  - Output extraction (state[k], state[k] XOR const, permute(state[k]), etc.)

Check if any combination produces X_b1_init[2] across many samples.

If a match is found, we have the pre-cipher formula.
"""
import json, hashlib, sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher

XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')
samples = json.load(open('/tmp/xb_samples_large.json'))
N = 50  # quick test on 50 samples


def md5_bytes(s): return bytes.fromhex(s['md5'])
def post_xor(s): return bytes(a^b for a,b in zip(md5_bytes(s), XOR_STREAM[:16]))


def to_u32_be(b): return [int.from_bytes(b[i:i+4], 'big') for i in range(0, len(b), 4)][:4]
def to_u32_le(b): return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)][:4]


# Input transformations
input_funcs = [
    ('md5_be', lambda s: to_u32_be(md5_bytes(s))),
    ('md5_le', lambda s: to_u32_le(md5_bytes(s))),
    ('post_be', lambda s: to_u32_be(post_xor(s))),
    ('post_le', lambda s: to_u32_le(post_xor(s))),
    ('md5_rev_be', lambda s: to_u32_be(md5_bytes(s)[::-1])),
    ('md5_rev_le', lambda s: to_u32_le(md5_bytes(s)[::-1])),
    ('md5_rot_be', lambda s: to_u32_be(md5_bytes(s)[8:] + md5_bytes(s)[:8])),
]


# Round key sets
rk_sets = [
    ('RK_B1', pure_cipher.RK_B1),
    ('RK_B2', pure_cipher.RK_B2),
    ('RK_B1_rev', pure_cipher.RK_B1[::-1]),
    ('RK_B2_rev', pure_cipher.RK_B2[::-1]),
    ('zeros', [0] * 32),
    ('RK_B1_xor_const', [k ^ 0x114D0B11 for k in pure_cipher.RK_B1]),
    ('RK_B1_xor_818b', [k ^ 0x818B for k in pure_cipher.RK_B1]),
]


# For each (input_fn, rk), compute state per sample. Extract each u32 and
# check if it matches X_b1_init[2] across N samples.
target_x1_2 = [int(s['xb1'][2], 16) for s in samples[:N]]
target_x2_1 = [int(s['xb2'][1], 16) for s in samples[:N]]

def check_match(extract_fn, label):
    """extract_fn(state) -> u32. Check if extract_fn matches X_b1_init[2] for all samples."""
    for input_label, input_fn in input_funcs:
        for rk_label, rk in rk_sets:
            ok_x1_2 = True
            ok_x2_1 = True
            for i, s in enumerate(samples[:N]):
                state = pure_cipher.cipher_forward(input_fn(s), rk)
                v = extract_fn(state)
                if v != target_x1_2[i]: ok_x1_2 = False
                if v != target_x2_1[i]: ok_x2_1 = False
                if not ok_x1_2 and not ok_x2_1: break
            if ok_x1_2:
                print(f"  HIT X_b1[2]: input={input_label} rk={rk_label} extract={label}")
            if ok_x2_1:
                print(f"  HIT X_b2[1]: input={input_label} rk={rk_label} extract={label}")

# Try every possible state slot extraction
print("=== Checking each state[k] for X_b1[2] / X_b2[1] ===")
for k in range(36):
    check_match(lambda state, k=k: state[k], f"state[{k}]")

# Also try state[k] XOR various constants
print("\n=== Checking state[k] XOR rk[0..7] ===")
for k in range(36):
    for c_idx in range(min(32, len(pure_cipher.RK_B1))):
        c = pure_cipher.RK_B1[c_idx]
        check_match(lambda state, k=k, c=c: state[k] ^ c, f"state[{k}] ^ RK_B1[{c_idx}]")

# Also try permutations of state[k]
print("\n=== Checking permute(state[k]) ===")
for k in range(36):
    check_match(lambda state, k=k: pure_cipher.permute_word(state[k]), f"permute(state[{k}])")

# Also try sbox_word(state[k])
print("\n=== Checking sbox_word(state[k]) ===")
for k in range(36):
    check_match(lambda state, k=k: pure_cipher.sbox_word(state[k]), f"sbox_word(state[{k}])")

print("\nIf no HITs above, pre-cipher uses a different structure entirely.")
