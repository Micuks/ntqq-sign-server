#!/usr/bin/env python3
"""Test whether cipher_forward applied to MD5(src) (or post-XOR(src)) produces the
variable bytes of X_b1_init or X_b2[1] AT ANY BYTE POSITION of the 36-u32 output.

If found, we have the formula for the pre-cipher's input + key schedule.
"""
import json, hashlib, sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher

XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

samples = json.load(open('/tmp/xb_samples_large.json'))
print(f"Loaded {len(samples)} samples")

def state_bytes(state):
    """Convert 36-u32 state to 144 bytes (BE)."""
    out = bytearray()
    for w in state:
        out.extend(w.to_bytes(4, 'big'))
    return bytes(out)

# For each sample, compute multiple cipher runs and check if X_b1[3] low byte
# (=0x87 for src=00) appears at SOME byte position
input_funcs = []
def f_md5_be(md5):
    return [int.from_bytes(md5[i:i+4], 'big') for i in range(0, 16, 4)]
def f_md5_le(md5):
    return [int.from_bytes(md5[i:i+4], 'little') for i in range(0, 16, 4)]
def f_post_be(md5):
    p = bytes(a ^ b for a, b in zip(md5, XOR_STREAM[:16]))
    return [int.from_bytes(p[i:i+4], 'big') for i in range(0, 16, 4)]
def f_post_le(md5):
    p = bytes(a ^ b for a, b in zip(md5, XOR_STREAM[:16]))
    return [int.from_bytes(p[i:i+4], 'little') for i in range(0, 16, 4)]
input_funcs.append(('MD5 BE', f_md5_be))
input_funcs.append(('MD5 LE', f_md5_le))
input_funcs.append(('post-XOR BE', f_post_be))
input_funcs.append(('post-XOR LE', f_post_le))

# For each (input_fn, rk), check if there's a stable byte position k such that
# state_bytes(cipher(input))[k] == X_b1[3] & 0xFF for ALL samples.
# If yes, that byte position is the "source" of X_b1[3] low byte.

# We test for X_b1[3] low byte first (single byte; easy to test).
def test_single_byte(target_extract, label):
    """target_extract: function(sample) -> int target byte (0..255)"""
    print(f"\n=== Searching for byte position that produces {label} ===")
    n_test = min(200, len(samples))  # use first 200 samples for speed
    for input_label, input_fn in input_funcs:
        for rk_label, rk in [('RK_B1', pure_cipher.RK_B1), ('RK_B2', pure_cipher.RK_B2)]:
            # Compute cipher state for first sample
            md5 = bytes.fromhex(samples[0]['md5'])
            state = pure_cipher.cipher_forward(input_fn(md5), rk)
            state_b = state_bytes(state)
            target0 = target_extract(samples[0])
            candidates = [k for k, b in enumerate(state_b) if b == target0]
            if not candidates:
                continue
            # Verify across samples
            for k in candidates:
                ok = True
                for s in samples[1:n_test]:
                    md5 = bytes.fromhex(s['md5'])
                    state = pure_cipher.cipher_forward(input_fn(md5), rk)
                    if state_bytes(state)[k] != target_extract(s):
                        ok = False
                        break
                if ok:
                    print(f"  FOUND: input={input_label} rk={rk_label} byte_position={k} (state_word={k//4} byte_in_word={k%4})")

test_single_byte(lambda s: int(s['xb1'][3], 16) & 0xFF, "X_b1[3] low byte")
test_single_byte(lambda s: (int(s['xb1'][2], 16) >> 24) & 0xFF, "X_b1[2] byte 0 (MSB)")
test_single_byte(lambda s: (int(s['xb1'][2], 16) >> 16) & 0xFF, "X_b1[2] byte 1")
test_single_byte(lambda s: (int(s['xb1'][2], 16) >> 8) & 0xFF, "X_b1[2] byte 2")
test_single_byte(lambda s: int(s['xb1'][2], 16) & 0xFF, "X_b1[2] byte 3 (LSB)")
test_single_byte(lambda s: (int(s['xb1'][1], 16) >> 24) & 0xFF, "X_b1[1] byte 0 (MSB)")
test_single_byte(lambda s: (int(s['xb1'][1], 16) >> 16) & 0xFF, "X_b1[1] byte 1")
test_single_byte(lambda s: (int(s['xb2'][1], 16) >> 24) & 0xFF, "X_b2[1] byte 0")
test_single_byte(lambda s: (int(s['xb2'][1], 16) >> 16) & 0xFF, "X_b2[1] byte 1")
test_single_byte(lambda s: (int(s['xb2'][1], 16) >> 8) & 0xFF, "X_b2[1] byte 2")
test_single_byte(lambda s: int(s['xb2'][1], 16) & 0xFF, "X_b2[1] byte 3")
