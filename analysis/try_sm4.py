#!/usr/bin/env python3
"""Test if X_b1_init derivation uses standard SM4 with cmd-derived master key.

Standard SM4:
  - MK = master key (4 u32)
  - K[i] = MK[i] ^ FK[i]
  - K[i+4] = K[i] ^ T'(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])
  - rk[i] = K[i+4]
  - T'(x) = L'(sbox_word(x))
  - L'(x) = x ^ rotl(x,13) ^ rotl(x,23)  [DIFFERENT from our cipher's L]

Then cipher_forward applied to MD5(src) might yield X_b1_init.
"""
import sys, hashlib, json
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher
MASK = 0xFFFFFFFF
def rotl(x, n): return ((x << n) | (x >> (32-n))) & MASK


# Standard SM4 constants (from spec)
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK_BYTES = [(i*7) & 0xff for i in range(128)]
CK = [int.from_bytes(bytes(CK_BYTES[i*4:i*4+4]), 'big') for i in range(32)]


def L_prime(x):
    """SM4 key schedule's L' function."""
    return (x ^ rotl(x, 13) ^ rotl(x, 23)) & MASK


def sm4_key_schedule(MK):
    """Standard SM4 key expansion. MK = 4 u32. Returns 32 rk."""
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        T = pure_cipher.sbox_word(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])
        K_next = K[i] ^ L_prime(T)
        K.append(K_next & MASK)
        rk.append(K[i+4])
    return rk


# Try cipher_forward(MD5(src), sm4_key_schedule(MK)) where MK = MD5(cmd) or other
samples = json.load(open('/tmp/xb_samples_large.json'))[:100]


def md5_to_u32_be(b):
    return [int.from_bytes(b[i:i+4], 'big') for i in range(0, 16, 4)]
def md5_to_u32_le(b):
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, 16, 4)]


# Try various MK candidates
mk_candidates = [
    ('MD5(wtlogin.login)_BE', md5_to_u32_be(hashlib.md5(b'wtlogin.login').digest())),
    ('MD5(wtlogin.login)_LE', md5_to_u32_le(hashlib.md5(b'wtlogin.login').digest())),
    ('MD5(wtlogin.login\\0)_BE', md5_to_u32_be(hashlib.md5(b'wtlogin.login\x00').digest())),
    ('FK', FK),
    ('CK[0..3]', CK[:4]),
    ('zeros', [0,0,0,0]),
    ('master_key_b1', [0x2cbb6ee6, 0x1c2ba03e, 0x81057e5e, 0x2e55de86]),
    ('our_RK_B1[0..3]', pure_cipher.RK_B1[:4]),
]


# For each candidate MK, compute cipher_forward(MD5(src), rk_from_MK) and check
# if any output u32 equals X_b1_init[2] across multiple samples.
def test_mk(label, MK):
    try:
        rk = sm4_key_schedule(MK)
    except Exception as e:
        return
    # Test with cipher_forward
    for input_label, input_fn in [('md5_be', md5_to_u32_be), ('md5_le', md5_to_u32_le)]:
        # For first sample, compute and find positions matching X_b1_init[2]
        first = samples[0]
        md5 = bytes.fromhex(first['md5'])
        try:
            state = pure_cipher.cipher_forward(input_fn(md5), rk)
        except:
            continue
        target = int(first['xb1'][2], 16)
        candidates = [k for k, v in enumerate(state) if v == target]
        for k in candidates:
            # Verify across more samples
            ok = True
            for s in samples[1:50]:
                md5 = bytes.fromhex(s['md5'])
                state = pure_cipher.cipher_forward(input_fn(md5), rk)
                if state[k] != int(s['xb1'][2], 16):
                    ok = False
                    break
            if ok:
                print(f"  HIT! MK={label} input={input_label} state[{k}] = X_b1_init[2]")


for label, mk in mk_candidates:
    test_mk(label, mk)


# Also test our existing pure_cipher.cipher_forward with FK as round keys
print("\n=== Test if cipher_forward with FK matches anything ===")
test_mk('via_pure_cipher_FK_RK', FK + [0]*28)

# Test the OUR cipher with derived RK from cmd
import hashlib
cmd_md5 = hashlib.md5(b'wtlogin.login').digest()
print(f"\nMD5(wtlogin.login) = {cmd_md5.hex()}")
md5_u32 = md5_to_u32_be(cmd_md5)
print(f"As u32 BE: {[hex(x) for x in md5_u32]}")
# Run sm4_key_schedule on it
rk = sm4_key_schedule(md5_u32)
print(f"Derived RK[0..3]: {[hex(x) for x in rk[:4]]}")
print(f"Compare to RK_B1[0..3]: {[hex(x) for x in pure_cipher.RK_B1[:4]]}")
