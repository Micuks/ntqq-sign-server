#!/usr/bin/env python3
"""
Pure-Python implementation of the NTQQ packet sign algorithm's two-block
SM4-like cipher and output extraction.

Scope (what IS implemented purely):
  * The 32-round SM4-style Feistel cipher with custom SBOX, used for both blocks
  * Round key schedules rk_b1 and rk_b2 (pinned for cmd="wtlogin.login", seq=1)
  * Output extraction: w_k = X[offset_k] XOR C_k with C tables per block
  * Block 2 input derivation: X_b2[0,2,3] from Block 1 output via the same XOR formula
  * Byte permutation (b0,b1,b2,b3) -> (b1,b0,b2,b3) on each emitted word

Scope (what is NOT implemented purely - still needs wrapper.node):
  * X_b1_init[1..3] derivation from (cmd, src, seq, body) - internal obfuscated hash
  * X_b2_init[1] derivation (depends on MK / body mixing not cracked)
  * rk derivation for cmd != "wtlogin.login" or seq != 1 (key schedule not cracked)
  * Random nonce injection into X_b2[0] bytes (counter mixing)

To use this module as a fully deterministic SIGN function for a known input,
you must either:
  (a) supply X_b1_init and X_b2_init yourself (recovered via cipher inversion
      from one native wrapper call using recover_states_from_sign), or
  (b) use the hybrid sign harness in hybrid_sign.py which captures states
      via the native reference and then computes outputs in pure Python.
"""

import os

MASK = 0xFFFFFFFF

_SBOX_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)) or ".",
    "custom_sbox.bin"
)
if not os.path.exists(_SBOX_PATH):
    _SBOX_PATH = "/mnt/data1/wuql/services/ntqq-sign-server/custom_sbox.bin"
with open(_SBOX_PATH, "rb") as _f:
    SBOX = list(_f.read())

RK_B1 = [
    0x2cbb6ee6, 0x1c2ba03e, 0x81057e5e, 0x2e55de86,
    0xf06e9f8e, 0xa2f4a4de, 0x92d0e737, 0x15df8ce3,
    0x994d90f2, 0x524a3a08, 0x3344c2b1, 0xbdda16f7,
    0xbc3981e5, 0xb27df212, 0xf8b350e6, 0x8e23a4f2,
    0x230a16f8, 0x0ccc3529, 0x01bbd606, 0x468f698e,
    0xd8c06923, 0x03d8c454, 0x2144b6c0, 0x1333505c,
    0xc5eeb770, 0x6abaa2bd, 0xee06fb12, 0xec5f6aa1,
    0x73362478, 0x3271550c, 0xe8eb0699, 0x6d8bbf36,
]
RK_B2 = [
    0x2cbb6ee6, 0xced85f2e, 0x53f6814e, 0xfca62196,
    0xf06e9f8e, 0x70075bce, 0x40231827, 0xc72c73f3,
    0x994d90f2, 0x80b9c518, 0xe1b73da1, 0x6f29e9e7,
    0xbc3981e5, 0x608e0d02, 0x2a40aff6, 0x5cd05be2,
    0x230a16f8, 0xde3fca39, 0xd3482916, 0x947c969e,
    0xd8c06923, 0xd12b3b44, 0xf3b749d0, 0xc1c0af4c,
    0xc5eeb770, 0xb8495dad, 0x3cf50402, 0x3eac95b1,
    0x73362478, 0xe082aa1c, 0x3a18f989, 0xbf784026,
]

C_B1 = {32: 0x35b21fcb, 33: 0x4310dd6f, 34: 0xe83ad9cc, 35: 0x60c8dac1}
C_B2 = {32: 0xe741e0db, 33: 0x4310dd6f, 34: 0xe83ad9cc, 35: 0x60c8dac1}


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def L(x):
    return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24)


def sbox_word(x):
    b1 = (x >> 24) & 0xFF
    b0 = (x >> 16) & 0xFF
    b2 = (x >> 8) & 0xFF
    b3 = x & 0xFF
    return (SBOX[b1] << 24) | (SBOX[b0] << 16) | (SBOX[b2] << 8) | SBOX[b3]


def permute_word(w):
    b = w.to_bytes(4, "big")
    return int.from_bytes([b[1], b[0], b[2], b[3]], "big")


def cipher_forward(x_init, rk):
    X = list(x_init)
    for i in range(32):
        Y = X[-3] ^ X[-2] ^ X[-1] ^ rk[i]
        X.append((X[-4] ^ L(sbox_word(Y))) & MASK)
    return X


def cipher_backward_from_tail(x_last4, rk):
    X = [0] * 36
    X[32], X[33], X[34], X[35] = x_last4
    for i in range(31, -1, -1):
        Y = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]
        X[i] = (X[i + 4] ^ L(sbox_word(Y))) & MASK
    return X


def emit_block_bytes(x_final_32_35, C):
    out = bytearray()
    for idx in (34, 35, 32, 33):
        w = (x_final_32_35[idx - 32] ^ C[idx]) & MASK
        out.extend(permute_word(w).to_bytes(4, "big"))
    return bytes(out)


def compute_sign_from_states(x_b1_init, x_b2_init, rk_b1=RK_B1, rk_b2=RK_B2):
    x_b1_full = cipher_forward(x_b1_init, rk_b1)
    x_b2_full = cipher_forward(x_b2_init, rk_b2)
    return emit_block_bytes(x_b1_full[32:36], C_B1) + emit_block_bytes(x_b2_full[32:36], C_B2)


def recover_states_from_sign(sign_bytes, rk_b1=RK_B1, rk_b2=RK_B2):
    if len(sign_bytes) != 32:
        raise ValueError("sign_bytes must be exactly 32 bytes")
    w_b1 = [permute_word(int.from_bytes(sign_bytes[i * 4:(i + 1) * 4], "big")) for i in range(4)]
    x_b1_32_35 = [w_b1[2] ^ C_B1[32], w_b1[3] ^ C_B1[33], w_b1[0] ^ C_B1[34], w_b1[1] ^ C_B1[35]]
    x_b1_full = cipher_backward_from_tail(x_b1_32_35, rk_b1)
    w_b2 = [permute_word(int.from_bytes(sign_bytes[16 + i * 4:16 + (i + 1) * 4], "big")) for i in range(4)]
    x_b2_32_35 = [w_b2[2] ^ C_B2[32], w_b2[3] ^ C_B2[33], w_b2[0] ^ C_B2[34], w_b2[1] ^ C_B2[35]]
    x_b2_full = cipher_backward_from_tail(x_b2_32_35, rk_b2)
    return x_b1_full[0:4], x_b2_full[0:4]


# Base constant for X_b2[0] derivation (for ctr=0). Bits 16..31 get XORed with
# a ctr-dependent 16-bit word T(ctr). Empirical fit (verified on 256 samples
# cmd="wtlogin.login", src=0x00):
#   for ctr in [0..0xFFFE]: T(ctr) = (ctr + 2) if ctr odd else ctr
#   ctr=0xFFFF: T = 0xFFFE   (edge case; rule changes at u16 overflow)
# Low 16 bits of the XOR constant are always 0x25c1.
X_B2_0_BASE_CONST = 0x60C925C1


def ctr_mix_u16(ctr):
    """Compute the 16-bit ctr transform used in X_b2[0] derivation.
    ctr is treated as a 32-bit unsigned integer; only low 16 bits matter."""
    c = ctr & 0xFFFF
    if c == 0xFFFF:
        return 0xFFFE
    if c & 1:
        return (c + 2) & 0xFFFF
    return c


def derive_x_b2_from_block1(x_b1_full, x_b2_1_nonce, ctr=100):
    """
    Three of the four X_b2_init slots are deterministically sourced from Block 1's
    output + counter:
      X_b2[0] = X_b1_full[35] ^ (X_B2_0_BASE_CONST ^ (T(ctr) << 16))
      X_b2[2] = X_b1_full[33] ^ C_B1[33]
      X_b2[3] = X_b1_full[32] ^ C_B1[32]

    X_b2[1] must be supplied separately - it carries the body-specific mixing
    that is NOT implemented purely here (empirically shown to depend only on
    MD5(src), not on seq or ctr).
    """
    ctr_const = X_B2_0_BASE_CONST ^ (ctr_mix_u16(ctr) << 16)
    return [
        (x_b1_full[35] ^ ctr_const) & MASK,
        x_b2_1_nonce,
        (x_b1_full[33] ^ C_B1[33]) & MASK,
        (x_b1_full[32] ^ C_B1[32]) & MASK,
    ]


def compute_sign_from_block1_and_nonce(x_b1_init, x_b2_1_nonce, ctr=100,
                                        rk_b1=RK_B1, rk_b2=RK_B2):
    """High-level sign: derive X_b2_init entirely from (X_b1_init, X_b2[1], ctr)
    and run both cipher blocks.

    This is the pure-Python path that makes the oracle surface minimal:
    callers need only supply X_b1_init (4 u32, depends on MD5(src)+cmd) and
    X_b2[1] (1 u32, depends on MD5(src)+cmd). ctr is a user-supplied counter.
    """
    x_b1_full = cipher_forward(x_b1_init, rk_b1)
    x_b2_init = derive_x_b2_from_block1(x_b1_full, x_b2_1_nonce, ctr=ctr)
    x_b2_full = cipher_forward(x_b2_init, rk_b2)
    return emit_block_bytes(x_b1_full[32:36], C_B1) + emit_block_bytes(x_b2_full[32:36], C_B2)


if __name__ == "__main__":
    x_b1_init = [0x114D0B11, 0xAFFC818B, 0xFC57448F, 0x011D0687]
    x_b2_init = [0x60E5DF16, 0x8DBF308E, 0x195D773F, 0xDEAAD8B7]
    expected = bytes.fromhex(
        "e957228ae560df16aaded8b75d19773f2e8cb6c5be0e43d970bb0b02956d3c57"
    )
    got = compute_sign_from_states(x_b1_init, x_b2_init)
    print(f"self-test: got={got.hex()}")
    print(f"           exp={expected.hex()}")
    print(f"           {'PASS' if got == expected else 'FAIL'}")

    rx_b1, rx_b2 = recover_states_from_sign(expected)
    rt = compute_sign_from_states(rx_b1, rx_b2)
    print(f"round-trip: {'PASS' if rt == expected else 'FAIL'}")
    print(f"  recovered X_b1_init = {[hex(x) for x in rx_b1]}")
    print(f"  recovered X_b2_init = {[hex(x) for x in rx_b2]}")
