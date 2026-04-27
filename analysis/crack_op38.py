#!/usr/bin/env python3
"""Try to crack op 0x38 — the operation that produces X_b1_init[2] from X_b1_init[1].

For step 7140, op 0x38 ib=[56, 13, 13, 42]:
  r[13]=0xaffc818b → r[42]=0xfc57448f  (src=00)
  r[13]=0xe099818b → r[42]=0x30d351c6  (src=01)
  r[13]=0x72b3818b → r[42]=0x170f594a  (src=02)
  r[13]=0x4c4b818b → r[42]=0x830a9c17  (src=ff)

The X_b1_init bytes are the cipher input, so ib=[56, X, X, Y] is part of building
the cipher input. f(input) = ? Try many cipher-derived transforms.
"""
import sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher
MASK = 0xFFFFFFFF
def rotl(x, n): return ((x << n) | (x >> (32-n))) & MASK
def rotr(x, n): return ((x >> n) | (x << (32-n))) & MASK

# Test pairs
pairs = [
    (0xaffc818b, 0xfc57448f),
    (0xe099818b, 0x30d351c6),
    (0x72b3818b, 0x170f594a),
    (0x4c4b818b, 0x830a9c17),
]

def all_match(fn):
    for inp, expected in pairs:
        if fn(inp) != expected:
            return False
    return True


# 1. Direct transforms
candidates = [
    ('sbox_word', lambda x: pure_cipher.sbox_word(x)),
    ('L(sbox_word)', lambda x: pure_cipher.L(pure_cipher.sbox_word(x))),
    ('sbox_word(L)', lambda x: pure_cipher.sbox_word(pure_cipher.L(x))),
    ('L(x)', lambda x: pure_cipher.L(x)),
]
for n in range(32):
    candidates.append((f'rotl{n}', lambda x, n=n: rotl(x, n)))
    candidates.append((f'rotl{n}(sbox)', lambda x, n=n: rotl(pure_cipher.sbox_word(x), n)))
    candidates.append((f'sbox(rotl{n})', lambda x, n=n: pure_cipher.sbox_word(rotl(x, n))))

# 2. With a constant
test_consts = list(range(256)) + [0x2cbb6ee6, 0x1c2ba03e, 0x114D0B11, 0x818B,
                                    0xa3b1bac6, 0x56aa3350, 0x67452301, 0xefcdab89]
for c in test_consts:
    candidates.append((f'^0x{c:08x}', lambda x, c=c: (x ^ c) & MASK))
    candidates.append((f'sbox(x^0x{c:08x})', lambda x, c=c: pure_cipher.sbox_word(x ^ c)))
    candidates.append((f'L(sbox(x^0x{c:08x}))', lambda x, c=c: pure_cipher.L(pure_cipher.sbox_word(x ^ c))))

# 3. Combined cipher round
for rk in pure_cipher.RK_B1:
    candidates.append((f'cipher_round_rk={rk:#x}',
                        lambda x, rk=rk: (x ^ pure_cipher.L(pure_cipher.sbox_word(x ^ rk))) & MASK))

# 4. Multiple operations
for c1 in [0x114D0B11, 0x2cbb6ee6, 0x818B, 0xa3b1bac6]:
    for c2 in [0x114D0B11, 0x2cbb6ee6, 0x818B, 0xa3b1bac6]:
        candidates.append((f'L(sbox(^{c1:#x}))^{c2:#x}',
                          lambda x, c1=c1, c2=c2: (pure_cipher.L(pure_cipher.sbox_word(x ^ c1)) ^ c2) & MASK))

# Test all
for label, fn in candidates:
    if all_match(fn):
        print(f"MATCH: {label}")

print("\nAll-pairs delta analysis:")
for i, (inp, out) in enumerate(pairs):
    print(f"  inp=0x{inp:08x} out=0x{out:08x}  delta=0x{(out^inp)&MASK:08x}  +=0x{(out-inp)&MASK:08x}")

# Check if output is L of something
print("\nL inverse: if out = L(y), find y")
# L is not always invertible, but try L^-1 if exists
# Actually L(x) = x ^ rotl(x,2) ^ rotl(x,10) ^ rotl(x,18) ^ rotl(x,24)
# This is a linear function over GF(2)^32. May or may not be invertible.

import numpy as np
# Build L matrix (32x32 over GF(2))
def L_matrix():
    M = np.zeros((32, 32), dtype=np.uint8)
    for i in range(32):
        # L(x) where x = 1 << i
        x = 1 << i
        y = pure_cipher.L(x)
        for j in range(32):
            if (y >> j) & 1:
                M[j, i] = 1
    return M

L_mat = L_matrix()
# Try to invert
def invert_gf2(M):
    n = M.shape[0]
    A = np.hstack([M, np.eye(n, dtype=np.uint8)]).copy()
    for col in range(n):
        # Find pivot
        for r in range(col, n):
            if A[r, col] == 1:
                A[[col, r]] = A[[r, col]]
                break
        else:
            return None  # singular
        for r in range(n):
            if r != col and A[r, col] == 1:
                A[r] ^= A[col]
    return A[:, n:]

L_inv = invert_gf2(L_mat)
if L_inv is not None:
    print("L is invertible!")
    def L_inverse(y):
        bits = [(y >> i) & 1 for i in range(32)]
        in_bits = (L_inv @ np.array(bits, dtype=np.uint8)) & 1
        result = 0
        for i in range(32):
            if in_bits[i]: result |= (1 << i)
        return result
    # Verify
    test = 0xdeadbeef
    print(f"L(0x{test:08x}) = 0x{pure_cipher.L(test):08x}")
    print(f"L_inv(L(0x{test:08x})) = 0x{L_inverse(pure_cipher.L(test)):08x}")
    print(f"Match: {L_inverse(pure_cipher.L(test)) == test}")

    # Now if op 0x38 = L(something), then L_inv(out) = something
    print("\nUsing L_inv on outputs:")
    for inp, out in pairs:
        y = L_inverse(out)
        print(f"  inp=0x{inp:08x} out=0x{out:08x} L_inv(out)=0x{y:08x}")
else:
    print("L is NOT invertible.")
