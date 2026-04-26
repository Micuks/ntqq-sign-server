#!/usr/bin/env python3
"""Check if the 20-value sequence at reg[100..119] (src=00) satisfies the SM4-like
Feistel recurrence X[i+4] = X[i] ^ L(sbox_word(Y)) where Y = X[i+1]^X[i+2]^X[i+3]^rk[i]
with rk = RK_B1.

If yes, then this sequence is the cipher state, and the input was X[0..3] = first 4 values.
"""
import sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher
MASK = 0xFFFFFFFF

# Sequence at reg[100..119] for src=00 (from previous output)
seq = [0x2cbb6ee6, 0x1c2ba03e, 0xa0dfc8e2, 0xfab7f5a8, 0xabcc17f1, 0x7013a64d,
       0xebd737cf, 0x93932f9b, 0xc374435b, 0x316cd642, 0x470f7ab9, 0x96c1ce8f,
       0x690fb455, 0xe3c5d002, 0x5601e1c6, 0x329bcaea, 0xff9cf508, 0x92b0ddc0,
       0x2217d1c3, 0xf700a462]

# Try recurrence with various rk choices
for rk_label, rk in [('RK_B1', pure_cipher.RK_B1), ('RK_B2', pure_cipher.RK_B2)]:
    print(f"\n=== Testing recurrence with {rk_label} ===")
    n_ok = 0
    n_fail = 0
    for i in range(len(seq) - 4):
        x0, x1, x2, x3 = seq[i], seq[i+1], seq[i+2], seq[i+3]
        rk_i = rk[i % 32] if i < 32 else 0
        Y = (x1 ^ x2 ^ x3 ^ rk_i) & MASK
        x4_pred = (x0 ^ pure_cipher.L(pure_cipher.sbox_word(Y))) & MASK
        x4_actual = seq[i+4]
        ok = x4_pred == x4_actual
        if ok: n_ok += 1
        else: n_fail += 1
        marker = '✓' if ok else '✗'
        if i < 5 or not ok:
            print(f"  i={i}: x4_pred=0x{x4_pred:08x} x4_actual=0x{x4_actual:08x} {marker}")
    print(f"  Total: {n_ok}/{n_ok+n_fail} match")

# Also try using rk in REVERSE order
print(f"\n=== Testing recurrence with RK_B1 REVERSED ===")
rk_rev = pure_cipher.RK_B1[::-1]
for i in range(len(seq) - 4):
    x0, x1, x2, x3 = seq[i], seq[i+1], seq[i+2], seq[i+3]
    rk_i = rk_rev[i % 32] if i < 32 else 0
    Y = (x1 ^ x2 ^ x3 ^ rk_i) & MASK
    x4_pred = (x0 ^ pure_cipher.L(pure_cipher.sbox_word(Y))) & MASK
    if x4_pred == seq[i+4]:
        print(f"  i={i}: MATCH with rk_rev[{i % 32}]={rk_rev[i % 32]:08x}")

# Try with 4-valued offset: maybe rk index doesn't start at 0
for offset in range(8):
    print(f"\n=== Recurrence with RK_B1 offset {offset} ===")
    n_ok = 0
    for i in range(len(seq) - 4):
        x0, x1, x2, x3 = seq[i], seq[i+1], seq[i+2], seq[i+3]
        rk_i = pure_cipher.RK_B1[(i + offset) % 32]
        Y = (x1 ^ x2 ^ x3 ^ rk_i) & MASK
        x4_pred = (x0 ^ pure_cipher.L(pure_cipher.sbox_word(Y))) & MASK
        if x4_pred == seq[i+4]: n_ok += 1
    if n_ok > 0:
        print(f"  Match count: {n_ok}/{len(seq)-4}")
