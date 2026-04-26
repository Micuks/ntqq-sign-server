#!/usr/bin/env python3
"""GF(2) linear regression: for each output bit (in X_b1_init[1..3] variable bits +
X_b2[1] all 32 bits), test if it equals a fixed XOR of input MD5 bits + a constant.

If the obfuscation is just bit-permutations and XOR with constants, this will find
the exact formula. If it uses SBOX/AND/OR, no linear fit will exist (residual error
indicates nonlinearity).

Sample size: 4755 unique MD5 inputs. Input dim = 128 bits + 1 constant. Output = 88 bits
(7 variable bytes of X_b1_init = 56 bits + 32 bits of X_b2[1]).
"""
import json, sys
import numpy as np
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')

samples = json.load(open('/tmp/xb_samples_large.json'))
print(f"Loaded {len(samples)} samples")

# Build input matrix A (n × 129): each row is (md5 bits || 1)
# Build output matrix Y (n × 88): each row is the output bits

n = len(samples)
A = np.zeros((n, 129), dtype=np.uint8)
Y = np.zeros((n, 88), dtype=np.uint8)
for i, s in enumerate(samples):
    md5 = bytes.fromhex(s['md5'])
    md5_bits = [(md5[b] >> bb) & 1 for b in range(16) for bb in range(8)]
    A[i, :128] = md5_bits
    A[i, 128] = 1  # constant
    # Variable bytes of X_b1: position 4 (bits 16..23 of word 1), position 5 (bits 24..31 of word 1),
    # positions 8,9,10,11 (all 4 bytes of word 2), position 15 (bits 0..7 of word 3)
    x1 = [int(v, 16) for v in s['xb1']]
    x2 = [int(v, 16) for v in s['xb2']]
    out_bits = []
    # X_b1[1] high 16 bits (bits 16..31)
    for bb in range(16, 32):
        out_bits.append((x1[1] >> bb) & 1)
    # X_b1[2] all 32 bits
    for bb in range(32):
        out_bits.append((x1[2] >> bb) & 1)
    # X_b1[3] low 8 bits
    for bb in range(8):
        out_bits.append((x1[3] >> bb) & 1)
    # X_b2[1] all 32 bits
    for bb in range(32):
        out_bits.append((x2[1] >> bb) & 1)
    Y[i, :] = out_bits

print(f"Input dim: {A.shape[1]} (128 MD5 bits + 1 const), output dim: {Y.shape[1]}")

# For each output bit, fit y = A @ x (mod 2) by Gaussian elimination over GF(2)
# Stack A and y, find x such that Ax = y. If no solution exists exactly, the bit is nonlinear.

def gf2_solve(A, b):
    """Solve A @ x = b over GF(2). Returns (x, residual_vec) where residual_vec are
    rows where Ax != b. If residual is all zero, fit is exact."""
    n, m = A.shape
    M = np.hstack([A, b.reshape(-1, 1)]).astype(np.uint8)
    # Forward elimination
    pivot_col = 0
    pivot_rows = []
    for col in range(m):
        # Find a row with 1 in this column at row >= pivot_col
        pivot_row = None
        for r in range(pivot_col, n):
            if M[r, col] == 1:
                pivot_row = r
                break
        if pivot_row is None:
            continue
        if pivot_row != pivot_col:
            M[[pivot_col, pivot_row]] = M[[pivot_row, pivot_col]]
        pivot_rows.append((pivot_col, col))
        # Eliminate this column from all other rows
        for r in range(n):
            if r != pivot_col and M[r, col] == 1:
                M[r] ^= M[pivot_col]
        pivot_col += 1
    # After elimination, M[r, m] (the last col) should be 0 for r >= pivot_col, else inconsistent
    inconsistent = 0
    for r in range(pivot_col, n):
        if M[r, m] == 1:
            inconsistent += 1
    # Recover x
    x = np.zeros(m, dtype=np.uint8)
    for pr, pc in pivot_rows:
        x[pc] = M[pr, m]
    # Compute residual
    pred = (A @ x) & 1
    err = pred ^ b
    return x, err.sum(), inconsistent

# Output bit labels
labels = []
for bb in range(16, 32):
    labels.append(f'X_b1[1]_bit{bb}')
for bb in range(32):
    labels.append(f'X_b1[2]_bit{bb}')
for bb in range(8):
    labels.append(f'X_b1[3]_bit{bb}')
for bb in range(32):
    labels.append(f'X_b2[1]_bit{bb}')

n_linear = 0
n_nonlinear = 0
for j in range(Y.shape[1]):
    coef, err, inc = gf2_solve(A.copy(), Y[:, j].copy())
    if err == 0:
        n_linear += 1
        # Print which input bits contribute
        contribs = [k for k in range(128) if coef[k] == 1]
        const = coef[128]
        if len(contribs) <= 8:
            print(f"  LINEAR  {labels[j]:<20}: y = XOR of MD5 bits {contribs} {'XOR 1' if const else ''}")
        else:
            print(f"  LINEAR  {labels[j]:<20}: {len(contribs)} input bits {'XOR 1' if const else ''}")
    else:
        n_nonlinear += 1
        print(f"  NONLIN  {labels[j]:<20}: residual = {err}/{n} ({100.0*err/n:.1f}% errors)")

print(f"\nSummary: {n_linear} linear bits, {n_nonlinear} nonlinear bits (out of {Y.shape[1]})")
