#!/usr/bin/env python3
"""For src=00 at step 6900, check if reg[100..135] values match cipher_forward(some_input, RK_B1)
output (the 36-slot cipher state).
"""
import json, hashlib, sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher
MASK = 0xFFFFFFFF

XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

# Reconstruct state at step 6900 for each trace
def reconstruct_at(trace, step):
    regs = {}
    for i in range(step + 1):
        diff = trace[i][3]
        for k, v in diff.items():
            regs[int(k)] = v & MASK
    return regs

states = {}
for name in ['00','01','02','ff']:
    trace = json.load(open(f'/tmp/complete_trace_{name}.json'))
    states[name] = reconstruct_at(trace, 6900)

# For src=00, reg[100..119] values are:
# 2cbb6ee6, 1c2ba03e, a0dfc8e2, fab7f5a8, abcc17f1, 7013a64d, ebd737cf, 93932f9b,
# c374435b, 316cd642, 470f7ab9, 96c1ce8f, 690fb455, e3c5d002, 5601e1c6, 329bcaea,
# ff9cf508, 92b0ddc0, 2217d1c3, f700a462

# Let's compute cipher_forward of MD5(src) and post_xor with RK_B1 and RK_B2, in BE/LE
for name in ['00','01','02','ff']:
    md5 = hashlib.md5(bytes.fromhex(name)).digest()
    post = bytes(a^b for a,b in zip(md5, XOR_STREAM[:16]))

    inputs = {
        'MD5_BE': [int.from_bytes(md5[i:i+4], 'big') for i in range(0,16,4)],
        'MD5_LE': [int.from_bytes(md5[i:i+4], 'little') for i in range(0,16,4)],
        'post_BE': [int.from_bytes(post[i:i+4], 'big') for i in range(0,16,4)],
        'post_LE': [int.from_bytes(post[i:i+4], 'little') for i in range(0,16,4)],
    }
    print(f"\n=== src={name}: state[100..119] = {[hex(states[name].get(r, 0)) for r in range(100, 120)]}")
    for inp_label, inp in inputs.items():
        for rk_label, rk in [('RK_B1', pure_cipher.RK_B1), ('RK_B2', pure_cipher.RK_B2)]:
            try:
                cstate = pure_cipher.cipher_forward(inp, rk)
            except Exception:
                continue
            # Find positions where reg[100..119] matches cstate[k..k+19] for some k
            target = [states[name].get(r, 0) for r in range(100, 120)]
            for k in range(0, 36-19):
                if list(cstate[k:k+20]) == target:
                    print(f"  HIT {inp_label}/{rk_label}: cipher_state[{k}..{k+19}] == reg[100..119]")
            # Also try reverse order
            if list(cstate[k:k+20])[::-1] == target:
                print(f"  HIT {inp_label}/{rk_label}: cipher_state[{k}..{k+19}] REVERSED == reg[100..119]")
