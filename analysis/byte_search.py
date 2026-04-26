#!/usr/bin/env python3
"""For each variable byte of X_b1_init/X_b2[1] (11 bytes total), search whether
it appears at a FIXED byte position in any computed buffer derived from MD5(src).

Buffers searched per sample:
  - MD5(src) itself
  - post_xor (MD5 ^ XOR_STREAM)
  - MD5(post_xor)
  - MD5(MD5(src))
  - SHA1(MD5)
  - cipher_forward(MD5_BE, RK_B1) state (144 bytes)
  - cipher_forward(MD5_LE, RK_B1) state
  - cipher_forward(MD5_BE, RK_B2) state
  - cipher_forward(post_xor_BE, RK_B1) state
  - cipher_forward(post_xor_LE, RK_B1) state
  - and many byte-position-cycling variants
"""
import json, hashlib, sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher

XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')
samples = json.load(open('/tmp/xb_samples_large.json'))

def state_bytes(state):
    out = bytearray()
    for w in state:
        out.extend(w.to_bytes(4, 'big'))
    return bytes(out)

def state_bytes_le(state):
    out = bytearray()
    for w in state:
        out.extend(w.to_bytes(4, 'little'))
    return bytes(out)

def make_buffers(s):
    md5 = bytes.fromhex(s['md5'])
    post = bytes(a^b for a, b in zip(md5, XOR_STREAM[:16]))
    bufs = {
        'md5': md5,
        'post_xor': post,
        'md5_md5': hashlib.md5(md5).digest(),
        'md5_post': hashlib.md5(post).digest(),
        'sha1_md5': hashlib.sha1(md5).digest(),
        'sha1_post': hashlib.sha1(post).digest(),
        'cipher_md5_BE_RK1':   state_bytes(pure_cipher.cipher_forward([int.from_bytes(md5[i:i+4],'big') for i in range(0,16,4)], pure_cipher.RK_B1)),
        'cipher_md5_LE_RK1':   state_bytes(pure_cipher.cipher_forward([int.from_bytes(md5[i:i+4],'little') for i in range(0,16,4)], pure_cipher.RK_B1)),
        'cipher_md5_BE_RK2':   state_bytes(pure_cipher.cipher_forward([int.from_bytes(md5[i:i+4],'big') for i in range(0,16,4)], pure_cipher.RK_B2)),
        'cipher_post_BE_RK1':  state_bytes(pure_cipher.cipher_forward([int.from_bytes(post[i:i+4],'big') for i in range(0,16,4)], pure_cipher.RK_B1)),
        'cipher_post_LE_RK1':  state_bytes(pure_cipher.cipher_forward([int.from_bytes(post[i:i+4],'little') for i in range(0,16,4)], pure_cipher.RK_B1)),
        'cipher_post_BE_RK2':  state_bytes(pure_cipher.cipher_forward([int.from_bytes(post[i:i+4],'big') for i in range(0,16,4)], pure_cipher.RK_B2)),
        'cipher_md5_BE_RK1_LE_state': state_bytes_le(pure_cipher.cipher_forward([int.from_bytes(md5[i:i+4],'big') for i in range(0,16,4)], pure_cipher.RK_B1)),
        'cipher_post_BE_RK1_LE_state': state_bytes_le(pure_cipher.cipher_forward([int.from_bytes(post[i:i+4],'big') for i in range(0,16,4)], pure_cipher.RK_B1)),
    }
    # Add SBOX-ed variants
    bufs['sbox_md5'] = bytes(pure_cipher.SBOX[b] for b in md5)
    bufs['sbox_post'] = bytes(pure_cipher.SBOX[b] for b in post)
    bufs['md5_xor_sbox'] = bytes(b ^ pure_cipher.SBOX[b] for b in md5)
    return bufs

def get_var_bytes(s):
    """Return 11 input-dependent bytes from X_b1[1..3] + X_b2[1]."""
    x1 = [int(v, 16) for v in s['xb1']]
    x2 = [int(v, 16) for v in s['xb2']]
    return [
        ('X_b1[1]_b0', (x1[1] >> 24) & 0xFF),  # high byte
        ('X_b1[1]_b1', (x1[1] >> 16) & 0xFF),
        ('X_b1[2]_b0', (x1[2] >> 24) & 0xFF),
        ('X_b1[2]_b1', (x1[2] >> 16) & 0xFF),
        ('X_b1[2]_b2', (x1[2] >>  8) & 0xFF),
        ('X_b1[2]_b3',  x1[2] & 0xFF),
        ('X_b1[3]_b3',  x1[3] & 0xFF),
        ('X_b2[1]_b0', (x2[1] >> 24) & 0xFF),
        ('X_b2[1]_b1', (x2[1] >> 16) & 0xFF),
        ('X_b2[1]_b2', (x2[1] >>  8) & 0xFF),
        ('X_b2[1]_b3',  x2[1] & 0xFF),
    ]

# For each (target byte name, buffer name), find positions where target == buf[pos] for ALL samples
N_TEST = 200  # check 200 samples
print(f"Searching {len(make_buffers(samples[0]))} buffers for fixed positions of 11 target bytes...")

# Precompute buffers + target bytes for first sample to find candidates
sample0 = samples[0]
bufs0 = make_buffers(sample0)
targets0 = get_var_bytes(sample0)

candidates_per_target = {name: [] for name, _ in targets0}
for name, target in targets0:
    for bname, buf in bufs0.items():
        positions = [i for i, b in enumerate(buf) if b == target]
        for pos in positions:
            candidates_per_target[name].append((bname, pos))

# Now verify candidates across more samples
for tname, candidates in candidates_per_target.items():
    if not candidates:
        print(f"  {tname}: no candidates")
        continue
    matched = []
    for bname, pos in candidates:
        ok = True
        for s in samples[1:N_TEST]:
            bufs = make_buffers(s)
            tgts = dict(get_var_bytes(s))
            buf = bufs[bname]
            if pos >= len(buf) or buf[pos] != tgts[tname]:
                ok = False
                break
        if ok:
            matched.append((bname, pos))
    if matched:
        print(f"  HIT  {tname}: {matched}")
    else:
        print(f"  MISS {tname}: {len(candidates)} candidates failed")
