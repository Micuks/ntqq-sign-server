#!/usr/bin/env python3
"""Test if X_b1_init variable bytes appear in MD5 of various derived inputs.

For src=00, we want bytes: 0xfc, 0x57, 0x44, 0x8f, 0x87 (byte 0,1,2,3 of X_b1_init[2] + low byte X_b1_init[3])

If they appear contiguously in any MD5(some_function(MD5(src))), we found the formula.
"""
import json, hashlib, sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')

XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')
samples = json.load(open('/tmp/xb_samples_large.json'))

def md5(b): return hashlib.md5(b).digest()
def sha1(b): return hashlib.sha1(b).digest()

# For each sample, compute candidate hashes and check if X_b1[2] appears as a 4-byte slice
def x_b1_2_bytes(s):
    v = int(s['xb1'][2], 16)
    return v.to_bytes(4, 'big')

def x_b1_2_bytes_le(s):
    v = int(s['xb1'][2], 16)
    return v.to_bytes(4, 'little')

# Variants to try (function of MD5(src) only):
variants = [
    ('MD5(MD5(src))',           lambda s: md5(bytes.fromhex(s['md5']))),
    ('MD5(post_xor)',           lambda s: md5(bytes(a^b for a,b in zip(bytes.fromhex(s['md5']), XOR_STREAM[:16])))),
    ('MD5(post_xor||extra4)',   lambda s: md5(bytes(a^b for a,b in zip(bytes.fromhex(s['md5']), XOR_STREAM[:16])) + XOR_STREAM[16:20])),
    ('MD5(XOR_STREAM||md5)',    lambda s: md5(XOR_STREAM[:16] + bytes.fromhex(s['md5']))),
    ('MD5(md5||XOR_STREAM)',    lambda s: md5(bytes.fromhex(s['md5']) + XOR_STREAM[:16])),
    ('MD5(md5||XOR_STREAM_20)', lambda s: md5(bytes.fromhex(s['md5']) + XOR_STREAM)),
    ('MD5(XOR_STREAM_20||md5)', lambda s: md5(XOR_STREAM + bytes.fromhex(s['md5']))),
    ('MD5(XOR_STREAM)',         lambda s: md5(XOR_STREAM)),  # constant - won't vary
    ('SHA1(MD5(src))',          lambda s: sha1(bytes.fromhex(s['md5']))),
    ('SHA1(post_xor)',          lambda s: sha1(bytes(a^b for a,b in zip(bytes.fromhex(s['md5']), XOR_STREAM[:16])))),
    ('MD5(md5||md5)',           lambda s: md5(bytes.fromhex(s['md5']) + bytes.fromhex(s['md5']))),
    ('MD5(md5 reversed)',       lambda s: md5(bytes.fromhex(s['md5'])[::-1])),
    ('MD5(md5 ^ md5_rev)',      lambda s: md5(bytes(a^b for a,b in zip(bytes.fromhex(s['md5']), bytes.fromhex(s['md5'])[::-1])))),
]

for label, fn in variants:
    sample0 = samples[0]
    h = fn(sample0)
    target = x_b1_2_bytes(sample0)
    target_le = x_b1_2_bytes_le(sample0)
    pos_be = h.find(target)
    pos_le = h.find(target_le)
    if pos_be >= 0 or pos_le >= 0:
        # Verify across more samples
        ok_be = ok_le = True
        for s in samples[:50]:
            h = fn(s)
            t = x_b1_2_bytes(s)
            t_le = x_b1_2_bytes_le(s)
            if pos_be >= 0 and (pos_be + 4 > len(h) or h[pos_be:pos_be+4] != t):
                ok_be = False
            if pos_le >= 0 and (pos_le + 4 > len(h) or h[pos_le:pos_le+4] != t_le):
                ok_le = False
        if ok_be: print(f"  HIT BE: {label}: X_b1[2] BE at offset {pos_be}")
        if ok_le: print(f"  HIT LE: {label}: X_b1[2] LE at offset {pos_le}")

# Also check single-byte hits across the variants for X_b1_init[2] byte 0 (varying byte)
print("\n=== Single-byte hit search for X_b1[2] byte 0 (src=00 → 0xfc) ===")
for label, fn in variants:
    h = fn(samples[0])
    target0 = (int(samples[0]['xb1'][2], 16) >> 24) & 0xFF
    positions = [i for i, b in enumerate(h) if b == target0]
    if positions:
        # Check if SAME position works for sample 1, 2, 3
        ok_pos = []
        for pos in positions:
            consistent = True
            for s in samples[:50]:
                h2 = fn(s)
                tgt = (int(s['xb1'][2], 16) >> 24) & 0xFF
                if pos >= len(h2) or h2[pos] != tgt:
                    consistent = False
                    break
            if consistent: ok_pos.append(pos)
        if ok_pos:
            print(f"  {label}: byte at pos {ok_pos} matches across 50 samples")
