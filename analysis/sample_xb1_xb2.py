#!/usr/bin/env python3
"""Sample X_b1_init and X_b2_init for many src inputs (cmd=wtlogin.login, seq=1, ctr=100)
then search for algebraic relations to MD5(src) byte-by-byte.

Strategy:
  1. Collect 256 samples (one per single-byte src).
  2. For each of the 7 input-dependent bits of X_b1_init:
       - compute all 256 bytes seen
       - check if it's a bijection of MD5 byte (would reveal SBOX)
       - check if it's a XOR of subset of MD5 bytes with constants (linear)
  3. Same for X_b2_init (16 bytes).

Saves raw data to /tmp/xb_samples.json for later analysis.
"""
import ctypes, os, sys, hashlib, json
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')

os.chdir('/mnt/data1/wuql/services/ntqq-sign-server')
for lib in ["libgnutls.so.30","libssl.so.3","libcrypto.so.3","libpsl.so.5",
            "libnghttp2.so.14","libbrotlidec.so.1","libzstd.so.1",
            "libldap.so","liblber.so","libcurl.so.4","librtmp.so.1",
            "libssh2.so.1","./libsymbols.so"]:
    try: ctypes.CDLL(lib, mode=ctypes.RTLD_GLOBAL)
    except OSError: pass
ctypes.CDLL("./wrapper.node", mode=1)
libc = ctypes.CDLL(None)
base = ctypes.c_ulong(0)
CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
@CB
def cb(info, sz, data):
    addr = ctypes.c_ulong.from_address(info).value
    nm = ctypes.c_void_p.from_address(info + 8).value
    if nm:
        try:
            if "wrapper.node" in ctypes.string_at(nm).decode():
                base.value = addr; return 1
        except: pass
    return 0
libc.dl_iterate_phdr(cb, None)
SIGN_T = ctypes.CFUNCTYPE(ctypes.c_longlong, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte))
sf = SIGN_T(base.value + 0x56D81D1)
COUNTER = base.value + 0x7DD868C

def sign_once(src, seq=1, ctr=100, cmd=b"wtlogin.login"):
    sb = (ctypes.c_ubyte * max(len(src),1))(*src)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = ctr
    sf(cmd, sb, len(src), seq, out)
    raw = bytes(out)
    return raw[0x200:0x200+raw[0x2FF]]

# Warm up
_ = sign_once(b"\x00", 0, 0, b"init")
_ = sign_once(b"\x00", 1, 100)

import pure_cipher

# Single-byte srcs for 256 inputs
samples = []
for b in range(256):
    src = bytes([b])
    sig = sign_once(src)
    if len(sig) != 32:
        print(f"skip {b}: sign size {len(sig)}")
        continue
    x1, x2 = pure_cipher.recover_states_from_sign(sig)
    md5 = hashlib.md5(src).digest()
    samples.append({
        'src': src.hex(),
        'md5': md5.hex(),
        'xb1': [f'{v:08x}' for v in x1],
        'xb2': [f'{v:08x}' for v in x2],
    })
print(f"Collected {len(samples)} samples")

with open('/tmp/xb_samples.json', 'w') as f:
    json.dump(samples, f)

# Quick analysis: is X_b1[1] high16 a function of MD5[0..1] only?
# Check if for same MD5[0..1], X_b1[1] high16 is the same.
from collections import defaultdict
group = defaultdict(set)
for s in samples:
    md5 = bytes.fromhex(s['md5'])
    xb1_1 = int(s['xb1'][1], 16)
    group[md5[:2]].add(xb1_1 >> 16)
print(f"\nX_b1[1] high16 vs MD5[0..1]: {len(group)} distinct MD5[0..1] prefixes")
multi = [k for k, v in group.items() if len(v) > 1]
print(f"  MD5[0..1] prefixes with multiple X_b1[1] high16 values: {len(multi)}")
# if 0, it's a function of MD5[0..1] only

# Do same for X_b1[3] low8 vs MD5[?]
print("\n=== X_b1[3] low8 dependency ===")
for width_start in range(0, 16):
    group = defaultdict(set)
    for s in samples:
        md5 = bytes.fromhex(s['md5'])
        xb1_3 = int(s['xb1'][3], 16)
        group[md5[width_start:width_start+1]].add(xb1_3 & 0xFF)
    if all(len(v) == 1 for v in group.values()):
        print(f"  X_b1[3] low8 is a function of MD5[{width_start}] alone  (bijection? {len(set(next(iter(v)) for v in group.values()))}/256)")
        break
else:
    # Try 2-byte
    for w in range(15):
        group = defaultdict(set)
        for s in samples:
            md5 = bytes.fromhex(s['md5'])
            xb1_3 = int(s['xb1'][3], 16)
            group[md5[w:w+2]].add(xb1_3 & 0xFF)
        if all(len(v) == 1 for v in group.values()):
            print(f"  X_b1[3] low8 is a function of MD5[{w}:{w+2}]")
            break

# Same for X_b1[1] high 16 across 2 consecutive MD5 bytes
print("\n=== X_b1[1] high16 dependency ===")
for w in range(15):
    group = defaultdict(set)
    for s in samples:
        md5 = bytes.fromhex(s['md5'])
        xb1_1 = int(s['xb1'][1], 16)
        group[md5[w:w+2]].add(xb1_1 >> 16)
    if all(len(v) == 1 for v in group.values()):
        print(f"  X_b1[1] high16 is a function of MD5[{w}:{w+2}]")

# Same for X_b1[2] across 4 consecutive MD5 bytes
print("\n=== X_b1[2] dependency ===")
for w in range(13):
    group = defaultdict(set)
    for s in samples:
        md5 = bytes.fromhex(s['md5'])
        xb1_2 = int(s['xb1'][2], 16)
        group[md5[w:w+4]].add(xb1_2)
    if all(len(v) == 1 for v in group.values()):
        print(f"  X_b1[2] is a function of MD5[{w}:{w+4}]")
