#!/usr/bin/env python3
"""Build a 5000-sample dataset of (MD5(src) -> X_b1_init, X_b2[1]) for empirical analysis.
Runs deterministically under LD_PRELOAD=libfaketime_zero.so.

Saves to /tmp/xb_samples_large.json.
"""
import ctypes, os, sys, hashlib, json, time, random
random.seed(42)
def rand_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))
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

OUT = '/tmp/xb_samples_large.json'
target_n = 5000

# Generate inputs: 256 single-byte + many 2-byte + many random N-byte
inputs = []
# All 256 single bytes
for b in range(256):
    inputs.append(bytes([b]))
# 2-byte inputs (256 + ones with structured patterns)
for _ in range(500):
    inputs.append(rand_bytes(2))
# 4-byte inputs (lots)
for _ in range(1000):
    inputs.append(rand_bytes(4))
# 16-byte inputs (matches MD5 length)
for _ in range(1500):
    inputs.append(rand_bytes(16))
# 32-byte
for _ in range(1000):
    inputs.append(rand_bytes(32))
# 64-byte
for _ in range(500):
    inputs.append(rand_bytes(64))

# Deduplicate by hex
seen = set()
unique = []
for src in inputs:
    h = src.hex()
    if h not in seen:
        seen.add(h)
        unique.append(src)
print(f"Unique inputs: {len(unique)}")
inputs = unique[:target_n]

samples = []
t0 = time.time()
for i, src in enumerate(inputs):
    sig = sign_once(src, 1, 100)
    if len(sig) != 32:
        continue
    try:
        x1, x2 = pure_cipher.recover_states_from_sign(sig)
    except Exception:
        continue
    md5 = hashlib.md5(src).digest()
    samples.append({
        'src': src.hex(),
        'md5': md5.hex(),
        'xb1': [f'{v:08x}' for v in x1],
        'xb2': [f'{v:08x}' for v in x2],
    })
    if (i+1) % 500 == 0:
        print(f"  {i+1}/{len(inputs)} ({time.time()-t0:.1f}s)", flush=True)

print(f"\nSaved {len(samples)} samples in {time.time()-t0:.1f}s")
with open(OUT, 'w') as f:
    json.dump(samples, f)
print(f"Wrote {OUT}")
