#!/usr/bin/env python3
"""Sample many ctr values to determine the F(ctr) function in X_b2[0] = X_b1_full[35] ^ F(ctr).

Fix src=b"\x00" seq=1. Vary ctr across a wide range. Compute F(ctr) and look for pattern.
"""
import ctypes, os, sys
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

_ = sign_once(b"\x00", 0, 0, b"init")
_ = sign_once(b"\x00", 1, 100)

import pure_cipher
# First compute X_b1_full[35] for src=00 (constant across ctr)
sig0 = sign_once(b"\x00", 1, 0)
x1, x2 = pure_cipher.recover_states_from_sign(sig0)
x1_full = pure_cipher.cipher_forward(x1, pure_cipher.RK_B1)
CIPHER_35 = x1_full[35]
print(f"X_b1_full[35] (constant) = 0x{CIPHER_35:08x}")

# Sample across ctr values
ctrs = list(range(0, 20)) + [100, 256, 300, 1000, 10000, 0xFFFF,
                              0x10000, 0x10001, 0x1FFFF, 0x20000,
                              0x100000, 0xDEADBEEF & 0xFFFFFFFF,
                              0xFFFFFFFF, 0xFFFFFFFE]
results = []
for ctr in ctrs:
    sig = sign_once(b"\x00", 1, ctr & 0xFFFFFFFF)
    if len(sig) != 32: continue
    _, x2 = pure_cipher.recover_states_from_sign(sig)
    F = x2[0] ^ CIPHER_35
    results.append((ctr, x2[0], F))
    print(f"  ctr={ctr:>12}=0x{ctr & 0xFFFFFFFF:08x}  X_b2[0]=0x{x2[0]:08x}  F(ctr)=0x{F:08x}")

# Focus on the structure of F(ctr): break into bytes and see which byte depends on what
print("\n=== F(ctr) byte-breakdown ===")
print(f"{'ctr':>12} {'F(ctr)':>10} {'byte0':>5} {'byte1':>5} {'byte2':>5} {'byte3':>5}")
for ctr, x20, F in results:
    b0 = (F >> 24) & 0xFF
    b1 = (F >> 16) & 0xFF
    b2 = (F >> 8) & 0xFF
    b3 = F & 0xFF
    print(f"  {ctr:>10} 0x{F:08x} {b0:>5} {b1:>5} {b2:>5} {b3:>5}")

# Try fit: F(ctr) = 0x60c925c1 ^ g(ctr) where g(0)=0, g(1)=?
base_F = results[0][2]
print(f"\nbase F(0) = 0x{base_F:08x}")
print(f"\n{'ctr':>12} F(ctr)^F(0)")
for ctr, x20, F in results:
    print(f"  {ctr:>10} 0x{F ^ base_F:08x}")
