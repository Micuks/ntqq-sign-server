#!/usr/bin/env python3
"""Test: does X_b1_init depend on seq/ctr, or is it a pure function of (MD5(src), cmd)?
Also: how does X_b2[1] depend on (MD5(src), seq, ctr)?

Fix src=b"\x00" for cmd=wtlogin.login. Vary seq in {1,2,3,5,10,100} and ctr in
{0,1,2,100,1000,0xFFFF}. Collect X_b1_init and X_b2_init for each. Compare.

Then: for X_b2[1], find what function of (seq, ctr) it is given fixed MD5(src).
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

print("=== Fix src=0x00, vary seq and ctr ===")
results = []
for seq in [1, 2, 3, 5, 10, 100, 0x10000]:
    for ctr in [0, 1, 2, 100, 1000, 0xFFFF]:
        sig = sign_once(b"\x00", seq, ctr)
        if len(sig) != 32:
            continue
        x1, x2 = pure_cipher.recover_states_from_sign(sig)
        results.append((seq, ctr, x1, x2))
        print(f"  seq={seq:>6} ctr={ctr:>5}: X_b1={[hex(v) for v in x1]}  X_b2={[hex(v) for v in x2]}")

# Is X_b1_init identical across seq/ctr variations?
print("\n=== X_b1_init invariance check ===")
base_x1 = results[0][2]
all_same = all(r[2] == base_x1 for r in results)
print(f"All X_b1_init equal across seq/ctr variations: {all_same}")
if not all_same:
    # show the differing ones
    for seq, ctr, x1, x2 in results[:5]:
        print(f"  seq={seq} ctr={ctr}: {[hex(v) for v in x1]}")

# X_b2[1] variation with seq/ctr
print("\n=== X_b2[1] variation with (seq, ctr) for fixed src=0x00 ===")
# Compute X_b1_full[34] for the fixed src=00 — constant across these trials
x1_full = pure_cipher.cipher_forward(base_x1, pure_cipher.RK_B1)
x1_34 = x1_full[34]
print(f"X_b1_full[34] = 0x{x1_34:08x}  (constant because X_b1_init is constant)")
for seq, ctr, x1, x2 in results:
    delta = x1_34 ^ x2[1]
    print(f"  seq={seq:>6} ctr={ctr:>5}: X_b2[1]=0x{x2[1]:08x}  XOR-X_b1_full[34]=0x{delta:08x}")
