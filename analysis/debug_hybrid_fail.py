#!/usr/bin/env python3
"""Isolate why hybrid sign fails for src=6f6b113d at ctr=1."""
import ctypes, os, sys
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')

os.chdir('/mnt/data1/wuql/services/ntqq-sign-server')
for lib in ["libgnutls.so.30","libssl.so.3","libcrypto.so.3","libpsl.so.5",
            "libnghttp2.so.14","libbrotlidec.so.1","libzstd.so.1",
            "libldap.so","liblber.so","libcurl.so.4","librtmp.so.1",
            "libssh2.so.1","./libsymbols.so"]:
    try: ctypes.CDLL(lib, mode=ctypes.RTLD_GLOBAL)
    except: pass
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

def native_sign(src, seq=1, ctr=100, cmd=b"wtlogin.login"):
    sb = (ctypes.c_ubyte * max(len(src),1))(*src)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = ctr
    sf(cmd, sb, len(src), seq, out)
    raw = bytes(out)
    return raw[0x200:0x200+raw[0x2FF]]

# Warm up
_ = native_sign(b"\x00", 0, 0, b"init")
_ = native_sign(b"\x00", 1, 100)

import pure_cipher

src = bytes.fromhex("6f6b113d")
print(f"Testing src={src.hex()}")

# Call native at ctr=1 and ctr=100 to see if X_b1_init really IS ctr-independent
truth_1 = native_sign(src, seq=1, ctr=1)
truth_100 = native_sign(src, seq=1, ctr=100)
truth_65535 = native_sign(src, seq=1, ctr=65535)

print(f"\nTruth sign at ctr=1:    {truth_1.hex()}")
print(f"Truth sign at ctr=100:  {truth_100.hex()}")
print(f"Truth sign at ctr=65535: {truth_65535.hex()}")

x1_1, x2_1 = pure_cipher.recover_states_from_sign(truth_1)
x1_100, x2_100 = pure_cipher.recover_states_from_sign(truth_100)
x1_65535, x2_65535 = pure_cipher.recover_states_from_sign(truth_65535)

print(f"\nRecovered X_b1_init (ctr=1):    {[hex(v) for v in x1_1]}")
print(f"Recovered X_b1_init (ctr=100):  {[hex(v) for v in x1_100]}")
print(f"Recovered X_b1_init (ctr=65535): {[hex(v) for v in x1_65535]}")

print(f"\nRecovered X_b2_init (ctr=1):    {[hex(v) for v in x2_1]}")
print(f"Recovered X_b2_init (ctr=100):  {[hex(v) for v in x2_100]}")
print(f"Recovered X_b2_init (ctr=65535): {[hex(v) for v in x2_65535]}")

# Compute pure-python sign from recovered (ctr=1) state at ctr=1
rebuilt_at_1 = pure_cipher.compute_sign_from_block1_and_nonce(x1_1, x2_1[1], ctr=1)
print(f"\nRebuilt sign (from ctr=1 state, at ctr=1): {rebuilt_at_1.hex()}")
print(f"Truth                                       : {truth_1.hex()}")
print(f"Match: {rebuilt_at_1 == truth_1}")

# Compute from ctr=100 state at ctr=1
rebuilt_at_1_v2 = pure_cipher.compute_sign_from_block1_and_nonce(x1_100, x2_100[1], ctr=1)
print(f"\nRebuilt sign (from ctr=100 state, at ctr=1): {rebuilt_at_1_v2.hex()}")
print(f"Truth                                       : {truth_1.hex()}")
print(f"Match: {rebuilt_at_1_v2 == truth_1}")
