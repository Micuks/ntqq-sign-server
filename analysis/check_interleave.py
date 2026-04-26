#!/usr/bin/env python3
"""Test if many interleaved native calls cause non-determinism."""
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

# Warm
_ = native_sign(b"\x00", 0, 0, b"init")
_ = native_sign(b"\x00", 1, 100)

# Get the canonical sign
canonical = native_sign(b"\x00", 1, 100)
print(f"Canonical sign for src=00 ctr=100: {canonical.hex()}")

# Now interleave with a bunch of other calls and re-check
print("\nInterleaving with 50 different sign calls...")
import random
random.seed(42)
for i in range(50):
    src = bytes(random.getrandbits(8) for _ in range(random.choice([1, 2, 4, 8])))
    ctr = random.choice([0, 1, 100, 1000, 65535])
    _ = native_sign(src, seq=1, ctr=ctr)

after = native_sign(b"\x00", 1, 100)
print(f"After 50 interleaved calls: {after.hex()}")
print(f"Match canonical: {after == canonical}")

# Try setting counter explicitly
print("\n--- Now set ctr explicitly to ensure consistency ---")
ctypes.c_uint32.from_address(COUNTER).value = 100
after2 = native_sign(b"\x00", 1, 100)
print(f"After explicit ctr=100 set: {after2.hex()}")
print(f"Match: {after2 == canonical}")
