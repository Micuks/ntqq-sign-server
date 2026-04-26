#!/usr/bin/env python3
"""Use hybrid_sign directly with the same src that fails in test_hybrid.py."""
import ctypes, os, sys, tempfile
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

class NativeWrapper:
    def __init__(self):
        self._last_ctr = 100
    def set_ctr(self, c): self._last_ctr = c
    def sign(self, cmd, seq, src):
        sb = (ctypes.c_ubyte * max(len(src),1))(*src)
        out = (ctypes.c_ubyte * 0x300)()
        ctypes.c_uint32.from_address(COUNTER).value = self._last_ctr
        sf(cmd.encode(), sb, len(src), seq, out)
        raw = bytes(out)
        sign_bytes = raw[0x200:0x200+raw[0x2FF]]
        return {"sign": sign_bytes.hex().upper(), "extra": "", "token": ""}

native = NativeWrapper()
# Warm
native.set_ctr(0); native.sign("init", 0, b"\x00")
native.set_ctr(100); native.sign("wtlogin.login", 1, b"\x00")

import hybrid_sign

src = bytes.fromhex("70")
print(f"src={src.hex()}")

with tempfile.TemporaryDirectory() as tmp:
    cache_path = os.path.join(tmp, "c.json")
    hybrid = hybrid_sign.HybridSignProvider(native, cache_path=cache_path)

    # Iterate ctr values; first call is cache miss
    for ctr in [1, 100, 1000, 65535]:
        native.set_ctr(ctr)
        truth = native.sign("wtlogin.login", 1, src)
        hyb = hybrid.sign("wtlogin.login", 1, src, ctr=ctr)
        ok = truth["sign"] == hyb["sign"]
        print(f"ctr={ctr}: truth={truth['sign']}, hybrid={hyb['sign']}, match={ok}")

    print(f"\nCache contents: {hybrid._cache}")
