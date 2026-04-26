#!/usr/bin/env python3
"""Validate HybridSignProvider against the native wrapper across many inputs.

For each (cmd, src), we verify the cache + pure-Python path produces the SAME
sign as native at multiple ctr values. The first call populates the cache; all
subsequent calls hit cache and run pure-Python.

This test specifically exercises the within-process determinism (which is what
production uses). The wrapper.node has been observed to produce different signs
for the same (cmd, src, ctr) ACROSS processes (likely ASLR/heap-derived state
leaking into the sign), but is fully deterministic within a single process.

Run:
    LD_PRELOAD=/tmp/libfaketime_zero.so python3 test_hybrid.py
"""
import ctypes, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _load_native():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    for lib in [
        "libgnutls.so.30", "libssl.so.3", "libcrypto.so.3", "libpsl.so.5",
        "libnghttp2.so.14", "libbrotlidec.so.1", "libzstd.so.1",
        "libldap.so", "liblber.so", "libcurl.so.4", "librtmp.so.1",
        "libssh2.so.1", "./libsymbols.so",
    ]:
        try:
            ctypes.CDLL(lib, mode=ctypes.RTLD_GLOBAL)
        except OSError:
            pass
    ctypes.CDLL("./wrapper.node", mode=1)
    libc = ctypes.CDLL(None)
    base = ctypes.c_ulong(0)
    CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
    @CB
    def cb(info, _sz, _data):
        addr = ctypes.c_ulong.from_address(info).value
        name_ptr = ctypes.c_void_p.from_address(info + 8).value
        if name_ptr:
            try:
                if "wrapper.node" in ctypes.string_at(name_ptr).decode():
                    base.value = addr
                    return 1
            except Exception:
                pass
        return 0
    libc.dl_iterate_phdr(cb, None)
    SIGN_T = ctypes.CFUNCTYPE(
        ctypes.c_longlong, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
    )
    sf = SIGN_T(base.value + 0x56D81D1)
    counter_addr = base.value + 0x7DD868C

    class NativeWrapper:
        def __init__(self):
            self._last_ctr = 100
        def set_ctr(self, ctr):
            self._last_ctr = ctr
        def sign(self, cmd: str, seq: int, src: bytes):
            sb = (ctypes.c_ubyte * max(len(src), 1))(*src)
            out = (ctypes.c_ubyte * 0x300)()
            ctypes.c_uint32.from_address(counter_addr).value = self._last_ctr
            sf(cmd.encode(), sb, len(src), seq, out)
            raw = bytes(out)
            sign_len = raw[0x2FF]
            return {"sign": raw[0x200:0x200 + sign_len].hex().upper(), "extra": "", "token": ""}

    nw = NativeWrapper()
    nw.set_ctr(0); nw.sign("init", 0, b"\x00")
    nw.set_ctr(100); nw.sign("wtlogin.login", 1, b"\x00")
    return nw


def main():
    import hybrid_sign
    native = _load_native()

    with tempfile.TemporaryDirectory() as tmp:
        cache_path = os.path.join(tmp, "cache.json")
        hybrid = hybrid_sign.HybridSignProvider(native, cache_path=cache_path)

        # Test: for each src, verify hybrid matches native at multiple ctrs.
        # The first call (ctr=1) populates the cache from native. Subsequent
        # calls (ctr=100, 1000, 65535) hit cache and run pure-Python.
        srcs = [bytes([b]) for b in [0, 0x42, 0xff]]
        srcs += [b"hello", b"\x00\x01\x02\x03", b"\xde\xad\xbe\xef"]

        # We sample ctrs known to be safe boundary cases
        ctrs = [1, 100, 1000, 0xFFFE, 0xFFFF]

        passed = failed = 0
        for src in srcs:
            for ctr in ctrs:
                native.set_ctr(ctr)
                truth = native.sign("wtlogin.login", 1, src)
                if len(bytes.fromhex(truth["sign"])) != 32:
                    continue
                hyb = hybrid.sign("wtlogin.login", 1, src, ctr=ctr)
                ok = hyb["sign"] == truth["sign"]
                tag = "PASS" if ok else "FAIL"
                if not ok:
                    print(f"  {tag} src={src.hex()} ctr={ctr}")
                    print(f"        truth   = {truth['sign']}")
                    print(f"        hybrid  = {hyb['sign']}")
                    failed += 1
                else:
                    passed += 1

        s = hybrid.stats()
        print(f"\nstats: {s}")
        print(f"PASS: {passed}, FAIL: {failed}")
        # Sanity: native is called at most once per unique src
        assert s["native_calls"] <= len(srcs), f"too many native calls: {s['native_calls']}"

    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
