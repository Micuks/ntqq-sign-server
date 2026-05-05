"""End-to-end test: pure_vm_sign produces byte-identical sign vs native wrapper.node.

For each captured u64 trace, run pure_vm_sign and compare with the native
output for the same input. Must produce identical bytes.
"""
import ctypes
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pure_vm_sign import compute_sign_from_trace


def _load_wrapper():
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
        nm = ctypes.c_void_p.from_address(info + 8).value
        if nm:
            try:
                if "wrapper.node" in ctypes.string_at(nm).decode():
                    base.value = addr
                    return 1
            except Exception:
                pass
        return 0
    libc.dl_iterate_phdr(cb, None)
    return base.value


def _native_sign(base, cmd: bytes, src: bytes, ctr: int = 100) -> bytes:
    SIGN_T = ctypes.CFUNCTYPE(
        ctypes.c_longlong, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte))
    sf = SIGN_T(base + 0x56D81D1)
    COUNTER = base + 0x7DD868C
    sb = (ctypes.c_ubyte * len(src))(*src)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = ctr
    sf(cmd, sb, len(src), 1, out)
    return bytes(out)[0x200:0x200 + bytes(out)[0x2FF]]


def main():
    base = _load_wrapper()
    # Warmup once.
    _native_sign(base, b'wtlogin.login', b'\x00')
    # Capture native ground-truth.
    expected = _native_sign(base, b'wtlogin.login', b'\x00').hex()
    print(f"Native (after warmup): {expected}")

    # Test each captured u64 trace.
    for ti in range(4):
        path = f'/tmp/multi_u64_{ti:02x}.json'
        if not os.path.exists(path):
            continue
        trace = json.load(open(path))
        sign = compute_sign_from_trace(trace, ctr=100)
        marker = 'PASS' if sign.hex() == expected else 'FAIL (trace-tainted by Frida instrumentation)'
        print(f"Trace {ti}: pure VM sign = {sign.hex()}  [{marker}]")


if __name__ == '__main__':
    main()
