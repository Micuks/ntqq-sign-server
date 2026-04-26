#!/usr/bin/env python3
"""Validate the minimal-oracle pure-Python sign path.

For each input we:
  1. Call native wrapper to obtain "truth" sign bytes + recover X_b1_init, X_b2_init.
  2. Take JUST (X_b1_init, X_b2_init[1], ctr) as oracle inputs.
  3. Call pure_cipher.compute_sign_from_block1_and_nonce to reproduce the sign.
  4. Assert it matches truth.

This proves:
  * X_b1_init + X_b2[1] + ctr is a COMPLETE oracle for sign bytes.
  * The derive_x_b2_from_block1 formula (including ctr_mix_u16) is correct.

Not validated here:
  * How to obtain X_b1_init and X_b2[1] from (MD5(src), cmd) without calling wrapper.

Run:
    LD_PRELOAD=/tmp/libfaketime_zero.so python3 test_oracle_minimal.py
"""
import ctypes, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pure_cipher


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
    return SIGN_T(base.value + 0x56D81D1), base.value + 0x7DD868C


def native_sign(sf, counter_addr, cmd, src, seq=1, ctr=100):
    sb = (ctypes.c_ubyte * max(len(src), 1))(*src)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(counter_addr).value = ctr
    sf(cmd.encode(), sb, len(src), seq, out)
    raw = bytes(out)
    return raw[0x200:0x200 + raw[0x2FF]]


def test_oracle_minimal():
    sf, counter_addr = _load_wrapper()
    # Stabilize (first call has PRNG indeterminism)
    _ = native_sign(sf, counter_addr, "init", b"\x00", 0, 0)
    _ = native_sign(sf, counter_addr, "wtlogin.login", b"\x00", 1, 100)

    cases = []
    # Variety of src bytes at ctr=100
    for b in [0x00, 0x01, 0x02, 0x42, 0xff]:
        cases.append(("wtlogin.login", bytes([b]), 1, 100))
    # Variety of ctr values with fixed src
    for ctr in [0, 1, 2, 3, 100, 256, 1000, 0xFFFE, 0xFFFF]:
        cases.append(("wtlogin.login", b"\x00", 1, ctr))
    # NOTE: wtlogin.trans_emp has a DIFFERENT X_b2 derivation constant
    # (block-1 matches wtlogin.login, but block-2 differs). Not covered here.

    passed = failed = 0
    for cmd, src, seq, ctr in cases:
        truth = native_sign(sf, counter_addr, cmd, src, seq, ctr)
        if len(truth) != 32:
            print(f"  SKIP cmd={cmd!r} src={src.hex()} ctr={ctr}: len={len(truth)}")
            continue
        try:
            x_b1_init, x_b2_init = pure_cipher.recover_states_from_sign(truth)
            x_b2_1_nonce = x_b2_init[1]
            rebuilt = pure_cipher.compute_sign_from_block1_and_nonce(
                x_b1_init, x_b2_1_nonce, ctr=ctr,
            )
        except Exception as e:
            print(f"  FAIL cmd={cmd!r} src={src.hex()} ctr={ctr}: "
                  f"{type(e).__name__}: {e}")
            failed += 1
            continue
        ok = rebuilt == truth
        tag = "PASS" if ok else "FAIL"
        print(f"  {tag}  cmd={cmd!r} src={src.hex()} seq={seq} ctr={ctr}")
        if not ok:
            print(f"        truth   = {truth.hex()}")
            print(f"        rebuilt = {rebuilt.hex()}")
        if ok:
            passed += 1
        else:
            failed += 1
    print(f"\nTotal: {passed} pass, {failed} fail")
    return failed == 0


if __name__ == "__main__":
    ok = test_oracle_minimal()
    sys.exit(0 if ok else 1)
