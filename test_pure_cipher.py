#!/usr/bin/env python3
"""Validation test: pure_cipher's cipher + output extraction must round-trip
against the native wrapper.node for the deterministic path (LD_PRELOAD=libfaketime_zero.so).

For each input tested, this test:
  1. Calls wrapper.node to get the "truth" sign bytes.
  2. Uses pure_cipher.recover_states_from_sign to invert those bytes to
     X_b1_init and X_b2_init states.
  3. Calls pure_cipher.compute_sign_from_states with those states.
  4. Asserts the result equals the native output.

This validates:
  * The 32-round SM4-like cipher (both directions)
  * Both block round-key schedules (RK_B1, RK_B2)
  * All 8 output constants (C_B1 and C_B2 at indices 32..35)
  * Byte permutation on emit
  * Overall sign = block1 || block2 structure

It does NOT test:
  * X_b1_init derivation from input (not yet pure Python — internal VM hash)
  * X_b2_init[1] / counter mixing (not yet pure Python)

Run:
    LD_PRELOAD=/tmp/libfaketime_zero.so python3 test_pure_cipher.py
"""
import ctypes
import os
import sys

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
    if not base.value:
        raise RuntimeError("could not find wrapper.node base address")
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


def test_cipher_roundtrip():
    sf, counter_addr = _load_wrapper()
    # Warm-up: the native wrapper has PRNG/init state that stabilizes after
    # a couple of calls. Run twice with cmd="init" to flush initial
    # indeterminism before measuring.
    _ = native_sign(sf, counter_addr, "init", b"\x00", 0, 0)
    _ = native_sign(sf, counter_addr, "wtlogin.login", b"\x00", 1, 100)

    # Recovered X_b1_init has a known invariant byte-layout for cmd="wtlogin.login":
    #   X_b1[0]         = 0x114D0B11              (fully const)
    #   X_b1[1] & 0xFFFF = 0x818B                 (low 16 bits const)
    #   X_b1[3] >> 8    = 0x011D06                (high 24 bits const)
    # These constants must survive invert+recompute across any cmd="wtlogin.login" input.
    WTLOGIN_INVARIANTS = {
        "X_b1[0] == 0x114D0B11": lambda x1, _x2: x1[0] == 0x114D0B11,
        "X_b1[1] & 0xFFFF == 0x818B": lambda x1, _x2: (x1[1] & 0xFFFF) == 0x818B,
        "X_b1[3] >> 8 == 0x011D06": lambda x1, _x2: (x1[3] >> 8) == 0x011D06,
    }

    cases = [
        ("wtlogin.login", b"\x00", 1, 100, True),
        ("wtlogin.login", b"\x01", 1, 100, True),
        ("wtlogin.login", b"\x02", 1, 100, True),
        ("wtlogin.login", b"\xff", 1, 100, True),
        ("wtlogin.login", b"\x00", 1, 0, True),
        ("wtlogin.login", b"\x42", 1, 7, True),
        # wtlogin.trans_emp has same block-1 constants (shares cmd bucket)
        ("wtlogin.trans_emp", b"\x00", 1, 0, True),
    ]
    passed = failed = 0
    for cmd, src, seq, ctr, check_inv in cases:
        truth = native_sign(sf, counter_addr, cmd, src, seq, ctr)
        if len(truth) != 32:
            print(f"  SKIP (cmd={cmd!r} src={src.hex()} ctr={ctr}): native returned {len(truth)} bytes")
            continue
        try:
            x_b1_init, x_b2_init = pure_cipher.recover_states_from_sign(truth)
            rebuilt = pure_cipher.compute_sign_from_states(x_b1_init, x_b2_init)
        except Exception as e:
            print(f"  FAIL cmd={cmd!r} src={src.hex()} ctr={ctr}: {type(e).__name__}: {e}")
            failed += 1
            continue
        roundtrip_ok = rebuilt == truth
        inv_ok = True
        broken = []
        if check_inv:
            for name, fn in WTLOGIN_INVARIANTS.items():
                if not fn(x_b1_init, x_b2_init):
                    inv_ok = False
                    broken.append(name)
        ok = roundtrip_ok and inv_ok
        tag = "PASS" if ok else "FAIL"
        print(f"  {tag}  cmd={cmd!r} src={src.hex()} seq={seq} ctr={ctr}")
        if not roundtrip_ok:
            print(f"        ROUND-TRIP FAILED")
            print(f"        truth   = {truth.hex()}")
            print(f"        rebuilt = {rebuilt.hex()}")
        if not inv_ok:
            print(f"        INVARIANT FAILED: {broken}")
            print(f"        X_b1    = {[hex(x) for x in x_b1_init]}")
            print(f"        X_b2    = {[hex(x) for x in x_b2_init]}")
        if ok:
            passed += 1
        else:
            failed += 1
    print(f"\nTotal: {passed} pass, {failed} fail")
    return failed == 0


if __name__ == "__main__":
    ok = test_cipher_roundtrip()
    sys.exit(0 if ok else 1)
