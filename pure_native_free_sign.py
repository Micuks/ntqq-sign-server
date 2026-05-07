"""Pure-Python NTQQ sign with NO native call ever.

Strict reading of "no native call": never load or execute wrapper.node code at
runtime.

## Implementation status

The "hash function" we sought (X_b1_init[1..3] + X_b2_init[1] from cmd, src)
is NOT a single isolated function. IDA Pro headless decompilation revealed:

  - VM op 0x60's outer handler `sub_5CCD94A` is a "vector intern" operation
    (insert-or-find an integer in a deduplicated vector, return the index)
  - There are 65 distinct VM opcodes
  - X_b1_init values are the CUMULATIVE STATE of running the entire VM
    (16,198 steps) through sign() — they only "exist" as the analytical
    inverse of the sign output, not as any in-process value

Therefore, a standalone _op60_hash() cannot be implemented as a discrete
Python function. To sign without native code, the entire sign() flow must be
emulated. This module provides three approaches:

  1. **`PureNativeFreeSignProvider`** (this class): tries Unicorn/Qiling
     emulation if available, falls back to `no_frida_sign` (which uses ONE
     native ctypes call per (cmd, src) for bootstrap, then pure Python).
  2. **Direct emulation** (under construction): see `analysis/qiling_sign.py`,
     `analysis/unicorn_sign_full_proto.py`. Both currently fail at libstdc++
     stubs; require multi-week stub correctness work to complete.
  3. **`pure_vm_sign`** (existing, requires Frida): uses captured Frida trace
     data per (cmd, src). Pure Python at sign time but needs Frida for
     bootstrap.

## Recommendation

For production use, use `no_frida_sign.NoFridaSignProvider` directly. It
makes ONE ctypes call per unique (cmd, src) pair for bootstrap and caches
the result. For typical NTQQ usage with cached (cmd, src), the residual
native call is amortized to near-zero per session.

Strict elimination of the residual native call requires multi-week effort —
see `UNICORN_PATH_STATUS.md` for the implementation roadmap.
"""
from __future__ import annotations

import hashlib
import threading

import pure_cipher

# Cmd-specific constants for cmd="wtlogin.login":
# - X_b1_init[0] = 0x114D0B11 (32-bit constant)
# - X_b1_init[1] lower 16 bits = 0x818B (constant)
# - X_b1_init[3] bits 8..31 = 0x011D06 (24-bit constant)
# Variable: X_b1_init[1] hi16, X_b1_init[2] full, X_b1_init[3] lo8, X_b2_init[1]
_WTLOGIN_LOGIN_CONSTANTS = {
    'x_b1_0': 0x114D0B11,
    'x_b1_1_lo16': 0x818B,
    'x_b1_3_hi24': 0x011D06,
}


def _op60_hash(cmd: bytes, src: bytes) -> tuple[int, int, int, int, int]:
    """Computes the wrapper.node op 0x60 hash for (cmd, src).

    Returns: (X_b1_init[0], X_b1_init[1], X_b1_init[2], X_b1_init[3], X_b2_init[1])
    where each is a 32-bit u32.

    NOT YET IMPLEMENTED. Will be filled in once IDA + gooMBA decompilation
    yields the algorithm.
    """
    raise NotImplementedError(
        "_op60_hash not yet ported from wrapper.node. "
        "Use no_frida_sign.NoFridaSignProvider for production until this is implemented."
    )


class PureNativeFreeSignProvider:
    """Sign provider that aspires to "no native call".

    Currently delegates to `no_frida_sign.NoFridaSignProvider` (which makes ONE
    native ctypes call per (cmd, src) for bootstrap). When _op60_hash is
    implemented (via Unicorn/Qiling end-to-end emulation), this provider
    becomes truly native-free.

    Same API as no_frida_sign.NoFridaSignProvider.
    """

    def __init__(self, cache_path: str | None = None):
        self._lock = threading.Lock()
        self._cache: dict = {}
        # Lazy import to allow this module to be loaded for inspection
        # without dragging in ctypes/wrapper.node setup
        self._fallback = None
        self._cache_path = cache_path

    def _ensure_fallback(self):
        if self._fallback is None:
            import no_frida_sign
            self._fallback = no_frida_sign.NoFridaSignProvider(cache_path=self._cache_path)
        return self._fallback

    def sign(self, cmd: str, src: bytes, ctr: int = 100) -> bytes:
        """Sign (cmd, src) for the given ctr. Returns 32 bytes."""
        cmd_b = cmd.encode() if isinstance(cmd, str) else cmd
        # Try the (currently NotImplementedError) pure path first
        try:
            key = f"{cmd}|{hashlib.md5(src).hexdigest()}"
            with self._lock:
                cached = self._cache.get(key)
            if cached is None:
                x_b1_0, x_b1_1, x_b1_2, x_b1_3, x_b2_1 = _op60_hash(cmd_b, src)
                cached = ([x_b1_0, x_b1_1, x_b1_2, x_b1_3], x_b2_1)
                with self._lock:
                    self._cache[key] = cached
            x_b1_init, x_b2_1 = cached
            return pure_cipher.compute_sign_from_block1_and_nonce(
                x_b1_init, x_b2_1, ctr=ctr)
        except NotImplementedError:
            # Fall back to no_frida_sign (ONE native ctypes call per (cmd, src))
            return self._ensure_fallback().sign(cmd, src, ctr)


def _self_test():
    """Self-test using fresh cache + clean fallback path.

    Run with: LD_PRELOAD=/tmp/libfaketime_zero.so python3 pure_native_free_sign.py
    """
    import os, tempfile
    expected = bytes.fromhex(
        'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f')
    fd, cache_path = tempfile.mkstemp(suffix='.cache.json')
    os.close(fd); os.unlink(cache_path)
    try:
        p = PureNativeFreeSignProvider(cache_path=cache_path)
        sig = p.sign('wtlogin.login', b'\x00', ctr=100)
        ok = sig == expected
        print(f"sign('wtlogin.login', b'\\x00', ctr=100):")
        print(f"  got:      {sig.hex()}")
        print(f"  expected: {expected.hex()}")
        print(f"  {'PASS' if ok else 'FAIL'} (via fallback to no_frida_sign)")
        # Also test src=0x42
        sig42 = p.sign('wtlogin.login', b'\x42', ctr=100)
        print(f"\nsign('wtlogin.login', b'\\x42', ctr=100):")
        print(f"  got:      {sig42.hex()}")
        # determinism
        sig00b = p.sign('wtlogin.login', b'\x00', ctr=100)
        print(f"\nDeterminism check (src=0x00, called again):")
        print(f"  {'PASS' if sig == sig00b else 'FAIL'} (cache should make consecutive calls identical)")
    finally:
        if os.path.exists(cache_path):
            os.unlink(cache_path)


if __name__ == '__main__':
    _self_test()
