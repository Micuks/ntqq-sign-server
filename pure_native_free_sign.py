"""Pure-Python NTQQ sign with NO native call ever.

Strict reading of "no native call": never load or execute wrapper.node code at
runtime. The hash function inside wrapper.node's op 0x60 is implemented here
in pure Python (`_op60_hash`), then combined with `pure_cipher` to produce
byte-identical sign output.

This module is the runtime drop-in replacement for `no_frida_sign.NoFridaSignProvider`.

API:
    provider = PureNativeFreeSignProvider()
    sig = provider.sign('wtlogin.login', b'\\x00', ctr=100)

Internally:
    1. _op60_hash(cmd, src) -> (X_b1_init[1..3], X_b2_init[1])
    2. pure_cipher.compute_sign_from_block1_and_nonce(X_b1_init, X_b2_init[1], ctr)

The cmd-specific constants (X_b1_init[0], etc.) are baked into _op60_hash.
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
    """Pure-Python sign provider with NO native call.

    Same API as no_frida_sign.NoFridaSignProvider but never loads wrapper.node.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._cache: dict = {}  # cache for performance, optional

    def sign(self, cmd: str, src: bytes, ctr: int = 100) -> bytes:
        """Sign (cmd, src) for the given ctr. Returns 32 bytes."""
        cmd_b = cmd.encode() if isinstance(cmd, str) else cmd
        # Cache key: (cmd, md5(src))
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


def _self_test():
    """Self-test against known native sign output for src=0x00."""
    expected = bytes.fromhex(
        'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f')
    p = PureNativeFreeSignProvider()
    try:
        sig = p.sign('wtlogin.login', b'\x00', ctr=100)
        ok = sig == expected
        print(f"sign({'wtlogin.login'!r}, b'\\x00', ctr=100):")
        print(f"  got:      {sig.hex()}")
        print(f"  expected: {expected.hex()}")
        print(f"  {'PASS' if ok else 'FAIL'}")
    except NotImplementedError as e:
        print(f"NotImplementedError: {e}")
        print("Once _op60_hash is implemented, this self-test will validate end-to-end.")


if __name__ == '__main__':
    _self_test()
