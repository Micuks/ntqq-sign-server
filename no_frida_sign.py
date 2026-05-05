"""Frida-free pure-Python NTQQ sign.

This module achieves the "no Frida dependency" goal by combining:
- ONE native wrapper.node call per unique (cmd, src) pair (no Frida — just
  a regular ctypes invocation)
- Cipher inversion via pure_cipher.recover_states_from_sign() to extract
  X_b1_init and X_b2[1] from the native sign output
- pure_cipher.compute_sign_from_block1_and_nonce() for ALL subsequent ctr
  values — fully pure Python, no native dependency

Key API:
    sign(cmd: str, src: bytes, ctr: int = 100) -> bytes

Compared to pure_vm_sign (which requires Frida trace capture), this approach:
- Needs no dynamic instrumentation tool (no Frida, no GDB, no ptrace).
- Uses only ctypes to load wrapper.node and invoke its native sign function ONCE.
- After capture, the (cmd, src) pair is cached forever; new ctr values run
  entirely in pure Python.

Usage:
    from no_frida_sign import NoFridaSignProvider
    provider = NoFridaSignProvider(cache_path='/tmp/sign_cache.json')
    sig = provider.sign('wtlogin.login', b'\\x00', ctr=100)
"""
import ctypes
import hashlib
import json
import os
import threading
from typing import Optional

import pure_cipher

# ----------------------------------------------------------------------------
# Native wrapper loader (no Frida required — pure ctypes).


class _NativeSign:
    """Loads wrapper.node and exposes the sign function as a Python callable.
    Used only on cache misses. After loading, all signing is pure Python."""

    def __init__(self):
        wrapper_dir = os.path.dirname(os.path.abspath(__file__))
        cwd_save = os.getcwd()
        try:
            os.chdir(wrapper_dir)
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
        finally:
            os.chdir(cwd_save)

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
        self._base = base.value
        SIGN_T = ctypes.CFUNCTYPE(
            ctypes.c_longlong, ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_int,
            ctypes.POINTER(ctypes.c_ubyte))
        self._sf = SIGN_T(self._base + 0x56D81D1)
        self._counter_addr = self._base + 0x7DD868C

    def sign(self, cmd: bytes, src: bytes, ctr: int = 100) -> bytes:
        """Invoke wrapper.node's native sign function. Returns 32-byte sign."""
        sb = (ctypes.c_ubyte * len(src))(*src)
        out = (ctypes.c_ubyte * 0x300)()
        ctypes.c_uint32.from_address(self._counter_addr).value = ctr
        self._sf(cmd, sb, len(src), 1, out)
        sign_len = bytes(out)[0x2FF]
        return bytes(out)[0x200:0x200 + sign_len]


# ----------------------------------------------------------------------------
# Frida-free sign provider.


class NoFridaSignProvider:
    """Pure-Python NTQQ sign with one-time native bootstrap per (cmd, src).

    On the FIRST call for a given (cmd, src) pair, makes a single native
    wrapper.node sign() invocation, then uses cipher inversion to recover
    the (X_b1_init, X_b2[1]) cipher state. All subsequent calls (any ctr)
    use pure_cipher to compute the sign — no native, no Frida.
    """

    def __init__(self, cache_path: Optional[str] = None):
        self._cache_path: str = cache_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "no_frida_cache.json")
        self._lock = threading.Lock()
        self._cache: dict = {}
        self._native: Optional[_NativeSign] = None
        self._native_calls = 0
        self._cache_hits = 0
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(self._cache_path):
            try:
                self._cache = json.load(open(self._cache_path))
            except Exception:
                self._cache = {}

    def _save_cache(self):
        try:
            tmp = self._cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._cache, f)
            os.replace(tmp, self._cache_path)
        except Exception:
            pass

    def _ensure_native(self):
        if self._native is None:
            self._native = _NativeSign()

    def sign(self, cmd: str, src: bytes, ctr: int = 100) -> bytes:
        """Sign (cmd, src) for the given ctr. Returns 32 bytes."""
        cmd_b = cmd.encode() if isinstance(cmd, str) else cmd
        md5 = hashlib.md5(src).hexdigest()
        key = f"{cmd}|{md5}"
        with self._lock:
            entry = self._cache.get(key)
        if entry is None:
            entry = self._populate(cmd_b, src, key)
        self._cache_hits += 1
        x_b1 = [int(v, 16) for v in entry["x_b1"]]
        x_b2_1 = int(entry["x_b2_1"], 16)
        # Special-case the bootstrap ctr — return cached native sign directly
        if entry.get("native_ctr") == ctr and entry.get("native_sign"):
            return bytes.fromhex(entry["native_sign"])
        return pure_cipher.compute_sign_from_block1_and_nonce(x_b1, x_b2_1, ctr=ctr)

    def _populate(self, cmd: bytes, src: bytes, key: str) -> dict:
        self._ensure_native()
        assert self._native is not None
        # Fixed bootstrap ctr — reproducible and avoids ctr-dependent recovery edge cases.
        bootstrap_ctr = 100
        sig = self._native.sign(cmd, src, ctr=bootstrap_ctr)
        self._native_calls += 1
        if len(sig) != 32:
            raise RuntimeError(f"Native sign returned unexpected length {len(sig)}")
        x1, x2 = pure_cipher.recover_states_from_sign(sig)
        entry = {
            "x_b1": [f"{v:08x}" for v in x1],
            "x_b2_1": f"{x2[1]:08x}",
            "native_ctr": bootstrap_ctr,
            "native_sign": sig.hex(),
        }
        with self._lock:
            self._cache[key] = entry
            self._save_cache()
        return entry

    @property
    def stats(self) -> dict:
        return {
            "native_calls": self._native_calls,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
        }


# ----------------------------------------------------------------------------

if __name__ == "__main__":
    provider = NoFridaSignProvider(cache_path="/tmp/no_frida_test.cache")
    sig = provider.sign("wtlogin.login", b"\x00", ctr=100)
    print(f"sign(wtlogin.login, 0x00, ctr=100) = {sig.hex()}")
    print(f"stats: {provider.stats}")
    # Second call hits cache
    sig2 = provider.sign("wtlogin.login", b"\x00", ctr=200)
    print(f"sign(wtlogin.login, 0x00, ctr=200) = {sig2.hex()}")
    print(f"stats: {provider.stats}")
    # Cleanup
    if os.path.exists("/tmp/no_frida_test.cache"):
        os.unlink("/tmp/no_frida_test.cache")
