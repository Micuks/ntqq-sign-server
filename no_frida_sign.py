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
import time
from typing import Optional

import pure_cipher

# Process-global lock serializing wrapper.node native calls.
# wrapper.node holds global VM / MK / PRNG state; concurrent invocations
# corrupt the output. Shared across all _NativeSign instances so that, even
# if multiple providers exist, native calls remain strictly serialized.
_NATIVE_CALL_LOCK = threading.Lock()

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
        return self.sign_full(cmd, src, ctr)["sign"]

    def sign_full(self, cmd: bytes, src: bytes, ctr: int = 100) -> dict:
        """Invoke wrapper.node's native sign function. Returns full output.

        The output buffer is 0x300 bytes: 0x000..0x0FF = token (length at 0x0FF),
        0x100..0x1FF = extra (length at 0x1FF), 0x200..0x2FF = sign (length at 0x2FF).

        seq (4th arg) is empirically a no-op cipher-side when ctr is held
        constant; native sign output is fully determined by (cmd, src, ctr).
        We pass seq=1 for reproducibility. src=b"" is passed with len=0 and a
        1-byte zero scratch buffer (matches NativeSignProvider.sign), so an
        empty payload is distinct from a 1-byte 0x00 payload.
        """
        if src:
            sb = (ctypes.c_ubyte * len(src))(*src)
        else:
            sb = (ctypes.c_ubyte * 1)()  # scratch — won't be read at len=0
        out = (ctypes.c_ubyte * 0x300)()
        with _NATIVE_CALL_LOCK:
            ctypes.c_uint32.from_address(self._counter_addr).value = ctr
            self._sf(cmd, sb, len(src), 1, out)
        raw = bytes(out)
        token_len = raw[0xFF]
        extra_len = raw[0x1FF]
        sign_len = raw[0x2FF]
        return {
            "sign": raw[0x200:0x200 + sign_len],
            "extra": raw[0x100:0x100 + extra_len],
            "token": raw[0x000:0x000 + token_len],
        }


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
        # Per-key in-progress condvars — when two threads ask for the same
        # cold key simultaneously, only the first issues the native call; the
        # rest wait here for the entry to land in the cache.
        self._in_progress: dict = {}
        self._cache: dict = {}
        self._native: Optional[_NativeSign] = None
        self._native_calls = 0
        self._cache_hits = 0
        self._total_native_ms = 0.0
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
        return self._sign_internal(cmd, src, ctr)["sign_bytes"]

    def sign_packet(self, cmd: str, seq: int, src: bytes, ctr: int = 100) -> dict:
        """Sign packet, returning {sign, extra, token} as uppercase hex strings.

        Compatible with sign.NativeSignProvider.sign signature minus the seq arg's
        impact: seq is unused for the cipher (X_b1_init/X_b2[1] don't depend on
        seq, and the round-key schedule does not depend on seq either —
        empirically verified by varying seq with ctr held constant: byte-identical
        sign across seq=1, 2, 3, 100, 12345). ctr controls X_b2[0] high 16 bits.
        Caller may pass any seq value.
        """
        result = self._sign_internal(cmd, src, ctr)
        return {
            "sign": result["sign_bytes"].hex().upper(),
            "extra": result["extra"].hex().upper(),
            "token": result["token"].hex().upper(),
        }

    def _cache_key(self, cmd: str, src: bytes) -> str:
        """Distinguish empty src from a 1-byte 0x00 src — native treats them
        differently (passes len=0 vs len=1), so they MUST live under distinct
        cache keys. We tag empty as the literal token 'empty' to make this
        unambiguous (and avoid colliding with md5(b'') which is a real hash)."""
        if not src:
            return f"{cmd}|empty"
        return f"{cmd}|{hashlib.md5(src).hexdigest()}"

    def _sign_internal(self, cmd: str, src: bytes, ctr: int) -> dict:
        cmd_b = cmd.encode() if isinstance(cmd, str) else cmd
        key = self._cache_key(cmd, src)
        # Critical section: check cache, and if cold, reserve the key so other
        # threads asking for the same key wait instead of racing into _populate.
        populate_owner = False
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                cv = self._in_progress.get(key)
                if cv is None:
                    cv = threading.Condition(self._lock)
                    self._in_progress[key] = cv
                    populate_owner = True
                else:
                    # Wait until the owner finishes populating (or fails).
                    while key not in self._cache and key in self._in_progress:
                        cv.wait()
                    entry = self._cache.get(key)
        if populate_owner and entry is None:
            try:
                entry = self._populate(cmd_b, src, key)
            finally:
                with self._lock:
                    cv = self._in_progress.pop(key, None)
                    if cv is not None:
                        cv.notify_all()
        if entry is None:
            raise RuntimeError(f"populate failed for key={key}")
        self._cache_hits += 1
        token_b = bytes.fromhex(entry.get("token", ""))
        extra_b = bytes.fromhex(entry.get("extra", ""))
        # Special-case the bootstrap ctr — return cached native sign directly
        if entry.get("native_ctr") == ctr and entry.get("native_sign"):
            return {
                "sign_bytes": bytes.fromhex(entry["native_sign"]),
                "extra": extra_b,
                "token": token_b,
            }
        x_b1 = [int(v, 16) for v in entry["x_b1"]]
        x_b2_1 = int(entry["x_b2_1"], 16)
        sig = pure_cipher.compute_sign_from_block1_and_nonce(x_b1, x_b2_1, ctr=ctr)
        return {"sign_bytes": sig, "extra": extra_b, "token": token_b}

    def _populate(self, cmd: bytes, src: bytes, key: str) -> dict:
        self._ensure_native()
        assert self._native is not None
        # Fixed bootstrap ctr — reproducible and avoids ctr-dependent recovery edge cases.
        bootstrap_ctr = 100
        t0 = time.monotonic()
        full = self._native.sign_full(cmd, src, ctr=bootstrap_ctr)
        self._total_native_ms += (time.monotonic() - t0) * 1000.0
        sig = full["sign"]
        self._native_calls += 1
        if len(sig) != 32:
            raise RuntimeError(f"Native sign returned unexpected length {len(sig)}")
        x1, x2 = pure_cipher.recover_states_from_sign(sig)
        entry = {
            "x_b1": [f"{v:08x}" for v in x1],
            "x_b2_1": f"{x2[1]:08x}",
            "native_ctr": bootstrap_ctr,
            "native_sign": sig.hex(),
            "extra": full["extra"].hex(),
            "token": full["token"].hex(),
        }
        with self._lock:
            self._cache[key] = entry
            self._save_cache()
        return entry

    @property
    def stats(self) -> dict:
        avg_ms = (self._total_native_ms / self._native_calls) if self._native_calls else 0.0
        # Both "native_calls" (clearer naming for the pure-Python server) and
        # "call_count" (compat with sign.py's stats() schema) are reported so
        # this provider is drop-in compatible with sign.py's /stats consumers.
        return {
            "native_calls": self._native_calls,
            "call_count": self._native_calls,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
            "total_native_ms": round(self._total_native_ms, 2),
            "avg_native_ms": round(avg_ms, 2),
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
