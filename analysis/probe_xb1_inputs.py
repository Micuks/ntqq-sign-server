#!/usr/bin/env python3
"""For each of 4 inputs (00,01,02,ff), call native sign under faketime (seq=1, ctr=100)
and recover X_b1_init + X_b2_init, then correlate with the 20 post-XOR bytes
(= MD5(src) ^ XOR_STREAM).

We want to find the simple algebraic relation:
  X_b1_init[1] high 16 = f(20-byte stream, cmd)
  X_b1_init[2]          = g(20-byte stream, cmd)
  X_b1_init[3] low 8    = h(20-byte stream, cmd)
  + all of X_b2_init
"""
import ctypes, os, sys, hashlib
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')

os.chdir('/mnt/data1/wuql/services/ntqq-sign-server')
for lib in ["libgnutls.so.30","libssl.so.3","libcrypto.so.3","libpsl.so.5",
            "libnghttp2.so.14","libbrotlidec.so.1","libzstd.so.1",
            "libldap.so","liblber.so","libcurl.so.4","librtmp.so.1",
            "libssh2.so.1","./libsymbols.so"]:
    try: ctypes.CDLL(lib, mode=ctypes.RTLD_GLOBAL)
    except OSError: pass
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

def sign_once(src, seq=1, ctr=100, cmd=b"wtlogin.login"):
    sb = (ctypes.c_ubyte * max(len(src),1))(*src)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = ctr
    sf(cmd, sb, len(src), seq, out)
    raw = bytes(out)
    return raw[0x200:0x200+raw[0x2FF]]

# Warm up (first call has indeterminism)
_ = sign_once(b"\x00", 0, 0, b"init")
_ = sign_once(b"\x00", 1, 100)

import pure_cipher
XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

print(f"{'src':>4} {'sign (32 bytes hex)':<66} "
      f"{'X_b1_init':>42} {'X_b2_init':>42}")
results = []
for src_byte in [0x00, 0x01, 0x02, 0xff]:
    src = bytes([src_byte])
    sig = sign_once(src, 1, 100)
    x1, x2 = pure_cipher.recover_states_from_sign(sig)
    md5 = hashlib.md5(src).digest()
    xor20 = bytes(a ^ b for a, b in zip(md5, XOR_STREAM[:16])) + XOR_STREAM[16:20]
    results.append((src, md5, xor20, x1, x2))
    print(f"  {src.hex()} {sig.hex()} "
          f"{[hex(v) for v in x1]} {[hex(v) for v in x2]}")

print("\n=== Correlate 20-byte post-XOR stream with X_b1_init ===")
for src, md5, xor20, x1, x2 in results:
    le = [int.from_bytes(xor20[i:i+4], 'little') for i in range(0, 20, 4)]
    be = [int.from_bytes(xor20[i:i+4], 'big') for i in range(0, 20, 4)]
    print(f"\nsrc={src.hex()}:")
    print(f"  xor20 = {xor20.hex()}")
    print(f"    LE u32: {[hex(x) for x in le]}")
    print(f"    BE u32: {[hex(x) for x in be]}")
    print(f"  X_b1  = {[hex(v) for v in x1]}")
    print(f"  X_b2  = {[hex(v) for v in x2]}")

# Diff across inputs: XOR each x1 with src=00's x1 and see which bits flip
print("\n=== Bits of X_b1 that flip across inputs (relative to src=00) ===")
_, _, _, x1_base, x2_base = results[0]
for src, md5, xor20, x1, x2 in results:
    d1 = [x1[i] ^ x1_base[i] for i in range(4)]
    d2 = [x2[i] ^ x2_base[i] for i in range(4)]
    print(f"  src={src.hex()}: ΔX_b1 = {[hex(v) for v in d1]}  ΔX_b2 = {[hex(v) for v in d2]}")

# Also print MD5 deltas (LE u32) to compare
print("\n=== MD5(src) diff across inputs ===")
_, md5_base, xor20_base, _, _ = results[0]
for src, md5, xor20, x1, x2 in results:
    dm = [md5[i] ^ md5_base[i] for i in range(16)]
    print(f"  src={src.hex()}: ΔMD5 = {bytes(dm).hex()}")
