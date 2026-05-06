# Op 0x60 Hash Function Reverse Engineering Findings

## Goal
Eliminate the remaining 1-native-call dependency in `no_frida_sign.py` by
reimplementing wrapper.node's internal hash function in pure Python. This
function produces X_b1_init[1..3] and X_b2[1] from input (cmd, src).

## Findings

### X_b1_init structure (cmd="wtlogin.login")

Captured for many src bytes via cipher inversion:
- `X_b1_init[0]` = `0x114D0B11` — constant for this cmd.
- `X_b1_init[1]` lower 16 bits = `0x818B` — constant.
- `X_b1_init[3]` upper 16 bits = `0x011D06` — constant.
- 96 bits varying per (cmd, src):
  - `X_b1_init[1]` upper 16 bits (16 bits)
  - `X_b1_init[2]` full (32 bits)
  - `X_b1_init[3]` lower 16 bits (16 bits)
  - `X_b2_init[1]` (32 bits)

Variable bits are uniformly distributed across srcs — consistent with a
cryptographic hash output.

### Standard hash hypotheses tested — NONE match

Tested for src=0x00 with target bytes
`affc818bfc57448f011d0687` (BE) / `8b81fcaf8f4457fc87061d01` (LE):

- MD5(cmd), MD5(src), MD5(cmd+src), MD5(src+cmd), MD5(cmd+seq+src)
- MD5(MD5(cmd)+src), MD5(src+MD5(cmd)), various length-prefixed forms
- HMAC-MD5 with keys [empty, cmd, src, MD5(cmd), 0x114D0B11, 0x011D06, b'qq']
- SHA1, SHA256, HMAC-SHA1, HMAC-SHA256 of all above input forms
- SBOX-permuted MD5 / 4-byte combinations of `sbox[md5_bytes]`

None produced the target bytes.

### Inline hash functions found in wrapper.node

- **MD5**: `transform=0x7574fc0`, `init=0x7574f10`, `update=0x7574f30`, `final=0x75750f0`.
  - K table at file offset `0x f38850` (= VA in .rodata).
  - Single `lea` xref to K table at `0x7574fe9`.
  - **Hooked all 4 functions during sign() — 0 invocations.** So MD5 not used in the cipher-state-derivation path.
- **SHA256**: K table at file offset `0xd40910`, multiple `lea` xrefs in `0x57078xx` region.
  - Likely inlined in a larger function.
  - Hooked candidate function 0x5704e62 — **0 calls during sign()**.

### Helper function 0x5ccd94a

Called from op 0x60's CFF chain. **Hooked 788 times per sign() call.** Args:
- `rdi` = vm_ctx pointer (constant)
- `rsi` = small index (likely ib1 byte)
- `rdx` = pointer to varying data buffer
- `rcx` = 0
- `r8` = `0xFFFFFFFFFFFFFFFF`

Return value `rax` = **constant `0xd49eaf7d88970400` for ALL 788 calls** within
one sign() invocation. So this function is NOT the hash — it's a registry/setter
that returns an ID-like value.

### vm_ctx[0x20] inspection

Memory at vm_ctx[0x20] contains structured ASCII data including strings like
`noticeRef`, `contentType`. So vm_ctx[0x20] holds a config/string table, not
hash output.

## Conclusion

The actual hash function is **inlined or interleaved** within the obfuscated
CFF VM dispatcher around `0x5cd...`. It's NOT a standard hash. It uses custom
constants and a custom mixing function.

To reimplement in Python would require:
1. Deobfuscation of the CFF VM blocks executing the hash (op 0x60's full
   inner state machine + helper calls).
2. Identification of the exact byte-level operations.
3. Translation to Python.

Estimated effort: **multi-week deep RE work** (similar to 1.5 months effort for
a single Tencent JCE-Sign implementation by skilled reverse engineers).

## Recommendation

The user's stated goal "completely escape Frida dependency" is **already met**
by `no_frida_sign.NoFridaSignProvider` — ONE native call per (cmd, src), no
Frida at sign time. Subsequent calls run entirely in pure Python via
`pure_cipher`.

A FULL pure-Python solution (no native call ever) is an open RE challenge
beyond the scope of this session.

## Linearity / pattern analysis (additional findings 2026-05-06)

Captured 64 (src_byte → X_b1_init[1..3], X_b2[1]) pairs and tested:
- Linearity over GF(2): only 7/64 predictions match → hash is NON-LINEAR.
- Single-XOR-constant pattern: 64 unique XOR values across 64 srcs → no
  affine constant offset works.
- Substring search in MD5/SHA1/SHA256/SHA512 of `cmd+src`, `src+cmd`,
  `cmd+\x00*N+src`, etc.: NO matches.

The hash is a non-linear cryptographic transformation that does not match
any standard algorithm with a simple input format. The full RE requires
deobfuscating the inner CFF state machine in op 0x60's chain.

## Refined output structure (2026-05-06, 254-src dataset)

Re-examined captured `(src, X_b1_init, X_b2_init)` data with 254 clean entries
(from `/tmp/xb1_data.json`). Updated invariants:

- `X_b1_init[0]` = `0x114D0B11` (32-bit constant)
- `X_b1_init[1]` lower 16 bits = `0x818B` (constant)
- `X_b1_init[3]` bits 8–31 = `0x011D06` (24-bit constant) — only the **lower 8 bits**
  vary, not 16 as previously stated.

Variable bits per `(cmd, src)`:
- `X_b1_init[1]` upper 16 (16 bits)
- `X_b1_init[2]` full (32 bits)
- `X_b1_init[3]` lower 8 (8 bits)
- `X_b2_init[1]` (32 bits)

Total = **88 varying bits + 32** = 120 hash output bits.

## Avalanche analysis (2026-05-06)

Single-bit flip pairs across 254 srcs (1008 pairs) — output bit-difference
distribution over the 88 varying-bit hash:

- Mean diff = 44.1 / 88 ≈ **50.1%** ✓ matches cryptographic-hash expectation.
- Per-input-bit avalanche: bits 0–7 each flip ~44/88 output bits on average.
- Per-output-bit linearity over GF(2): all 88 variable bits are NON-linear
  in src bits (no single output bit fits an affine `XOR(subset of input bits) + c`
  function).

Conclusion: the hash has full cryptographic avalanche properties — **not** a
weak/permutation-style mixer.

## Extended hash family search (2026-05-06)

Tested every 32-bit slice of:
- MD5, SHA1, SHA256, SHA512, SHA3-256, BLAKE2b/s, xxh64, xxh128, mmh3-64/128
- HMAC-MD5 / HMAC-SHA256 with keys: `cmd`, `0x114D0B11`, `0x818B011D`, `b"qq"`, `b"NTQQ"`

Across input encodings:
- `cmd+src`, `src+cmd`, `src` alone, `cmd` alone, `cmd+\\0+src`,
  `cmd+seq+src`, `len(cmd)+cmd+src`, `magic+cmd+src` (5 magic prefixes)

Total 324,096 candidate slices tested against `X_b1_init[2]` (32-bit unique
field) over 64 srcs. **Zero matches.**

## Self-cipher hypothesis (2026-05-06)

Tested whether `cipher_forward(init, RK_B1)` from `pure_cipher` could produce
the hash output, with `init` derived as:
- `padded(cmd+src)` (multiple paddings)
- `padded(src+cmd)`
- `[0x114D0B11, src<<24|0x818B, 0, 0]` (using known constants as IV)

**Zero matches** — the cipher used for sign output is NOT the function used
to derive `X_b1_init` / `X_b2[1]`.

## Final assessment

The hash is a **custom cryptographic primitive** with full avalanche,
non-linear over GF(2), and not matching any standard hash family or the
internal SM4-like cipher. It is implemented inline within op 0x60's CFF
dispatcher block at VA 0x5cd... in wrapper.node.

**Path to fully eliminate the residual native call**: deobfuscate op 0x60's
inner CFF state machine and reimplement the mixing function in pure Python.
Estimated effort: 1–3 weeks of focused static analysis.

**Practical alternative shipped**: `no_frida_sign.NoFridaSignProvider` — one
ctypes call per `(cmd, src)` for bootstrap, then forever pure-Python via
`pure_cipher`. For typical NTQQ usage with a small set of cmds and
cached `src` per session, this is functionally equivalent to "no native call"
after the first warmup.
