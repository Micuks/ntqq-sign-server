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
