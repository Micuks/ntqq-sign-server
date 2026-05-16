# NTQQ Sign Server

Self-hosted packet signing server for [Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) and compatible NTQQ protocol implementations.

Loads the official NTQQ `wrapper.node` and calls its internal signing function to produce `sign`/`extra`/`token` values for whitelisted SSO commands.

## Quick Start

### Prerequisites

- Linux x86_64
- Python 3
- GCC
- QQ Linux installed (or just its `wrapper.node` file)

### Run

```bash
# Build the stub library
gcc -std=c99 -shared -fPIC -o libsymbols.so symbols.c

# Run — point to your QQ installation's wrapper.node
python3 sign.py --wrapper /opt/QQ/resources/app/wrapper.node --port 8080
```

If your QQ installation is elsewhere, or you only have the `wrapper.node` file:

```bash
python3 sign.py --wrapper /path/to/wrapper.node --port 8080
```

The signing function offset is auto-detected. If auto-detection fails, specify it manually with `--offset 0x56D81D1`.

### Pure-Python server (`pure_sign_server.py`)

Drop-in replacement for `sign.py` that calls native `wrapper.node` **once per unique
`(cmd, src)`**, then handles every subsequent `ctr` value entirely in Python via
`pure_cipher`. On a populated `no_frida_cache.json` no native call is made at all.

```bash
# Optional one-time prewarm so the first HTTP request doesn't pay the native cost
python3 pure_sign_server.py --port 8080 --prewarm wtlogin.login \
    trpc.qq_new_tech.status_svc.SsoHeartBeat
```

Same HTTP API as `sign.py`. See `/stats` for `native_calls` vs `cache_hits`.
Adds `ctr` query/body parameter (default `100`) — controls X_b2[0] high 16 bits.

### Docker

```bash
docker build -t ntqq-sign-server .
docker run -p 8080:8080 ntqq-sign-server
```

The Dockerfile downloads QQ Linux automatically during build.

## Lagrange.Core Configuration

Set `SignServerUrl` in `appsettings.json` to this server's root URL.
Lagrange.Core will then POST sign requests to `{SignServerUrl}` and GET
app-info from `{SignServerUrl}/api/sign/appinfo`.

```json
{
  "SignServerUrl": "http://YOUR_HOST:8080/"
}
```

Both the root `POST /` and `POST /api/sign/<version>` endpoints accept sign
requests, so URLs of the form `http://host:port/api/sign/39038` also work —
drop-in compatible with the public `sign.lagrangecore.org` service.

## API

### Sign a packet

```
POST /
Content-Type: application/json

{"cmd": "MessageSvc.PbSendMsg", "seq": 12345, "src": "0A0B0C..."}
```

Response:

```json
{
  "platform": "Linux",
  "version": "3.2.27-47354",
  "value": {
    "sign": "AABB...",
    "extra": "CCDD...",
    "token": "EEFF..."
  }
}
```

`GET /?cmd=...&seq=...&src=...` is also accepted (same parameters as query string).

### Health, version, and stats

```
GET /health           # {"status":"ok", "uptime_seconds":..., "platform":..., "version":...}
GET /api/sign/appinfo # Full Lagrange.Core BotAppInfo: Os, Kernel, VendorOs, CurrentVersion,
                      # MiscBitmap, AppId, SubAppId, AppIdQrCode, AppClientVersion,
                      # MainSigMap, SubSigMap, NTLoginType, PackageName, WtLoginSdk,
                      # PTVersion, SsoVersion
GET /appinfo          # alias for /api/sign/appinfo
GET /stats            # {"uptime_seconds":..., "call_count":..., "avg_native_ms":...}
```

`/health` is wired into the Docker `HEALTHCHECK` — if the native call breaks,
the container is reported unhealthy.

## Integration tests

```bash
# In one shell
python3 sign.py --wrapper ./wrapper.node --port 8080

# In another
python3 test_sign.py --url http://127.0.0.1:8080
```

The suite covers endpoint handlers, malformed input (bad JSON, bad hex, missing
`cmd`), and 10 concurrent sign requests (validates the native-call lock).

## Pure-Python cipher module (`pure_cipher.py`)

A pure-Python reimplementation of the inner SM4-like Feistel cipher and the
32-byte output extraction. Both blocks run the same 32-round cipher with
different round-key schedules (`RK_B1`, `RK_B2`) and output constants
(`C_B1`, `C_B2`). The final sign is produced as:

```
sign[ 0..16] = block1_output = permute(X_b1[34,35,32,33] XOR C_B1[...])
sign[16..32] = block2_output = permute(X_b2[34,35,32,33] XOR C_B2[...])
```

`pure_cipher.py` exposes:
- `compute_sign_from_states(x_b1_init, x_b2_init)` — full forward path
- `recover_states_from_sign(sign_bytes)` — invert: given a sign, recover the
  16-byte block inputs (useful for verification and instrumentation)
- `cipher_forward` / `cipher_backward_from_tail` — the bare cipher

**Not yet reimplemented purely** (the following still require `wrapper.node`):
- `X_b1_init[1..3]` derivation from `(cmd, src, seq)` — internal obfuscated hash
- `X_b2_init[1]` derivation (MK / body mixing)
- Counter mixing into `X_b2_init[0]`
- `rk` derivation from `(cmd, seq)` for arbitrary commands

### Reverse-engineering progress (`analysis/` directory)

The full sign computation runs inside a 16,186-step obfuscated VM. Analysis so far:

- **`analysis/vm_classify.py`** — 71.6% of steps are input-independent (diff same
  across all 4 captured traces); 28.4% (4,593 steps) are input-dependent and
  need real semantics. Only 32 of the 65 opcodes appear in input-dependent work.

- **`analysis/opcode_catalog.py`** — frequency + ib-pattern catalog. Top 5 ops
  (0x32, 0x31, 0x05, 0x02, 0x2f) account for 36% of all calls.

- **`analysis/probe_memory_ops.py`** — opcode determinism. 5 opcodes are 100%
  pure register functions: 0x38, 0x15, 0x3a, 0x06, 0x2a. Most others are 80–99%
  deterministic with residual cases being memory-dependent.

- **`analysis/trace_md5_flow.py`** — **KEY FINDING**: the VM internally computes
  `MD5(src)` and reads it byte-by-byte. Op `0x32 ib=[50,8,5,6]` performs
  `r7 = MD5(src)[r6]` where r6 is the byte index 0..15. Verified exactly:
  for src=0x00, reads match `md5(b'\x00') = 93b885adfe0da089cdf634904fd59f71`.

- **`analysis/identify_xor_constants.py`** — **SECOND KEY FINDING**: each MD5
  byte is XOR'd with two constants drawn from a 20-byte stream
  `550504a20fd4f219c36087685573c224881743b7`. This stream is computed inside the
  VM at runtime — it is NOT a direct MD5/SHA1/HMAC of `(cmd, seq)` on any
  obvious input ordering, and does not appear as static bytes in `wrapper.node`.
  Finding its origin is the remaining blocker for purifying `X_b1_init`.

### Path to a fully pure-Python implementation

The VM's register diffs are captured in 4 traces (src=00,01,02,ff) at
`/tmp/complete_trace_*.json`. The opcode sequence is **input-independent**
(verified zero op-divergence across all 4 traces), so the full bytecode program
can be extracted from any single trace. The remaining work is:

1. **Memory instrumentation**: the traces record register diffs only. A VM
   interpreter needs a memory model — running wrapper.node under `frida` or
   `gdb` to capture memory writes would fill this gap.
2. **Opcode semantics**: with memory visible, remaining opcodes can be
   implemented empirically from `(before_state, ib, diff)` tuples.
3. **Input-injection mapping**: locate where src bytes enter VM memory and
   simulate the deterministic allocator so slot IDs are reproducible.

With these three pieces the sign function becomes fully pure Python (≈150ms
estimated; the native version runs in ~4ms due to JIT-compiled VM).

Validate the pure cipher against the native reference:

```bash
LD_PRELOAD=/path/to/libfaketime_zero.so python3 test_pure_cipher.py
```

The test invokes `wrapper.node` for ground truth, inverts the output via
`recover_states_from_sign`, then forwards through `compute_sign_from_states`
and asserts byte-exact equality. It also verifies the `cmd="wtlogin.login"`
X_b1_init invariants (constant high/low bits) hold after the round trip.

## Supported QQ Versions

| QQ Version | Offset |
|-----------|--------|
| 3.2.27-47354 | `0x56D81D1` |
| 3.2.19-39038 | `0x5ADE220` |
| 3.2.18-36497 | `0x59660D0` |

Offsets are auto-detected by pattern matching. Use `--offset` to override.

## How It Works

1. `dlopen()` loads `wrapper.node`
2. `dl_iterate_phdr()` finds the module base address
3. Calls the native signing function at `base + offset` with `(cmd, src, src_len, seq, out_buf)`
4. Parses the 768-byte output buffer: token at `[0x000]`, extra at `[0x100]`, sign at `[0x200]`

Native calls are serialized with a mutex — `wrapper.node` carries global VM and
PRNG state, so concurrent invocations produce garbage. HTTP handling itself is
threaded (via `ThreadingMixIn`) so parallel clients still benefit from
overlapped request parsing and response writing.

On startup the server issues one `sign("wtlogin.login", 1, b"\x00")` call as a
self-test. Any failure (missing preload deps, wrong offset, broken
`wrapper.node`) aborts the process before the port is opened, so orchestrators
never see a zombie container.

## Related Projects

- [LagrangeDev/Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) — NTQQ protocol implementation (C#)
- [Micuks/waylay-qq-bridge](https://github.com/Micuks/waylay-qq-bridge) — NTQQ headless bridge with OneBot v11

## License

AGPL-3.0
