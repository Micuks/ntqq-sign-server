# NTQQ Sign Server

Self-hosted packet signing server for [Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) and compatible NTQQ protocol implementations.

Loads the official NTQQ `wrapper.node` and calls its internal signing function to produce `sign`/`extra`/`token` values for whitelisted SSO commands.

> Looking for the pure-Python re-implementation that needs zero native calls after a one-time bootstrap? See the [`pure-sign-server`](https://github.com/Micuks/ntqq-sign-server/tree/pure-sign-server) branch.

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

### Caching wrapper (`--hybrid`)

`wrapper.node`'s sign call takes a few milliseconds because of the internal VM.
For repeated `(cmd, src)` inputs the call is wasteful — only the counter
changes. The `--hybrid` flag wraps the native provider with `HybridSignProvider`,
which calls `wrapper.node` once per unique `(cmd, MD5(src))` and computes
subsequent counter variations in pure Python via `pure_cipher`:

```bash
python3 sign.py --wrapper ./wrapper.node --port 8080 --hybrid
```

10–100× throughput on repeated `src` payloads. Cache is persisted at
`./oracle_cache.json` (override with `--hybrid-cache`).

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
