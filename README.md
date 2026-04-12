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

### Docker

```bash
docker build -t ntqq-sign-server .
docker run -p 8080:8080 ntqq-sign-server
```

The Dockerfile downloads QQ Linux automatically during build.

## Lagrange.Core Configuration

Set `SignServerUrl` in `appsettings.json`:

```json
{
  "SignServerUrl": "http://YOUR_HOST:8080/"
}
```

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

### App info

```
GET /appinfo
```

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

## Credits

- [nimeng1299/SignServer](https://github.com/nimeng1299/SignServer) — Rust implementation
- [shixiansi/SingServer](https://github.com/shixiansi/SingServer) — Python reference
- [LagrangeDev/Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) — NTQQ protocol implementation

## License

AGPL-3.0
