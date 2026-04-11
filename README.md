# NTQQ Sign Server

Self-hosted packet signing server for [Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) and compatible NTQQ protocol implementations.

Loads the official NTQQ `wrapper.node` native library and calls its internal signing function to produce `sign`/`extra`/`token` values for whitelisted SSO commands.

## Quick Start

### Option 1: Run directly (requires Linux QQ installed)

```bash
# Build libsymbols.so stub
gcc -std=c99 -shared -fPIC -o libsymbols.so symbols.c

# Copy wrapper.node from your QQ installation
cp /opt/QQ/resources/app/wrapper.node ./

# Run the server
python3 sign.py --wrapper ./wrapper.node --port 8080
```

### Option 2: Docker

```bash
docker build -t ntqq-sign-server .
docker run -p 8080:8080 ntqq-sign-server
```

## Configuration

Configure Lagrange.Core to use your sign server by setting `SignServerUrl` in `appsettings.json`:

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

The server auto-detects the signing function offset. Known offsets:

| QQ Version | Offset |
|-----------|--------|
| 3.2.27-47354 | `0x56D81D1` |
| 3.2.19-39038 | `0x5ADE220` |
| 3.2.18-36497 | `0x59660D0` |

For unknown versions, specify `--offset` manually or the server will attempt pattern-based auto-detection.

## How It Works

1. Loads `wrapper.node` (NTQQ's native module) via `dlopen()`
2. Finds the module base address using `dl_iterate_phdr()`
3. Calculates the signing function address: `base + offset`
4. Calls the native function with `(cmd, src, src_len, seq, out_buf)`
5. Parses the 768-byte output buffer:
   - `[0x000..0x0FF]`: token (length at byte 0xFF)
   - `[0x100..0x1FF]`: extra (length at byte 0x1FF)
   - `[0x200..0x2FF]`: sign (length at byte 0x2FF)

## Credits

- [nimeng1299/SignServer](https://github.com/nimeng1299/SignServer) — Original Rust implementation
- [shixiansi/SingServer](https://github.com/shixiansi/SingServer) — Python reference implementation
- [LagrangeDev/Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) — NTQQ protocol implementation

## License

AGPL-3.0
