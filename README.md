# NTQQ Sign Server

Self-hosted packet signing server for [Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) and compatible NTQQ protocol implementations.

Loads the official NTQQ `wrapper.node` native library and calls its internal signing function to produce `sign`/`extra`/`token` values for whitelisted SSO commands.

## Quick Start

### Option 1: Run with compressed wrapper.node (recommended)

```bash
# 1. Download QQ Linux and extract wrapper.node
# Visit https://im.qq.com/linuxqq/index.shtml to get the latest .deb
dpkg -x QQ_*.deb /tmp/qq
cp /tmp/qq/opt/QQ/resources/app/wrapper.node ./

# 2. Compress for distribution (132MB → 37MB)
gzip -k wrapper.node

# 3. Build the stub library
gcc -std=c99 -shared -fPIC -o libsymbols.so symbols.c

# 4. Run (auto-extracts wrapper.node.gz on first start)
./extract_and_run.sh --port 8080
```

### Option 2: Run directly

```bash
gcc -std=c99 -shared -fPIC -o libsymbols.so symbols.c
cp /opt/QQ/resources/app/wrapper.node ./

# Set LD_LIBRARY_PATH to include wrapper.node's dependencies
export LD_LIBRARY_PATH=.:/opt/QQ/resources/app/sharp-lib:$LD_LIBRARY_PATH

python3 sign.py --wrapper ./wrapper.node --port 8080
```

### Option 3: Docker

```bash
docker build -t ntqq-sign-server .
docker run -p 8080:8080 ntqq-sign-server
```

> The Dockerfile downloads QQ Linux automatically during build. Override `QQ_DEB_URL` build arg to specify a different version.

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

## Dependencies

The sign server loads `wrapper.node` via `dlopen`, which in turn depends on several system libraries. Required at minimum:

- `libgnutls.so.30`
- `libssl.so.3`, `libcrypto.so.3`
- `gcc` (to compile `libsymbols.so` stub)
- `python3`

When running inside a container or alongside a full QQ installation, all dependencies are typically already available.

## Supported QQ Versions

The server auto-detects the signing function offset by pattern matching. Known offsets:

| QQ Version | Offset |
|-----------|--------|
| 3.2.27-47354 | `0x56D81D1` |
| 3.2.19-39038 | `0x5ADE220` |
| 3.2.18-36497 | `0x59660D0` |

For unknown versions, specify `--offset` manually or the server will attempt auto-detection.

## How It Works

1. Loads `wrapper.node` (NTQQ's native module) via `dlopen()`
2. Finds the module base address using `dl_iterate_phdr()`
3. Calculates the signing function address: `base + offset`
4. Calls the native function with `(cmd, src, src_len, seq, out_buf)`
5. Parses the 768-byte output buffer:
   - `[0x000..0x0FF]`: token (length at byte 0xFF)
   - `[0x100..0x1FF]`: extra (length at byte 0x1FF)
   - `[0x200..0x2FF]`: sign (length at byte 0x2FF)

## File Structure

```
sign.py              # Main server — offset detection, native loading, HTTP API
symbols.c            # Stub for qq_magic_napi_register (required by wrapper.node)
extract_and_run.sh   # Convenience script: decompress + build + run
Dockerfile           # Self-contained Docker build
docker-compose.yml   # Docker Compose config
```

## Credits

- [nimeng1299/SignServer](https://github.com/nimeng1299/SignServer) — Original Rust implementation
- [shixiansi/SingServer](https://github.com/shixiansi/SingServer) — Python reference implementation
- [LagrangeDev/Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) — NTQQ protocol implementation

## License

AGPL-3.0
