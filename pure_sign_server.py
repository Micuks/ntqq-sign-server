"""
Pure (Python-cipher) NTQQ Sign Server for Lagrange.Core.

Drop-in replacement for sign.py with the same HTTP API, but uses
NoFridaSignProvider — only ONE native wrapper.node sign() call per
unique (cmd, src) pair, then forever pure Python via pure_cipher.

A populated cache (no_frida_cache.json) lets the server serve sign
requests with NO native call at all. On cache miss, wrapper.node is
loaded lazily and called once to recover cipher state.

HTTP API (compatible with sign.py / Lagrange.Core):
- POST /                       JSON body {cmd, seq, src} -> {value, platform, version}
- GET  /api/sign/appinfo       Lagrange BotAppInfo
- GET  /health                 liveness
- GET  /stats                  cache + native-call metrics
"""

import argparse
import json
import logging
import os
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

from no_frida_sign import NoFridaSignProvider

log = logging.getLogger("pure-sign")

DEFAULT_PORT = 8080
DEFAULT_HOST = "0.0.0.0"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_handler(provider: NoFridaSignProvider, platform: str, version: str, started_at: float):
    class SignHandler(BaseHTTPRequestHandler):
        server_version = "NTQQPureSignServer/1.0"

        def do_POST(self):
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len) if content_len else b""
            try:
                params = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "invalid JSON body"}, 400)
                return
            self._handle_sign(params)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            if path in ("/appinfo", "/api/sign/appinfo"):
                self._handle_appinfo()
                return
            if path in ("/health", "/healthz"):
                self._json({
                    "status": "ok",
                    "uptime_seconds": round(time.time() - started_at, 1),
                    "platform": platform,
                    "version": version,
                })
                return
            if path in ("/stats", "/metrics"):
                self._json({
                    "uptime_seconds": round(time.time() - started_at, 1),
                    **provider.stats,
                })
                return
            params = dict(urllib.parse.parse_qsl(parsed.query))
            self._handle_sign(params)

        def _handle_sign(self, params: dict):
            cmd = params.get("cmd", "")
            try:
                seq = int(params.get("seq", 0))
            except (TypeError, ValueError):
                self._json({"error": "seq must be int"}, 400)
                return
            src_hex = params.get("src", "") or ""
            try:
                ctr = int(params.get("ctr", 100))
            except (TypeError, ValueError):
                ctr = 100
            if not cmd:
                self._json({"error": "missing cmd"}, 400)
                return
            try:
                src = bytes.fromhex(src_hex) if src_hex else b""
            except ValueError:
                self._json({"error": "invalid hex in src"}, 400)
                return
            try:
                value = provider.sign_packet(cmd, seq, src, ctr=ctr)
            except Exception as e:
                log.exception("sign failed cmd=%s src_len=%d", cmd, len(src))
                self._json({"error": str(e)}, 500)
                return
            self._json({"platform": platform, "version": version, "value": value})

        def _handle_appinfo(self):
            self._json({
                "Os": "Linux",
                "Kernel": "Linux",
                "VendorOs": "linux",
                "CurrentVersion": version,
                "MiscBitmap": 32764,
                "PTVersion": "2.0.0",
                "SsoVersion": 19,
                "PackageName": "com.tencent.qq",
                "WtLoginSdk": "nt.wtlogin.0.0.1",
                "AppId": 1600001615,
                "SubAppId": 537341034,
                "AppIdQrCode": 537341034,
                "AppClientVersion": 13172,
                "MainSigMap": 169742560,
                "SubSigMap": 0,
                "NTLoginType": 1,
                "platform": platform,
                "version": version,
            })

        def _json(self, data: dict, status: int = 200):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            log.info("%s - %s", self.address_string(), format % args)

    return SignHandler


def main():
    parser = argparse.ArgumentParser(
        description="Pure-Python NTQQ Sign Server (cipher in Python, lazy native bootstrap)"
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Listen host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Listen port (default: {DEFAULT_PORT})")
    parser.add_argument("--cache", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                         "no_frida_cache.json"),
                        help="Path to cipher-state cache file")
    parser.add_argument("--version", default="3.2.27-47354", help="QQ version string for appinfo")
    parser.add_argument("--platform", default="Linux", help="Platform string for appinfo")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))
    parser.add_argument("--prewarm", nargs="*", default=None, metavar="CMD",
                        help="Commands to pre-warm cache for (with src=0x00). Triggers one "
                             "native call per cmd at startup so subsequent requests are pure Python. "
                             "If unset, no prewarm; first request per (cmd, src) triggers native load.")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    provider = NoFridaSignProvider(cache_path=args.cache)
    log.info("loaded cache with %d entries from %s", provider.stats["cache_size"], args.cache)

    if args.prewarm:
        log.info("prewarming cache for %d commands...", len(args.prewarm))
        for cmd in args.prewarm:
            try:
                r = provider.sign_packet(cmd, 1, b"\x00", ctr=100)
                log.info("  prewarmed: %s sign=%s", cmd, r["sign"][:16] + "...")
            except Exception as e:
                log.warning("  failed: %s — %s", cmd, e)

    started_at = time.time()
    log.info("starting pure sign server on %s:%d", args.host, args.port)
    log.info("platform=%s version=%s", args.platform, args.version)
    log.info("POST http://%s:%d/ — Lagrange.Core SignServerUrl", args.host, args.port)
    log.info("cache: %s — native calls happen ONLY on cache miss", args.cache)

    handler = create_handler(provider, args.platform, args.version, started_at)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutdown — final stats: %s", provider.stats)
        server.shutdown()


if __name__ == "__main__":
    main()
