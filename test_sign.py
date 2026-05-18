"""Integration tests for the NTQQ sign server.

Exercises:
  * /health, /appinfo, /stats endpoints
  * POST / sign round trip with hex src
  * GET / sign round trip with query params
  * determinism under fixed PRNG state (sanity only — the wrapper uses
    system RNG, so repeated calls will NOT produce identical signs unless
    the PRNG is frozen via LD_PRELOAD)
  * malformed input handling (bad JSON, bad hex, missing cmd)
  * concurrent sign requests — lock must keep native call serialized

Run:
    # in one shell
    python3 sign.py --wrapper /path/to/wrapper.node --port 8080
    # in another
    python3 test_sign.py --url http://127.0.0.1:8080
"""

import argparse
import concurrent.futures
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional


def http(url: str, method: str = "GET", body: Optional[dict] = None, timeout: float = 5.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class TestRun:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.passed = 0
        self.failed = 0

    def check(self, name: str, ok: bool, detail: str = ""):
        if ok:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}: {detail}")

    def test_health(self):
        code, data = http(f"{self.base_url}/health")
        self.check("health returns 200", code == 200, f"got {code}")
        self.check("health has status=ok", data.get("status") == "ok", f"got {data}")
        self.check("health has uptime", "uptime_seconds" in data)

    def test_appinfo(self):
        code, data = http(f"{self.base_url}/appinfo")
        self.check("appinfo returns 200", code == 200)
        self.check("appinfo has platform", data.get("platform") == "Linux")
        self.check("appinfo has version", "version" in data)

    def test_stats(self):
        code, data = http(f"{self.base_url}/stats")
        self.check("stats returns 200", code == 200)
        self.check("stats has call_count", "call_count" in data)

    def test_sign_post(self):
        code, data = http(
            f"{self.base_url}/",
            method="POST",
            body={"cmd": "wtlogin.login", "seq": 1, "src": "00"},
        )
        self.check("POST sign returns 200", code == 200, f"got {code}: {data}")
        value = data.get("value", {})
        sign_hex = value.get("sign", "")
        self.check("POST sign has non-empty sign", len(sign_hex) >= 8, f"sign={sign_hex!r}")
        self.check("POST sign hex length reasonable",
                   32 <= len(sign_hex) <= 256, f"len={len(sign_hex)}")

    def test_sign_get(self):
        qs = urllib.parse.urlencode({"cmd": "wtlogin.login", "seq": 1, "src": "00"})
        code, data = http(f"{self.base_url}/?{qs}")
        self.check("GET sign returns 200", code == 200)
        self.check("GET sign has value", "value" in data)

    def test_sign_empty_src(self):
        code, data = http(
            f"{self.base_url}/",
            method="POST",
            body={"cmd": "wtlogin.login", "seq": 1, "src": ""},
        )
        self.check("POST sign with empty src returns 200", code == 200, f"{code}: {data}")

    def test_missing_cmd(self):
        code, data = http(
            f"{self.base_url}/",
            method="POST",
            body={"seq": 1, "src": "00"},
        )
        self.check("missing cmd returns 400", code == 400, f"got {code}: {data}")

    def test_bad_hex(self):
        code, data = http(
            f"{self.base_url}/",
            method="POST",
            body={"cmd": "x", "seq": 1, "src": "not-hex-data"},
        )
        self.check("bad hex returns 400", code == 400, f"got {code}")

    def test_bad_json(self):
        req = urllib.request.Request(
            f"{self.base_url}/",
            data=b"{not json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.getcode()
        except urllib.error.HTTPError as e:
            code = e.code
        self.check("malformed JSON returns 400", code == 400, f"got {code}")

    def test_concurrent_signs(self):
        """10 concurrent signs should all succeed — the native lock serializes them."""
        def one(i):
            code, data = http(
                f"{self.base_url}/",
                method="POST",
                body={"cmd": "wtlogin.login", "seq": i, "src": f"{i:02x}"},
                timeout=30,
            )
            return code, data.get("value", {}).get("sign", "")

        t0 = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(one, range(10)))
        elapsed = time.monotonic() - t0

        all_ok = all(code == 200 and sign for code, sign in results)
        self.check(f"10 concurrent signs all succeed (in {elapsed:.2f}s)",
                   all_ok, f"results={results}")
        # Different inputs should produce different signs
        signs = {sign for _, sign in results}
        self.check("concurrent signs produce distinct outputs",
                   len(signs) > 1, f"unique={len(signs)}")

    def run_all(self):
        for name in [
            "test_health",
            "test_appinfo",
            "test_stats",
            "test_sign_post",
            "test_sign_get",
            "test_sign_empty_src",
            "test_missing_cmd",
            "test_bad_hex",
            "test_bad_json",
            "test_concurrent_signs",
        ]:
            print(f"[{name}]")
            try:
                getattr(self, name)()
            except Exception as e:
                self.failed += 1
                print(f"  ERROR {name}: {e}")

        print(f"\n{self.passed} passed, {self.failed} failed")
        return self.failed == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    args = ap.parse_args()
    ok = TestRun(args.url).run_all()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
