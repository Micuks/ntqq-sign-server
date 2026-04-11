"""
NTQQ Sign Server — Provides packet signing for Lagrange.Core and compatible projects.

Loads the official NTQQ wrapper.node via dlopen and calls the internal signing function
to produce sign/extra/token values for whitelisted SSO commands.
"""

import ctypes
import ctypes.util
import os
import sys
import struct
import json
import mmap
from ctypes import c_char_p, c_ubyte, c_uint, c_int, c_longlong, POINTER, CFUNCTYPE

# --- Configuration ---

DEFAULT_PORT = 8080
DEFAULT_HOST = "0.0.0.0"

# Known signing function offsets per QQ version
# Format: "major.minor.patch-build" -> offset
KNOWN_OFFSETS = {
    "3.2.27-47354": 0x56D81D1,
    "3.2.19-39038": 0x5ADE220,
    "3.2.18-36497": 0x59660D0,
}


# --- Offset auto-detection ---

def find_offset_by_pattern(wrapper_path: str):
    """Find signing function offset by searching for the call-site byte pattern."""
    with open(wrapper_path, "rb") as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    # Read ELF program headers to find .text section VA delta
    # LOAD segment with R+E flags: file_offset -> VirtAddr
    elf_magic = data[:4]
    if elf_magic != b'\x7fELF':
        print(f"[!] {wrapper_path} is not an ELF file")
        return None

    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]

    text_delta = 0
    text_start = 0
    text_end = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        if p_flags & 1:  # PF_X (executable)
            text_delta = p_vaddr - p_offset
            text_start = p_offset
            text_end = p_offset + p_filesz
            break

    if text_start == 0:
        print("[!] Could not find .text segment")
        return None

    # Search for the sign function call-site pattern:
    #   mov rsi, [r13+0]     49 8b 75 00
    #   mov edx, [r13+8]     41 8b 55 08
    #   sub edx, esi         29 f2
    #   lea r8, [rsp+XX]     4c 8d 44 24 XX
    #   mov ecx, r12d        44 89 e1
    #   call <sign_func>     e8 XX XX XX XX
    pattern = bytes.fromhex("29f24c8d4424")  # sub edx,esi + lea r8,[rsp+

    pos = text_start
    while True:
        idx = data.find(pattern, pos, text_end)
        if idx < 0:
            break
        pos = idx + 1

        # Check preceding bytes: should have mov rsi/mov edx loading from struct
        pre = data[max(0, idx - 12):idx]
        if b'\x8b' not in pre:
            continue

        # Check following bytes: lea r8 (5 bytes) + mov ecx (3 bytes) + call (5 bytes)
        lea_end = idx + 6  # 29 f2 (2) + 4c 8d 44 24 XX (5) - but pattern includes first 6
        # Actually pattern is: 29 f2 4c 8d 44 24 = 7 bytes, then XX (stack offset) at idx+6
        stack_off = data[idx + 6]
        if stack_off < 0x20 or stack_off > 0x80:
            continue

        # Next should be mov ecx,r12d (44 89 e1) or similar
        after_lea = idx + 7  # after the full lea instruction
        remaining = data[after_lea:after_lea + 16]

        # Find E8 (CALL) within next 8 bytes
        for j in range(min(8, len(remaining) - 4)):
            if remaining[j] == 0xE8:
                disp = struct.unpack('<i', remaining[j + 1:j + 5])[0]
                call_file = after_lea + j
                call_va = call_file + text_delta + 5 + disp
                # Verify target looks like a function (check prologue)
                target_file = call_va - text_delta
                if 0 <= target_file < len(data) - 8:
                    prologue = data[target_file:target_file + 8]
                    # Expected: 55 41 57 41 56 41 55 41 (push rbp; push r15; ...)
                    if prologue[:2] == b'\x55\x41' and prologue[2] in (0x54, 0x55, 0x56, 0x57):
                        data.close()
                        return call_va
                break

    data.close()
    return None


def get_qq_version(qq_dir: str):
    """Read QQ version from package.json."""
    pkg_path = os.path.join(qq_dir, "resources", "app", "package.json")
    if not os.path.exists(pkg_path):
        pkg_path = os.path.join(qq_dir, "package.json")
    if not os.path.exists(pkg_path):
        return None
    with open(pkg_path) as f:
        return json.load(f).get("version")


# --- Native signing via ctypes ---

# dl_iterate_phdr callback type
DlPhdrCallback = CFUNCTYPE(c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)

# Sign function type: long long sign(char* cmd, uint8_t* src, uint len, int seq, uint8_t* out)
SignFunc = CFUNCTYPE(c_longlong, c_char_p, POINTER(c_ubyte), c_uint, c_int, POINTER(c_ubyte))


class NativeSignProvider:
    """Loads wrapper.node and provides packet signing."""

    # Output buffer layout (0x300 bytes total)
    TOKEN_DATA = 0x000
    TOKEN_LEN = 0x0FF
    EXTRA_DATA = 0x100
    EXTRA_LEN = 0x1FF
    SIGN_DATA = 0x200
    SIGN_LEN = 0x2FF
    BUF_SIZE = 0x300

    def __init__(self, wrapper_path: str, offset: int, preload_libs=None):
        self.wrapper_path = os.path.abspath(wrapper_path)
        self.offset = offset
        self.preload_libs = preload_libs if preload_libs is not None else [
            "libgnutls.so.30",
            "libssl.so.3",
            "libcrypto.so.3",
            "libpsl.so.5",
            "libnghttp2.so.14",
            "libbrotlidec.so.1",
            "libzstd.so.1",
            "libldap.so",
            "liblber.so",
            "libcurl.so.4",
            "librtmp.so.1",
            "libssh2.so.1",
        ]
        self._func = None
        self._handles = []

    def load(self):
        """Load wrapper.node and resolve the signing function."""
        wrapper_dir = os.path.dirname(self.wrapper_path)

        # Ensure wrapper dir and sharp-lib subdir are in LD_LIBRARY_PATH
        ld_path = os.environ.get("LD_LIBRARY_PATH", "")
        sharp_lib = os.path.join(wrapper_dir, "sharp-lib")
        for p in [wrapper_dir, sharp_lib]:
            if os.path.isdir(p) and p not in ld_path:
                ld_path = p + ":" + ld_path if ld_path else p
        os.environ["LD_LIBRARY_PATH"] = ld_path
        # Also update ctypes search path
        if hasattr(ctypes, '_dlopen'):
            pass  # LD_LIBRARY_PATH is read by dlopen at call time

        # Compile and write libsymbols.so if needed
        symbols_path = os.path.join(wrapper_dir, "libsymbols.so")
        if not os.path.exists(symbols_path):
            self._build_libsymbols(symbols_path)

        # Preload required libraries
        for lib in self.preload_libs + [symbols_path]:
            lib_path = lib
            # Resolve relative paths against wrapper directory
            if lib.startswith("./"):
                lib_path = os.path.join(wrapper_dir, lib[2:])
            try:
                h = ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)
                self._handles.append(h)
                print(f"[+] Preloaded: {lib_path}")
            except OSError as e:
                print(f"[!] Failed to preload {lib_path}: {e} (non-fatal)")

        # Load wrapper.node
        old_cwd = os.getcwd()
        os.chdir(wrapper_dir)
        try:
            handle = ctypes.CDLL(self.wrapper_path, mode=1)  # RTLD_LAZY = 1
            self._handles.append(handle)
            print(f"[+] Loaded wrapper.node from {self.wrapper_path}")
        finally:
            os.chdir(old_cwd)

        # Find module base via dl_iterate_phdr
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        module_base = ctypes.c_ulong(0)

        @DlPhdrCallback
        def callback(info, size, data):
            # info is a pointer to dl_phdr_info struct
            # dlpi_addr is at offset 0, dlpi_name at offset 8
            addr = ctypes.c_ulong.from_address(info).value
            name_ptr = ctypes.c_void_p.from_address(info + 8).value
            if name_ptr:
                try:
                    name = ctypes.string_at(name_ptr).decode('utf-8', errors='ignore')
                    if "wrapper.node" in name:
                        module_base.value = addr
                        return 1
                except:
                    pass
            return 0

        libc.dl_iterate_phdr(callback, None)

        if module_base.value == 0:
            raise RuntimeError("Failed to find wrapper.node module base address")

        func_addr = module_base.value + self.offset
        print(f"[+] Module base: 0x{module_base.value:x}")
        print(f"[+] Sign function: 0x{func_addr:x} (base + 0x{self.offset:x})")

        self._func = SignFunc(func_addr)

    def sign(self, cmd: str, seq: int, src: bytes) -> dict:
        """Sign a packet and return {sign, extra, token} as hex strings."""
        if not self._func:
            raise RuntimeError("Sign provider not loaded")

        out_buf = (c_ubyte * self.BUF_SIZE)()
        src_buf = (c_ubyte * len(src)).from_buffer_copy(src)

        self._func(
            cmd.encode('utf-8'),
            ctypes.cast(src_buf, POINTER(c_ubyte)),
            c_uint(len(src)),
            c_int(seq),
            ctypes.cast(out_buf, POINTER(c_ubyte)),
        )

        raw = bytes(out_buf)
        token_len = raw[self.TOKEN_LEN]
        extra_len = raw[self.EXTRA_LEN]
        sign_len = raw[self.SIGN_LEN]

        return {
            "token": raw[self.TOKEN_DATA:self.TOKEN_DATA + token_len].hex().upper(),
            "extra": raw[self.EXTRA_DATA:self.EXTRA_DATA + extra_len].hex().upper(),
            "sign": raw[self.SIGN_DATA:self.SIGN_DATA + sign_len].hex().upper(),
        }

    @staticmethod
    def _build_libsymbols(output_path: str):
        """Compile the libsymbols.so stub."""
        import subprocess
        src = 'void qq_magic_napi_register(void* p) { }\n'
        src_path = output_path.replace('.so', '.c')
        with open(src_path, 'w') as f:
            f.write(src)
        subprocess.run(
            ["gcc", "-std=c99", "-shared", "-fPIC", "-o", output_path, src_path],
            check=True,
        )
        os.unlink(src_path)
        print(f"[+] Built {output_path}")


# --- HTTP Server ---

def create_app(provider: NativeSignProvider, platform: str = "Linux", version: str = "3.2.27-47354"):
    """Create Flask/HTTP app with Lagrange.Core compatible API."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse

    class SignHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len)
            try:
                params = json.loads(body)
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON")
                return
            self._handle_sign(params)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path in ("/appinfo", "/api/sign/appinfo"):
                self._handle_appinfo()
                return
            params = dict(urllib.parse.parse_qsl(parsed.query))
            self._handle_sign(params)

        def _handle_sign(self, params: dict):
            cmd = params.get("cmd", "")
            seq = int(params.get("seq", 0))
            src_hex = params.get("src", "")

            if not cmd:
                self._json_response({"error": "missing cmd"}, 400)
                return

            try:
                src = bytes.fromhex(src_hex) if src_hex else b""
            except ValueError:
                self._json_response({"error": "invalid hex in src"}, 400)
                return

            try:
                result = provider.sign(cmd, seq, src)
            except Exception as e:
                self._json_response({"error": str(e)}, 500)
                return

            self._json_response({
                "platform": platform,
                "version": version,
                "value": result,
            })

        def _handle_appinfo(self):
            self._json_response({
                "platform": platform,
                "version": version,
            })

        def _json_response(self, data: dict, status: int = 200):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            print(f"[{self.log_date_time_string()}] {format % args}")

    return HTTPServer, SignHandler


def main():
    import argparse

    parser = argparse.ArgumentParser(description="NTQQ Sign Server for Lagrange.Core")
    parser.add_argument("--wrapper", default="./wrapper.node", help="Path to wrapper.node")
    parser.add_argument("--offset", type=lambda x: int(x, 0), default=None,
                        help="Signing function offset (hex, e.g. 0x56D81D1). Auto-detected if not specified.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Listen host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Listen port (default: {DEFAULT_PORT})")
    parser.add_argument("--qq-dir", default=None, help="QQ installation directory (for version detection)")
    parser.add_argument("--version", default=None, help="QQ version string (e.g. 3.2.27-47354)")
    args = parser.parse_args()

    wrapper_path = os.path.abspath(args.wrapper)
    if not os.path.exists(wrapper_path):
        print(f"[!] wrapper.node not found at {wrapper_path}")
        sys.exit(1)

    # Determine QQ version
    qq_version = args.version
    if not qq_version and args.qq_dir:
        qq_version = get_qq_version(args.qq_dir)
    if not qq_version:
        qq_version = get_qq_version("/opt/QQ")

    # Determine offset
    offset = args.offset
    if offset is None and qq_version and qq_version in KNOWN_OFFSETS:
        offset = KNOWN_OFFSETS[qq_version]
        print(f"[+] Using known offset 0x{offset:x} for QQ {qq_version}")
    if offset is None:
        print(f"[*] Auto-detecting signing function offset...")
        offset = find_offset_by_pattern(wrapper_path)
        if offset:
            print(f"[+] Auto-detected offset: 0x{offset:x}")
        else:
            print("[!] Could not auto-detect offset. Please specify --offset")
            sys.exit(1)

    # Load and start
    provider = NativeSignProvider(wrapper_path, offset)
    provider.load()

    platform = "Linux"
    version_str = qq_version or "unknown"

    print(f"\n[*] Starting sign server on {args.host}:{args.port}")
    print(f"[*] Platform: {platform}, Version: {version_str}")
    print(f"[*] API endpoint: POST http://{args.host}:{args.port}/")
    print(f"[*] Lagrange.Core config: SignServerUrl = http://YOUR_HOST:{args.port}/\n")

    server_class, handler_class = create_app(provider, platform, version_str)
    server = server_class((args.host, args.port), handler_class)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
