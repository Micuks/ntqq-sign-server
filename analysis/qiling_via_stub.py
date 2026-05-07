"""Run /tmp/qiling_stub via Qiling. The stub has PT_INTERP, so Qiling drives
ld-linux which then dlopens wrapper.node. This avoids the GOT-resolution
issue we hit when loading wrapper.node directly as the main binary.
"""
import os, sys
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

STUB = '/tmp/qiling_stub'
ROOTFS = '/tmp/qiling_rootfs'

def main():
    src = os.environ.get('SRC_BYTE', '0x00')

    # Use a richer rootfs that includes everything wrapper.node needs.
    # Symlink the host's library tree so ld-linux can resolve everything.
    print(f"[+] Stub: {STUB}, rootfs: {ROOTFS}")
    print(f"[+] Args: stub {src}")

    ql = Qiling([STUB, src], ROOTFS,
                archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX,
                console=True, verbose=QL_VERBOSE.OFF)

    print(f"[+] Loaded; load_address=0x{ql.loader.load_address:x}")
    try:
        ql.run(count=200_000_000)
    except Exception as e:
        print(f"[!] Run exception: {type(e).__name__}: {e}")


if __name__ == '__main__':
    main()
