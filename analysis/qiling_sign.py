"""Tier 1 prototype: emulate wrapper.node's sign() in Qiling (no native call).

Qiling auto-handles libc/libstdc++/pthread/syscalls via its Linux OS layer,
sidestepping the manual stub work that has dominated the Unicorn iteration
cycle.

Usage:
    SRC_BYTE=0x00 python3 analysis/qiling_sign.py
"""
import os, sys, struct
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
ROOTFS = '/tmp/qiling_rootfs'

SIGN_FN_OFFSET = 0x56D81D1
COUNTER_OFFSET = 0x7DD868C  # global counter; sign_fn reads this

EXPECTED = {
    0x00: 'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f',
    0x42: '9fb5974211ac4e148579b26575ecc8c34f3dfd82728cecaf00ab0bfb394186e3',
}


def main():
    src_byte = int(os.environ.get('SRC_BYTE', '0x00'), 16)
    ctr_val = int(os.environ.get('CTR', '100'))

    ql = Qiling([WRAPPER], ROOTFS,
                archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX,
                console=True, verbose=QL_VERBOSE.OFF)
    base = ql.loader.load_address
    print(f"[+] Qiling loaded; base=0x{base:x}")

    # Set up I/O buffers (allocate from Qiling memory)
    # cmd buffer
    cmd_bytes = b'wtlogin.login\x00'
    cmd_va = ql.mem.map_anywhere(0x1000)
    ql.mem.write(cmd_va, cmd_bytes)
    # src buffer
    src_va = ql.mem.map_anywhere(0x1000)
    ql.mem.write(src_va, bytes([src_byte]))
    # out buffer (sign_fn writes 0x300 bytes)
    out_va = ql.mem.map_anywhere(0x1000)
    ql.mem.write(out_va, b'\x00' * 0x300)
    print(f"[+] Buffers: cmd=0x{cmd_va:x} src=0x{src_va:x} out=0x{out_va:x}")

    # Set the counter to ctr_val (sign_fn reads it from a fixed offset)
    ql.mem.write(base + COUNTER_OFFSET, struct.pack('<I', ctr_val))

    # Set up call: sign_fn(cmd, src_buf, src_len, seq, out_buf)
    # x86-64 SysV: rdi=cmd, rsi=src_buf, rdx=src_len, rcx=seq, r8=out_buf
    ql.arch.regs.rdi = cmd_va
    ql.arch.regs.rsi = src_va
    ql.arch.regs.rdx = 1
    ql.arch.regs.rcx = 1
    ql.arch.regs.r8 = out_va

    # Place a sentinel return address on stack
    SENTINEL = 0xCAFEBABEDEAD000
    rsp = ql.arch.regs.rsp - 8
    ql.mem.write(rsp, struct.pack('<Q', SENTINEL))
    ql.arch.regs.rsp = rsp

    # Hook code to detect early failures and log progress
    instr_count = [0]
    def hook_code(ql_, addr, size):
        instr_count[0] += 1
        if instr_count[0] in (1, 100, 1000, 10000, 100000, 1000000, 5000000):
            print(f"[trace] [{instr_count[0]:>7d}] 0x{addr:x}", flush=True)
    ql.hook_code(hook_code)

    # Catch invalid memory accesses
    def hook_mem_invalid(ql_, access, addr, size, value):
        rip = ql_.arch.regs.rip
        print(f"[!] Invalid mem at RIP=0x{rip:x} access={access} addr=0x{addr:x} sz={size}")
        return False
    ql.hook_mem_unmapped(hook_mem_invalid)

    sign_fn_va = base + SIGN_FN_OFFSET
    print(f"[+] Calling sign_fn at 0x{sign_fn_va:x}, sentinel=0x{SENTINEL:x}")
    try:
        ql.run(begin=sign_fn_va, end=SENTINEL, count=20_000_000)
    except Exception as e:
        print(f"[!] Run exception: {type(e).__name__}: {e}")

    print(f"[+] Total instructions: {instr_count[0]}")

    # Read output buffer
    out = bytes(ql.mem.read(out_va, 0x300))
    sign_len = out[0x2FF]
    sign_bytes = out[0x200:0x200 + sign_len] if sign_len <= 0x60 else out[0x200:0x220]
    print(f"\nOUT buffer:")
    print(f"  sign_len: {sign_len}")
    print(f"  sign[0:32]: {out[0x200:0x220].hex()}")
    if src_byte in EXPECTED:
        exp = bytes.fromhex(EXPECTED[src_byte])
        print(f"  expected: {exp.hex()}")
        print(f"  {'✅ MATCH' if out[0x200:0x220] == exp else '❌ MISMATCH'}")


if __name__ == '__main__':
    main()
