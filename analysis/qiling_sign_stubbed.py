"""Qiling emulation with PLT-entry stub interception.

Qiling's loader doesn't relocate wrapper.node's GOT entries (treats it as a
.node file rather than dynamic library). We intercept PLT entries at runtime
and provide Python stubs for libc/libstdc++ functions.

Critically, Qiling provides better infrastructure than raw Unicorn:
- Proper Linux process state (FS_BASE, GDT, vsyscall page)
- Auto-mapped stack
- ql.mem.read/write convenience
- Exception emulation (XSAVE/XSAVEC handled)

Usage:
    SRC_BYTE=0x00 python3 analysis/qiling_sign_stubbed.py
"""
import os, sys, struct, subprocess
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
ROOTFS = '/tmp/qiling_rootfs'

SIGN_FN_OFFSET = 0x56D81D1
COUNTER_OFFSET = 0x7DD868C

EXPECTED = {
    0x00: 'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f',
    0x42: '9fb5974211ac4e148579b26575ecc8c34f3dfd82728cecaf00ab0bfb394186e3',
}


def load_plt_table():
    """Load PLT name → offset map via objdump."""
    out = subprocess.check_output(
        ['objdump', '-d', '--section=.plt', WRAPPER], text=True)
    plt_offset_to_name = {}
    for line in out.split('\n'):
        if '@plt>:' in line:
            parts = line.split()
            offset = int(parts[0], 16)
            name = parts[1].rstrip(':').strip('<>').replace('@plt', '')
            plt_offset_to_name[offset] = name
    return plt_offset_to_name


PLT_TABLE = load_plt_table()
PLT_LO = min(PLT_TABLE.keys()) if PLT_TABLE else 0
PLT_HI = max(PLT_TABLE.keys()) + 16 if PLT_TABLE else 0
print(f"[+] {len(PLT_TABLE)} PLT entries; range 0x{PLT_LO:x}-0x{PLT_HI:x}")


def main():
    src_byte = int(os.environ.get('SRC_BYTE', '0x00'), 16)
    ctr_val = int(os.environ.get('CTR', '100'))

    ql = Qiling([WRAPPER], ROOTFS,
                archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX,
                console=False, verbose=QL_VERBOSE.OFF)
    base = ql.loader.load_address
    print(f"[+] Qiling loaded; base=0x{base:x}")

    # Set up I/O buffers
    cmd_va = ql.mem.map_anywhere(0x1000)
    ql.mem.write(cmd_va, b'wtlogin.login\x00')
    src_va = ql.mem.map_anywhere(0x1000)
    ql.mem.write(src_va, bytes([src_byte]))
    out_va = ql.mem.map_anywhere(0x1000)
    ql.mem.write(out_va, b'\x00' * 0x300)

    # Heap region for stub allocations
    HEAP_VA = ql.mem.map_anywhere(0x4000000)  # 64 MB
    heap_top = [HEAP_VA]
    def alloc(n):
        n = (n + 0xf) & ~0xf
        p = heap_top[0]; heap_top[0] += max(n, 16)
        return p

    # Counter
    ql.mem.write(base + COUNTER_OFFSET, struct.pack('<I', ctr_val))

    # Args
    ql.arch.regs.rdi = cmd_va
    ql.arch.regs.rsi = src_va
    ql.arch.regs.rdx = 1
    ql.arch.regs.rcx = 1
    ql.arch.regs.r8 = out_va

    # Sentinel return address
    SENTINEL = 0xCAFEBABEDEAD000
    rsp = ql.arch.regs.rsp - 8
    ql.mem.write(rsp, struct.pack('<Q', SENTINEL))
    ql.arch.regs.rsp = rsp

    # PLT stub handler
    stub_calls = {}
    def stub_handle(ql_, plt_va):
        plt_off = plt_va - base
        plt_idx = (plt_off - 0x7ae5ba0) // 16
        plt_entry_off = 0x7ae5ba0 + plt_idx * 16
        name = PLT_TABLE.get(plt_entry_off, f'plt+0x{plt_off:x}')
        stub_calls[name] = stub_calls.get(name, 0) + 1
        rdi = ql_.arch.regs.rdi; rsi = ql_.arch.regs.rsi
        rdx = ql_.arch.regs.rdx; rcx = ql_.arch.regs.rcx
        ret_val = 0

        if name in ('malloc', '_Znwm', '_Znam', '_ZnwmRKSt9nothrow_t'):
            ret_val = alloc(rdi if rdi > 0 else 16)
        elif name in ('memcpy', 'memmove'):
            if 0 < rdx < 0x100000:
                try: ql_.mem.write(rdi, bytes(ql_.mem.read(rsi, rdx)))
                except: pass
            ret_val = rdi
        elif name == 'memset':
            if 0 < rdx < 0x100000:
                try: ql_.mem.write(rdi, bytes([rsi & 0xff]) * rdx)
                except: pass
            ret_val = rdi
        elif name in ('memcmp', 'bcmp'):
            if rdx == 0: ret_val = 0
            else:
                try:
                    a = bytes(ql_.mem.read(rdi, rdx)); b = bytes(ql_.mem.read(rsi, rdx))
                    ret_val = 0 if a == b else (a[0] - b[0])
                except: ret_val = 0
        elif name == 'strlen':
            sz = 0
            try:
                while sz < 0x10000:
                    if ql_.mem.read(rdi + sz, 1)[0] == 0: break
                    sz += 1
            except: pass
            ret_val = sz
        elif name == 'strcmp':
            sz = 0
            try:
                while True:
                    a = ql_.mem.read(rdi+sz,1)[0]; b = ql_.mem.read(rsi+sz,1)[0]
                    if a != b: ret_val = a - b; break
                    if a == 0: ret_val = 0; break
                    sz += 1
            except: ret_val = 0
        elif name in ('free', '_ZdlPv', '_ZdaPv'):
            ret_val = 0
        elif name == '_ZNSt6vectorIlSaIlEE12emplace_backIJRlEEES3_DpOT_':
            this_ptr = rdi; val_ptr = rsi
            val = struct.unpack('<q', bytes(ql_.mem.read(val_ptr, 8)))[0]
            begin = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr, 8)))[0]
            end = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr+8, 8)))[0]
            cap = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr+16, 8)))[0]
            size = (end - begin) // 8 if begin else 0
            capacity = (cap - begin) // 8 if begin else 0
            if size < capacity:
                ql_.mem.write(end, struct.pack('<q', val))
                ql_.mem.write(this_ptr+8, struct.pack('<Q', end+8))
            else:
                new_cap = max(capacity * 2, 4)
                new_buf = alloc(new_cap * 8)
                if begin and size: ql_.mem.write(new_buf, bytes(ql_.mem.read(begin, size*8)))
                ql_.mem.write(new_buf + size*8, struct.pack('<q', val))
                ql_.mem.write(this_ptr, struct.pack('<Q', new_buf))
                ql_.mem.write(this_ptr+8, struct.pack('<Q', new_buf + (size+1)*8))
                ql_.mem.write(this_ptr+16, struct.pack('<Q', new_buf + new_cap*8))
            ret_val = 0
        elif name == '_ZNSt6vectorIlSaIlEE17_M_realloc_insertIJRlEEEvN9__gnu_cxx17__normal_iteratorIPlS1_EEDpOT_':
            this_ptr = rdi; val_ptr = rdx
            val = struct.unpack('<q', bytes(ql_.mem.read(val_ptr, 8)))[0]
            begin = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr, 8)))[0]
            end = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr+8, 8)))[0]
            size = (end - begin) // 8 if begin else 0
            new_cap = max(size * 2, 4)
            new_buf = alloc(new_cap * 8)
            if begin and size: ql_.mem.write(new_buf, bytes(ql_.mem.read(begin, size*8)))
            ql_.mem.write(new_buf + size*8, struct.pack('<q', val))
            ql_.mem.write(this_ptr, struct.pack('<Q', new_buf))
            ql_.mem.write(this_ptr+8, struct.pack('<Q', new_buf + (size+1)*8))
            ql_.mem.write(this_ptr+16, struct.pack('<Q', new_buf + new_cap*8))
            ret_val = 0
        elif name in ('_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag',
                      '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag'):
            this_ptr = rdi; p, q = rsi, rdx
            length = q - p
            if 0 < length < 0x10000:
                chars = bytes(ql_.mem.read(p, length))
                if length <= 15:
                    buf_va = this_ptr + 16
                    ql_.mem.write(buf_va, chars + b'\x00')
                    ql_.mem.write(this_ptr, struct.pack('<Q', buf_va))
                    ql_.mem.write(this_ptr+8, struct.pack('<Q', length))
                else:
                    buf = alloc(length + 1)
                    ql_.mem.write(buf, chars + b'\x00')
                    ql_.mem.write(this_ptr, struct.pack('<Q', buf))
                    ql_.mem.write(this_ptr+8, struct.pack('<Q', length))
                    ql_.mem.write(this_ptr+16, struct.pack('<Q', length))
            ret_val = 0
        elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm':
            this_ptr = rdi
            pos, n1, p, n2 = rsi, rdx, rcx, ql_.arch.regs.r8
            try:
                buf_ptr = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr, 8)))[0]
                cur_len = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr+8, 8)))[0]
                old = bytes(ql_.mem.read(buf_ptr, cur_len)) if (buf_ptr and cur_len < 0x10000) else b''
                new_data = bytes(ql_.mem.read(p, n2)) if (p and n2) else b''
                new_str = old[:pos] + new_data + old[pos + n1:]
                new_len = len(new_str)
                if new_len <= 15:
                    buf_va = this_ptr + 16
                    ql_.mem.write(buf_va, new_str + b'\x00')
                    ql_.mem.write(this_ptr, struct.pack('<Q', buf_va))
                    ql_.mem.write(this_ptr+8, struct.pack('<Q', new_len))
                else:
                    buf = alloc(new_len + 1)
                    ql_.mem.write(buf, new_str + b'\x00')
                    ql_.mem.write(this_ptr, struct.pack('<Q', buf))
                    ql_.mem.write(this_ptr+8, struct.pack('<Q', new_len))
                    ql_.mem.write(this_ptr+16, struct.pack('<Q', new_len))
            except: pass
            ret_val = this_ptr
        elif name == '_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4findEPKcmm':
            this_ptr = rdi; p, pos, n = rsi, rdx, rcx
            try:
                buf_ptr = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr, 8)))[0]
                cur_len = struct.unpack('<Q', bytes(ql_.mem.read(this_ptr+8, 8)))[0]
                if buf_ptr and cur_len < 0x10000:
                    haystack = bytes(ql_.mem.read(buf_ptr, cur_len))
                    needle = bytes(ql_.mem.read(p, n)) if n > 0 else b''
                    idx = haystack.find(needle, pos)
                    ret_val = idx if idx >= 0 else 0xFFFFFFFFFFFFFFFF
                else:
                    ret_val = 0xFFFFFFFFFFFFFFFF
            except: ret_val = 0xFFFFFFFFFFFFFFFF
        elif name == '_ZNSt6thread15_M_start_threadESt10unique_ptrINS_6_StateESt14default_deleteIS1_EEPFvvE':
            thread_ptr = rdi
            ql_.mem.write(thread_ptr, struct.pack('<Q', 0xDEAD0001))
            try: ql_.mem.write(rsi, struct.pack('<Q', 0))
            except: pass
            ret_val = 0
        elif name == '_ZNSt6thread4joinEv':
            ql_.mem.write(rdi, struct.pack('<Q', 0))
            ret_val = 0
        elif name in ('_ZNSt13__future_base12_Result_baseC2Ev',
                      '_ZNSt13__future_base12_Result_baseD2Ev'):
            ret_val = rdi
        elif name in ('srand', 'madvise', '__cxa_atexit', 'pthread_once',
                      'pthread_mutex_lock', 'pthread_mutex_unlock', 'time',
                      'pthread_self', '__cxa_finalize', '__errno_location',
                      'getpid', 'rand', 'clock_gettime',
                      '_ZNSt6chrono3_V212system_clock3nowEv',
                      '_ZSt20__throw_system_errori', 'fopen', 'fgets', 'fclose',
                      'syscall', 'dladdr', '__cxa_finalize'):
            ret_val = 0
        elif name == '__tls_get_addr':
            ret_val = alloc(256)
        elif name in ('snprintf', 'sprintf', 'vsnprintf'):
            s = rdi
            if s:
                try: ql_.mem.write(s, b'\x00')
                except: pass
            ret_val = 0
        elif name == '__stack_chk_fail':
            ret_val = 0
        else:
            ret_val = alloc(256)

        ql_.arch.regs.rax = ret_val
        # Pop return address and jump
        rsp = ql_.arch.regs.rsp
        ret_addr = struct.unpack('<Q', bytes(ql_.mem.read(rsp, 8)))[0]
        ql_.arch.regs.rsp = rsp + 8
        ql_.arch.regs.rip = ret_addr

    # Hook code: detect PLT entry execution
    instr_count = [0]
    PLT_LO_VA = base + 0x7ae5ba0
    PLT_HI_VA = base + PLT_HI

    def hook_code(ql_, addr, size):
        instr_count[0] += 1
        if PLT_LO_VA <= addr < PLT_HI_VA:
            stub_handle(ql_, addr)

    ql.hook_code(hook_code)

    def hook_mem_invalid(ql_, access, addr, size, value):
        rip = ql_.arch.regs.rip
        print(f"[!] Invalid mem at RIP=0x{rip-base:x} (rip-base) access={access} addr=0x{addr:x} sz={size}")
        return False
    ql.hook_mem_unmapped(hook_mem_invalid)

    sign_fn_va = base + SIGN_FN_OFFSET
    print(f"[+] Calling sign_fn at 0x{sign_fn_va:x}")
    try:
        ql.run(begin=sign_fn_va, end=SENTINEL, count=20_000_000)
    except Exception as e:
        print(f"[!] Run exception: {type(e).__name__}: {e}")

    print(f"[+] Total instructions: {instr_count[0]}")

    # Read output
    out = bytes(ql.mem.read(out_va, 0x300))
    sign_len = out[0x2FF]
    print(f"\nOUT buffer:")
    print(f"  sign_len: {sign_len}")
    print(f"  sign[0:32]: {out[0x200:0x220].hex()}")
    if src_byte in EXPECTED:
        exp = bytes.fromhex(EXPECTED[src_byte])
        print(f"  expected: {exp.hex()}")
        match = out[0x200:0x220] == exp
        print(f"  {'✅ MATCH' if match else '❌ MISMATCH'}")

    print(f"\nStub calls ({len(stub_calls)} distinct):")
    for nm, c in sorted(stub_calls.items(), key=lambda x: -x[1])[:25]:
        print(f"  {c:>5d}x  {nm}")


if __name__ == '__main__':
    main()
