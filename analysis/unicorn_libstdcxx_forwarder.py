"""Path A: Unicorn emulation with libstdc++ ctypes forwarder.

Strategy:
- mmap a shared ARENA in host memory (one chunk, e.g., 128 MB)
- Map that arena at the SAME virtual address in Unicorn via mem_map_ptr
- Both Unicorn AND native libstdc++ now access the same bytes
- For std::string/std::vector PLT calls, marshal `this` and pointer args from
  Unicorn → host (no copy if VA is in shared arena), call real libstdc++

This eliminates the need to manually re-implement std::string/vector semantics.
"""
import ctypes, struct, json, os, sys, subprocess, mmap
from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64,
                      UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL,
                      UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED,
                      UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
                      UcError)
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
                                 UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
                                 UC_X86_REG_RSP, UC_X86_REG_RBP,
                                 UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
                                 UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
                                 UC_X86_REG_R14, UC_X86_REG_R15,
                                 UC_X86_REG_RIP, UC_X86_REG_FS_BASE,
                                 UC_X86_REG_EFLAGS)
import capstone

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'

# ---------------------------------------------------------------------------
# Shared arena: mmap host memory at a chosen high VA, then map into Unicorn
# at the same VA via mem_map_ptr. Both processes see same bytes.

# Pick a high VA that's likely free. 0x500000000000 is well above typical
# Linux user-space mappings.
SHARED_ARENA_VA = 0x500000000000
SHARED_ARENA_SIZE = 0x8000000  # 128 MB


def alloc_shared_arena():
    """mmap a buffer at the chosen VA. Returns (ctypes_address, mmap_obj)."""
    libc = ctypes.CDLL(None)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                          ctypes.c_int, ctypes.c_int,
                          ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    PROT_READ = 1; PROT_WRITE = 2
    MAP_PRIVATE = 0x02; MAP_ANONYMOUS = 0x20; MAP_FIXED = 0x10
    addr = libc.mmap(SHARED_ARENA_VA, SHARED_ARENA_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
    if addr in (None, 0xFFFFFFFFFFFFFFFF, -1):
        raise RuntimeError(f"mmap fixed at 0x{SHARED_ARENA_VA:x} failed")
    if addr != SHARED_ARENA_VA:
        raise RuntimeError(f"mmap returned 0x{addr:x} instead of 0x{SHARED_ARENA_VA:x}")
    return addr


# ---------------------------------------------------------------------------
# Load real libstdc++ so we can forward std::string/std::vector calls

LIBSTDCXX_PATH = '/lib/x86_64-linux-gnu/libstdc++.so.6'
libstdcxx = ctypes.CDLL(LIBSTDCXX_PATH, mode=ctypes.RTLD_GLOBAL)
libc_full = ctypes.CDLL(None)


def setup_libstdcxx_funcs():
    """Resolve mangled symbols from libstdc++."""
    funcs = {}
    # std::string::_M_construct<char const*>(_M_construct, p, q, forward_iterator_tag)
    name = '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag'
    f = getattr(libstdcxx, name, None)
    if f:
        f.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        f.restype = None
        funcs['_M_construct_PKc'] = f
    # std::string::_M_replace
    name = '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm'
    f = getattr(libstdcxx, name, None)
    if f:
        f.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t,
                      ctypes.c_void_p, ctypes.c_size_t]
        f.restype = ctypes.c_void_p
        funcs['_M_replace'] = f
    # std::string::find
    name = '_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4findEPKcmm'
    f = getattr(libstdcxx, name, None)
    if f:
        f.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                      ctypes.c_size_t, ctypes.c_size_t]
        f.restype = ctypes.c_size_t
        funcs['find'] = f
    # std::vector<long>::emplace_back<long&>
    name = '_ZNSt6vectorIlSaIlEE12emplace_backIJRlEEES3_DpOT_'
    f = getattr(libstdcxx, name, None)
    if f:
        f.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        f.restype = ctypes.c_void_p
        funcs['vector_emplace_back'] = f
    # std::string::_M_assign
    name = '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_assignERKS4_'
    f = getattr(libstdcxx, name, None)
    if f:
        f.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        f.restype = None
        funcs['_M_assign'] = f
    # std::string::_M_append
    name = '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm'
    f = getattr(libstdcxx, name, None)
    if f:
        f.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        f.restype = ctypes.c_void_p
        funcs['_M_append'] = f
    # std::string::_M_create (allocates buffer)
    name = '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm'
    f = getattr(libstdcxx, name, None)
    if f:
        f.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        f.restype = ctypes.c_void_p
        funcs['_M_create'] = f
    return funcs


# ---------------------------------------------------------------------------
# Main emulation setup

def main():
    # 1. Allocate shared arena
    arena_addr = alloc_shared_arena()
    print(f"[+] Shared arena mapped at 0x{arena_addr:x} (size 0x{SHARED_ARENA_SIZE:x})")

    # 2. Load libstdc++ funcs
    libstdcxx_funcs = setup_libstdcxx_funcs()
    print(f"[+] Loaded {len(libstdcxx_funcs)} libstdc++ funcs: {list(libstdcxx_funcs.keys())}")

    # 3. Set up Unicorn
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    PAGE = 0x1000
    def align_down(x): return x & ~(PAGE-1)
    def align_up(x): return (x + PAGE - 1) & ~(PAGE-1)

    WBASE = 0  # wrapper.node at base 0, but we'll patch the ELF magic afterwards
    wdata = open(WRAPPER, 'rb').read()
    e_phoff, = struct.unpack_from('<Q', wdata, 0x20)
    e_phentsize, = struct.unpack_from('<H', wdata, 0x36)
    e_phnum, = struct.unpack_from('<H', wdata, 0x38)
    wrapper_va_ranges = []
    for i in range(e_phnum):
        p = wdata[e_phoff + i*e_phentsize: e_phoff + (i+1)*e_phentsize]
        p_type, p_flags, p_offset, _, p_vaddr, p_filesz, p_memsz, _ = struct.unpack('<IIQQQQQQ', p)
        if p_type != 1: continue
        perms = (UC_PROT_READ if p_flags & 4 else 0) | (UC_PROT_WRITE if p_flags & 2 else 0) | (UC_PROT_EXEC if p_flags & 1 else 0)
        va_start = align_down(WBASE + p_vaddr); va_end = align_up(WBASE + p_vaddr + p_memsz)
        mu.mem_map(va_start, va_end - va_start, perms)
        mu.mem_write(WBASE + p_vaddr, wdata[p_offset:p_offset + p_filesz])
        wrapper_va_ranges.append((va_start, va_end))

    WRAPPER_END = WBASE + 0x7dc0818
    PLT_LO_VA = WBASE + 0x7ae5ba0
    PLT_HI_VA = WBASE + 0x7ae5b90 + 793*16

    # Map shared arena into Unicorn at SAME VA
    mu.mem_map_ptr(arena_addr, SHARED_ARENA_SIZE,
                   UC_PROT_READ | UC_PROT_WRITE,
                   arena_addr)
    print(f"[+] Mapped arena into Unicorn at 0x{arena_addr:x}")

    # Layout in shared arena:
    # [0x000_0000 .. 0x080_0000]  — Stack (8MB, grows down)
    # [0x080_0000 .. 0x100_0000]  — FS canary region (also in arena)
    # [0x100_0000 .. 0x800_0000]  — Heap allocator (112MB)
    STACK_TOP = arena_addr + 0x800000
    FS_VA = arena_addr + 0x900000
    HEAP_START = arena_addr + 0x1000000

    mu.mem_write(FS_VA + 0x28, b'\x00' * 8)
    mu.reg_write(UC_X86_REG_FS_BASE, FS_VA)

    # I/O buffers + heap from shared arena
    heap_top = [HEAP_START]
    def alloc(n):
        n = (n + 0xf) & ~0xf
        p = heap_top[0]; heap_top[0] += max(n, 16)
        return p

    cmd_va = alloc(0x100)
    src_va = alloc(0x100)
    out_va = alloc(0x300)
    src_byte = int(os.environ.get('SRC_BYTE', '0x00'), 16)
    mu.mem_write(cmd_va, b'wtlogin.login\x00')
    mu.mem_write(src_va, bytes([src_byte]))
    mu.mem_write(out_va, b'\x00' * 0x300)

    # PLT name table
    plt_out = subprocess.check_output(['objdump', '-d', '--section=.plt', WRAPPER], text=True)
    plt_addr_to_name = {}
    for line in plt_out.split('\n'):
        if '@plt>:' in line:
            parts = line.split()
            plt_addr_to_name[int(parts[0], 16)] = parts[1].rstrip(':').strip('<>').replace('@plt', '')

    stub_calls = {}
    libfwd_calls = {'attempted': 0, 'forwarded': 0, 'noop': 0}

    def stub_handle(uc, plt_va):
        plt_off = plt_va - WBASE
        plt_idx = (plt_off - 0x7ae5ba0) // 16
        plt_entry = 0x7ae5ba0 + plt_idx * 16
        name = plt_addr_to_name.get(plt_entry, f'plt+0x{plt_off:x}')
        stub_calls[name] = stub_calls.get(name, 0) + 1
        rdi = uc.reg_read(UC_X86_REG_RDI); rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX); rcx = uc.reg_read(UC_X86_REG_RCX)
        ret_val = 0

        # Forward to real libstdc++ when possible
        if name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag':
            libfwd_calls['attempted'] += 1
            f = libstdcxx_funcs.get('_M_construct_PKc')
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                libfwd_calls['forwarded'] += 1
                # `this` must be in shared arena (it is, since stack is in arena)
                # Marshal char range if needed
                if SHARED_ARENA_VA <= rsi < SHARED_ARENA_VA + SHARED_ARENA_SIZE \
                        and SHARED_ARENA_VA <= rdx < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                    f(rdi, rsi, rdx)
                else:
                    length = rdx - rsi if rdx > rsi else 0
                    if 0 < length < 0x10000:
                        buf = alloc(length + 1)
                        try:
                            mu.mem_write(buf, bytes(uc.mem_read(rsi, length)))
                            f(rdi, buf, buf + length)
                        except UcError: pass
                ret_val = 0
            else:
                libfwd_calls['noop'] += 1
                ret_val = 0
        elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag':
            # Same as PKc variant — both have same impl
            f = libstdcxx_funcs.get('_M_construct_PKc')
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                if SHARED_ARENA_VA <= rsi < SHARED_ARENA_VA + SHARED_ARENA_SIZE \
                        and SHARED_ARENA_VA <= rdx < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                    f(rdi, rsi, rdx)
            ret_val = 0
        elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm':
            f = libstdcxx_funcs.get('_M_replace')
            r8 = uc.reg_read(UC_X86_REG_R8)
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                if SHARED_ARENA_VA <= rcx < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                    ret_val = f(rdi, rsi, rdx, rcx, r8)
                else:
                    if 0 < r8 < 0x10000:
                        buf = alloc(r8 + 1)
                        try:
                            mu.mem_write(buf, bytes(uc.mem_read(rcx, r8)))
                            ret_val = f(rdi, rsi, rdx, buf, r8)
                        except UcError: ret_val = rdi
                    else:
                        ret_val = rdi
            else:
                ret_val = rdi
        elif name == '_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4findEPKcmm':
            f = libstdcxx_funcs.get('find')
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                if SHARED_ARENA_VA <= rsi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                    ret_val = f(rdi, rsi, rdx, rcx)
                else:
                    if 0 < rcx < 0x10000:
                        buf = alloc(rcx)
                        try:
                            mu.mem_write(buf, bytes(uc.mem_read(rsi, rcx)))
                            ret_val = f(rdi, buf, rdx, rcx)
                        except UcError: ret_val = 0xFFFFFFFFFFFFFFFF
                    else:
                        ret_val = 0xFFFFFFFFFFFFFFFF
            else:
                ret_val = 0xFFFFFFFFFFFFFFFF
        elif name == '_ZNSt6vectorIlSaIlEE12emplace_backIJRlEEES3_DpOT_':
            f = libstdcxx_funcs.get('vector_emplace_back')
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE \
                    and SHARED_ARENA_VA <= rsi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                ret_val = f(rdi, rsi)
            else:
                ret_val = 0
        elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_assignERKS4_':
            # std::string::_M_assign(this, other_str) — copy other into this
            f = libstdcxx_funcs.get('_M_assign')
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE \
                    and SHARED_ARENA_VA <= rsi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                f(rdi, rsi)
            ret_val = 0
        elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm':
            f = libstdcxx_funcs.get('_M_append')
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                if SHARED_ARENA_VA <= rsi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                    ret_val = f(rdi, rsi, rdx)
                else:
                    if 0 < rdx < 0x10000:
                        buf = alloc(rdx)
                        try:
                            mu.mem_write(buf, bytes(uc.mem_read(rsi, rdx)))
                            ret_val = f(rdi, buf, rdx)
                        except UcError: ret_val = rdi
                    else:
                        ret_val = rdi
            else:
                ret_val = rdi
        elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm':
            f = libstdcxx_funcs.get('_M_create')
            if f and SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE \
                    and SHARED_ARENA_VA <= rsi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                ret_val = f(rdi, rsi, rdx)
            else:
                ret_val = alloc(rdx if rdx < 0x10000 else 256)
        elif name == '_ZN9__gnu_cxx12__to_xstringINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEcEET_PFiPT0_mPKS8_P13__va_list_tagEmSB_z':
            # __gnu_cxx::__to_xstring<std::string, char>(__convf, __n, __fmt, ...)
            # Used to convert numbers like seq (int 1) to "1" string
            # For our purposes, just write "1" to result string at rdi
            if SHARED_ARENA_VA <= rdi < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                # Write a small "1" string: SSO layout
                # this[0..7] = ptr to inline buf (this+16)
                # this[8..15] = length (1)
                # this[16..31] = "1\0..."
                buf_va = rdi + 16
                mu.mem_write(buf_va, b'1\x00' + b'\x00' * 14)
                mu.mem_write(rdi, struct.pack('<Q', buf_va))
                mu.mem_write(rdi + 8, struct.pack('<Q', 1))
            ret_val = 0
        elif name in ('malloc', '_Znwm', '_Znam', '_ZnwmRKSt9nothrow_t'):
            ret_val = alloc(rdi)
        elif name in ('memcpy', 'memmove'):
            if 0 < rdx < 0x100000:
                try: uc.mem_write(rdi, bytes(uc.mem_read(rsi, rdx)))
                except UcError: pass
            ret_val = rdi
        elif name == 'memset':
            if 0 < rdx < 0x100000:
                try: uc.mem_write(rdi, bytes([rsi & 0xff]) * rdx)
                except UcError: pass
            ret_val = rdi
        elif name == 'strlen':
            sz = 0
            try:
                while sz < 0x10000:
                    if uc.mem_read(rdi + sz, 1)[0] == 0: break
                    sz += 1
            except UcError: pass
            ret_val = sz
        elif name in ('free', '_ZdlPv', '_ZdaPv'):
            ret_val = 0
        elif name in ('srand', 'madvise', '__cxa_atexit', 'pthread_once',
                       'pthread_mutex_lock', 'pthread_mutex_unlock', 'time',
                       'pthread_self', '__cxa_finalize', '__errno_location',
                       'getpid', 'rand', 'clock_gettime',
                       '_ZNSt6chrono3_V212system_clock3nowEv',
                       'fopen', 'fgets', 'fclose', 'syscall'):
            ret_val = 0
        elif name == 'dladdr':
            # dladdr(addr, Dl_info*) fills info struct.
            # Critical: dli_fbase must be a valid pointer where ELF header is
            # readable. wrapper.node is mapped at vaddr 0 in Unicorn, so dli_fbase=0
            # would let the caller read ELF header at offset 0 (which works in
            # Unicorn), but then ELF integrity checks compare against expected
            # magic and ELF magic-as-pointer derefs would fail.
            #
            # Setting dli_fbase=0 made the integrity check route fail earlier,
            # so let's POINT it to a buffer in the arena where we PUT the real
            # ELF header bytes. Then *fbase = ELF magic (correct), and pointer
            # arithmetic from fbase still yields valid arena addresses.
            info_ptr = rsi
            if SHARED_ARENA_VA <= info_ptr < SHARED_ARENA_VA + SHARED_ARENA_SIZE:
                fname = alloc(64)
                mu.mem_write(fname, b'wrapper.node\x00')
                # Allocate fake ELF header buffer with real ELF bytes
                fbase = alloc(0x40)
                mu.mem_write(fbase, bytes.fromhex('7f454c46020101000000000000000000'))  # 16 bytes of ELF64 hdr
                mu.mem_write(info_ptr,      struct.pack('<Q', fname))
                mu.mem_write(info_ptr + 8,  struct.pack('<Q', fbase))
                mu.mem_write(info_ptr + 16, struct.pack('<Q', 0))
                mu.mem_write(info_ptr + 24, struct.pack('<Q', 0))
            ret_val = 1
        elif name == '_ZSt20__throw_system_errori':
            ret_val = 0
        elif name == '__tls_get_addr':
            ret_val = alloc(256)
        elif name in ('snprintf', 'sprintf', 'vsnprintf'):
            s = rdi
            if s:
                try: uc.mem_write(s, b'\x00')
                except UcError: pass
            ret_val = 0
        elif name == '__stack_chk_fail':
            ret_val = 0
        elif name == '_ZNSt6thread15_M_start_threadESt10unique_ptrINS_6_StateESt14default_deleteIS1_EEPFvvE':
            uc.mem_write(rdi, struct.pack('<Q', 0xDEAD0001))
            try: uc.mem_write(rsi, struct.pack('<Q', 0))
            except UcError: pass
            ret_val = 0
        elif name == '_ZNSt6thread4joinEv':
            uc.mem_write(rdi, struct.pack('<Q', 0))
            ret_val = 0
        else:
            ret_val = alloc(256)

        uc.reg_write(UC_X86_REG_RAX, ret_val)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr_b = uc.mem_read(rsp, 8)
        ret_addr = struct.unpack('<Q', bytes(ret_addr_b))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    exec_count = [0]
    last_insns = []  # (addr, regs_snapshot)
    chain_log = []
    rcx_changes = []
    last_rcx = [0]

    skipped_reads = [0]
    fixup_done = [False]
    fail_window = []
    def hook_code(uc, address, size, user_data):
        exec_count[0] += 1
        STRUCT_ABS = 0x5000007ef9f0
        if exec_count[0] == 42600 and not fixup_done[0]:
            try:
                v_10 = struct.unpack('<Q', bytes(uc.mem_read(STRUCT_ABS + 0x10, 8)))[0]
                # [+0x10]=index vec base, [+0x18]=flag array base. The chain at
                # 0x5ccd075 reads [rcx + rdi*8] — rcx should be index vec base.
                uc.mem_write(STRUCT_ABS + 0x20, struct.pack('<Q', v_10))
                print(f"  [fixup] [+0x20] := [+0x10] = 0x{v_10:x}")
                fixup_done[0] = True
            except UcError: pass
        # Capture window around new failure at insn ~42818, RIP=0x5cd32b0
        if 42780 <= exec_count[0] <= 42830:
            try:
                fail_window.append((exec_count[0], address,
                                    uc.reg_read(UC_X86_REG_RAX),
                                    uc.reg_read(UC_X86_REG_RBX),
                                    uc.reg_read(UC_X86_REG_RCX),
                                    uc.reg_read(UC_X86_REG_RDX),
                                    uc.reg_read(UC_X86_REG_RSI),
                                    uc.reg_read(UC_X86_REG_RDI),
                                    uc.reg_read(UC_X86_REG_RBP)))
            except UcError: pass
        # Dump candidate heap content around failure
        if exec_count[0] == 42810:
            try:
                rbp = uc.reg_read(UC_X86_REG_RBP)
                p = struct.unpack('<Q', bytes(uc.mem_read(rbp - 0x3e8, 8)))[0]
                print(f"  [pre-fail] [rbp-0x3e8] = 0x{p:x}")
                # Dump index vec at 0xca0 (160 bytes = 20 entries)
                blob1 = bytes(uc.mem_read(0x500001000ca0, 160))
                print(f"  [pre-fail] [0x500001000ca0..+160]:")
                for i in range(0, 160, 16):
                    print(f"    +0x{i:02x}: {blob1[i:i+16].hex()}")
                # Dump flag array
                blob2 = bytes(uc.mem_read(0x500001000d40, 32))
                print(f"  [pre-fail] [0x500001000d40..+32] = {blob2.hex()}")
            except UcError as e: print(f"  [pre-fail] err: {e}")
        # Track rdi at the chain critical loads
        if address in (0x5ccd075, 0x5ccd079) and 42670 <= exec_count[0] <= 42685:
            print(f"  [chain] insn={exec_count[0]} 0x{address:x} rdi=0x{uc.reg_read(UC_X86_REG_RDI):x} rcx=0x{uc.reg_read(UC_X86_REG_RCX):x}")
        if address in (0x5cd5c1a, 0x5cd5c21):
            regs = (uc.reg_read(UC_X86_REG_RAX), uc.reg_read(UC_X86_REG_RBP),
                    uc.reg_read(UC_X86_REG_RBX), uc.reg_read(UC_X86_REG_RDI))
            last_insns.append((address, regs, exec_count[0]))
        else:
            last_insns.append((address, None, exec_count[0]))
        if len(last_insns) > 80: last_insns.pop(0)
        # Capture rcx,rdi at the indirection chain that produces the ELF magic
        if address in (0x5ccd06d, 0x5ccd072, 0x5ccd075, 0x5ccd079):
            chain_log.append((exec_count[0], address,
                              uc.reg_read(UC_X86_REG_RCX),
                              uc.reg_read(UC_X86_REG_RDI),
                              uc.reg_read(UC_X86_REG_RSP),
                              uc.reg_read(UC_X86_REG_RBP)))
        # Track when rcx changes (within last 5000 insns before fail)
        if exec_count[0] > 37000 and exec_count[0] < 42700:
            rcx = uc.reg_read(UC_X86_REG_RCX)
            if rcx != last_rcx[0]:
                rcx_changes.append((exec_count[0], address, last_rcx[0], rcx))
                last_rcx[0] = rcx
        # Log EVERY instruction in narrow window before fail to find rcx-zeroing
        if 42617 <= exec_count[0] <= 42680:
            chain_log.append((exec_count[0], address,
                              uc.reg_read(UC_X86_REG_RCX),
                              uc.reg_read(UC_X86_REG_RDI),
                              uc.reg_read(UC_X86_REG_RAX),
                              uc.reg_read(UC_X86_REG_RBX)))

        # (removed enter skip — testing if high WBASE fixes root cause)
        if PLT_LO_VA <= address < PLT_HI_VA:
            stub_handle(uc, address)
            return
        if not (WBASE <= address < WRAPPER_END) and \
           not (SHARED_ARENA_VA <= address < SHARED_ARENA_VA + SHARED_ARENA_SIZE):
            # External or weird; treat as PLT-like
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret_addr = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
            uc.reg_write(UC_X86_REG_RAX, alloc(64))
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret_addr)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    invalid_log = []
    def hook_invalid(uc, access, address, size, value, user_data):
        invalid_log.append((uc.reg_read(UC_X86_REG_RIP), access, address, size))
        return False
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_invalid)

    # Watch entire stack range; filter values matching ELF magic patterns.
    from unicorn import UC_HOOK_MEM_WRITE
    write_log = []
    struct_writes = []
    ELF_MAGIC = 0x10102464c457f
    STRUCT_BASE = 0x5000007ef9f0
    STRUCT_END = STRUCT_BASE + 0x40
    def hook_write(uc, access, address, size, value, user_data):
        # Track ALL writes to the suspected struct (r14 base + 64 bytes)
        if STRUCT_BASE <= address < STRUCT_END:
            rip = uc.reg_read(UC_X86_REG_RIP)
            struct_writes.append((exec_count[0], rip, address, size, value))
        # Only stack range
        if not (arena_addr <= address < arena_addr + 0x800000): return
        if size != 8: return
        # Match if value is ELF_MAGIC, ELF_MAGIC+small offset, or contains the magic bytes
        v = value & ((1 << (size*8)) - 1)
        is_magic = (v == ELF_MAGIC) or (ELF_MAGIC <= v <= ELF_MAGIC + 0x100) or \
                   ((v >> 8) == (ELF_MAGIC >> 8) and (v & 0xFF) <= 0x20)
        if is_magic:
            rip = uc.reg_read(UC_X86_REG_RIP)
            write_log.append((rip, address, size, value, exec_count[0]))
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_write,
                begin=arena_addr, end=arena_addr + 0x800000)


    # Set up call — stack now in shared arena (top-down)
    SENTINEL = 0xCAFEBABEDEAD000
    rsp = STACK_TOP - 0x10000
    rsp -= 8
    mu.mem_write(rsp, struct.pack('<Q', SENTINEL))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RDI, cmd_va)
    mu.reg_write(UC_X86_REG_RSI, src_va)
    mu.reg_write(UC_X86_REG_RDX, 1)
    mu.reg_write(UC_X86_REG_RCX, 1)
    mu.reg_write(UC_X86_REG_R8, out_va)

    SIGN_FN = WBASE + 0x56D81D1
    print(f"[+] Calling sign_fn at 0x{SIGN_FN:x}")
    import time
    t0 = time.time()
    # Loop emu_start; some hooks stop emulation to advance RIP (e.g., enter skip)
    cur_pc = SIGN_FN
    prev_pc = -1
    try:
        while exec_count[0] < 20_000_000 and cur_pc != SENTINEL:
            try:
                mu.emu_start(cur_pc, SENTINEL, count=20_000_000 - exec_count[0])
            except UcError as e:
                # Re-raise to outer except for diagnostics
                raise
            new_pc = mu.reg_read(UC_X86_REG_RIP)
            if new_pc == SENTINEL: break
            if new_pc == prev_pc:
                # Stuck; abort
                print(f"  STUCK at 0x{new_pc:x}")
                break
            prev_pc = cur_pc
            cur_pc = new_pc
        print(f"  Finished after {time.time()-t0:.2f}s, {exec_count[0]} insns, RIP=0x{cur_pc:x}")
    except UcError as e:
        print(f"  UcError after {time.time()-t0:.2f}s, {exec_count[0]} insns: {e}")
        rip = mu.reg_read(UC_X86_REG_RIP)
        print(f"  RIP at error: 0x{rip:x}")
        print(f"\n  Last 25 insns before fail:")
        for entry in last_insns[-25:]:
            a = entry[0]; regs = entry[1]
            try:
                b = bytes(mu.mem_read(a, 16))
                ins = next(md.disasm(b, a), None)
                rs = ''
                if regs:
                    rs = f" rax=0x{regs[0]:x} rbp=0x{regs[1]:x} rbx=0x{regs[2]:x}"
                print(f"    0x{a:x}: {ins.mnemonic if ins else '?'} {ins.op_str if ins else ''}{rs}")
            except: pass

        # Read [rbp - 0x868] and surrounding stack
        try:
            rbp = mu.reg_read(UC_X86_REG_RBP)
            print(f"\n  rbp = 0x{rbp:x}")
            for off in [-0x870, -0x868, -0x860, -0x858, -0x850]:
                v = struct.unpack('<Q', bytes(mu.mem_read(rbp + off, 8)))[0]
                print(f"    [rbp{off:+d}] = 0x{v:x}")
        except UcError as e:
            print(f"  reading stack failed: {e}")

    out = bytes(mu.mem_read(out_va, 0x300))
    print(f"\n  out[0x200:0x220]: {out[0x200:0x220].hex()}")
    expected = 'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f' if src_byte == 0 else \
               '9fb5974211ac4e148579b26575ecc8c34f3dfd82728cecaf00ab0bfb394186e3'
    print(f"  expected:         {expected}")
    print(f"  {'✅ MATCH' if out[0x200:0x220].hex() == expected else '❌ MISMATCH'}")

    print(f"\nStub calls ({len(stub_calls)} distinct):")
    for nm, c in sorted(stub_calls.items(), key=lambda x: -x[1])[:25]:
        print(f"  {c:>4d}x  {nm}")

    print(f"\nlibfwd_calls (M_construct_PKc): {libfwd_calls}")

    print(f"\nELF-magic-pattern writes to stack: {len(write_log)} total")
    for rip, addr, size, value, exc in write_log[:80]:
        print(f"  insn={exc} RIP=0x{rip:x} write 0x{value:x} (sz={size}) to 0x{addr:x}")

    print(f"\nSkipped reads at 0x5cd5c21: {skipped_reads[0]}")
    print(f"\nFailure-window instructions (42780..42830, last 50):")
    for exc, a, rax, rbx, rcx, rdx, rsi, rdi, rbp in fail_window[-50:]:
        try:
            b = bytes(mu.mem_read(a, 16))
            ins = next(md.disasm(b, a), None)
            ins_str = f"{ins.mnemonic} {ins.op_str}" if ins else '?'
        except: ins_str = '?'
        print(f"  insn={exc} 0x{a:x}: {ins_str:55s} rax=0x{rax:x} rbx=0x{rbx:x} rdi=0x{rdi:x}")

    print(f"\nLast 30 rcx changes (insn 37000..42700):")
    for exc, addr, old, new in rcx_changes[-30:]:
        try:
            b = bytes(mu.mem_read(addr, 16))
            ins = next(md.disasm(b, addr), None)
            ins_str = f"{ins.mnemonic} {ins.op_str}" if ins else '?'
        except: ins_str = '?'
        print(f"  insn={exc} RIP=0x{addr:x} {ins_str:40s} rcx 0x{old:x} -> 0x{new:x}")
    print(f"\nInvalid memory accesses: {len(invalid_log)}")
    for rip, acc, addr, sz in invalid_log[:5]:
        print(f"  RIP=0x{rip:x} access={acc} addr=0x{addr:x} sz={sz}")


if __name__ == '__main__':
    main()
