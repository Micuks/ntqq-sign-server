"""Unicorn sign emulation v3: with PLT stub framework."""
import struct, capstone
from unicorn import *
from unicorn.x86_const import *
import subprocess

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
data = open(WRAPPER, 'rb').read()

# Parse PLT entries
plt_out = subprocess.check_output(['objdump', '-d', '--section=.plt', WRAPPER], text=True)
plt_addr_to_name = {}
for line in plt_out.split('\n'):
    if '@plt>:' in line:
        parts = line.split()
        plt_addr_to_name[int(parts[0], 16)] = parts[1].rstrip(':').strip('<>').replace('@plt', '')

# Setup Unicorn
mu = Uc(UC_ARCH_X86, UC_MODE_64)

e_phoff, = struct.unpack_from('<Q', data, 0x20)
e_phentsize, = struct.unpack_from('<H', data, 0x36)
e_phnum, = struct.unpack_from('<H', data, 0x38)
PAGE = 0x1000
def align_down(x): return x & ~(PAGE-1)
def align_up(x): return (x + PAGE - 1) & ~(PAGE-1)

for i in range(e_phnum):
    p = data[e_phoff + i*e_phentsize: e_phoff + (i+1)*e_phentsize]
    p_type, p_flags, p_offset, _, p_vaddr, p_filesz, p_memsz, _ = struct.unpack('<IIQQQQQQ', p)
    if p_type != 1: continue
    # ELF flags: R=4, W=2, X=1; Unicorn: R=1, W=2, X=4
    perms = (UC_PROT_READ if p_flags & 4 else 0) | (UC_PROT_WRITE if p_flags & 2 else 0) | (UC_PROT_EXEC if p_flags & 1 else 0)
    va_start = align_down(p_vaddr); va_end = align_up(p_vaddr + p_memsz)
    mu.mem_map(va_start, va_end - va_start, perms)
    mu.mem_write(p_vaddr, data[p_offset:p_offset + p_filesz])

STACK_VA = 0x90000000; STACK_SZ = 0x200000
mu.mem_map(STACK_VA, STACK_SZ, UC_PROT_READ | UC_PROT_WRITE)
RSP = STACK_VA + STACK_SZ - 0x10000

IO_VA = 0x80000000
mu.mem_map(IO_VA, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_write(IO_VA, b'wtlogin.login\x00')
SRC_VA = IO_VA + 0x100; mu.mem_write(SRC_VA, b'\x00')
OUT_VA = IO_VA + 0x1000

FS_VA = 0x70000000
mu.mem_map(FS_VA, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_write(FS_VA + 0x28, b'\x00'*8)
try: mu.msr_write(0xC0000100, FS_VA)
except: pass

# Heap allocator
HEAP_VA = 0xa0000000
HEAP_SIZE = 0x1000000  # 16 MB
mu.mem_map(HEAP_VA, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
heap_top = [HEAP_VA]

def stub_malloc(uc, args):
    sz = args[0]
    sz = (sz + 0xf) & ~0xf  # 16-byte align
    p = heap_top[0]; heap_top[0] += sz
    return p

def stub_free(uc, args):
    return 0  # leak, simple

def stub_memset(uc, args):
    dst, c, n = args[0], args[1] & 0xff, args[2]
    if n > 0:
        uc.mem_write(dst, bytes([c]) * n)
    return dst

def stub_memcpy(uc, args):
    dst, src, n = args[0], args[1], args[2]
    if n > 0:
        b = uc.mem_read(src, n)
        uc.mem_write(dst, bytes(b))
    return dst

def stub_memmove(uc, args):
    return stub_memcpy(uc, args)

def stub_memcmp(uc, args):
    a, b, n = args[0], args[1], args[2]
    if n == 0: return 0
    A = bytes(uc.mem_read(a, n))
    B = bytes(uc.mem_read(b, n))
    if A == B: return 0
    for i in range(n):
        if A[i] != B[i]:
            return A[i] - B[i]
    return 0

def stub_strlen(uc, args):
    p = args[0]; sz = 0
    while True:
        b = uc.mem_read(p + sz, 1)
        if b[0] == 0: return sz
        sz += 1
        if sz > 1000000: return sz

def stub_zero(uc, args):  # return 0
    return 0

def stub_dladdr(uc, args):  # return 0 (failure)
    return 0

def stub_unimpl(name):
    def fn(uc, args):
        print(f"  UNIMPL stub call: {name} args={[hex(a) for a in args]}")
        return 0
    return fn

PLT_STUBS = {
    'malloc':  stub_malloc,
    '_Znwm':   stub_malloc,  # operator new
    '_Znam':   stub_malloc,
    '_ZnwmRKSt9nothrow_t': stub_malloc,
    'free':    stub_free,
    '_ZdlPv':  stub_free,
    '_ZdaPv':  stub_free,
    'memset':  stub_memset,
    'memcpy':  stub_memcpy,
    'memmove': stub_memmove,
    'memcmp':  stub_memcmp,
    'bcmp':    stub_memcmp,
    'strlen':  stub_strlen,
    'pthread_mutex_lock': stub_zero,
    'pthread_mutex_unlock': stub_zero,
    'time': stub_zero,
    'dladdr': stub_dladdr,
    'pthread_self': stub_zero,
    '__cxa_finalize': stub_zero,
    '__errno_location': stub_zero,  # would need real errno
}

# Hook PLT entries by tracking when execution enters PLT range
PLT_LO = min(plt_addr_to_name.keys())
PLT_HI = max(plt_addr_to_name.keys()) + 16

def get_args(uc, n=6):
    rdi = uc.reg_read(UC_X86_REG_RDI)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
    return [rdi, rsi, rdx, rcx, r8, r9][:n]

stub_calls = {}
def hook_plt(uc, address, size, user_data):
    if PLT_LO <= address < PLT_HI:
        # Round to start of plt entry
        plt_addr = (address - 0x7ae5ba0) // 16 * 16 + 0x7ae5ba0
        if plt_addr not in plt_addr_to_name:
            return
        name = plt_addr_to_name[plt_addr]
        stub_calls[name] = stub_calls.get(name, 0) + 1
        # Read args
        if name in PLT_STUBS:
            args = get_args(uc)
            ret = PLT_STUBS[name](uc, args)
        else:
            # Unhandled: stub as malloc-like (returns heap pointer)
            ret = stub_malloc(uc, [256])
        uc.reg_write(UC_X86_REG_RAX, ret)
        # Pop return address and jump there
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr_b = uc.mem_read(rsp, 8)
        ret_addr = struct.unpack('<Q', bytes(ret_addr_b))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

mu.hook_add(UC_HOOK_CODE, hook_plt)

def hook_invalid(uc, access, address, size, value, user_data):
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(f"  INVALID @ 0x{rip:x}: access={access} addr=0x{address:x} sz={size}")
    return False
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_invalid)

# Setup args
RSP_LOC = STACK_VA + STACK_SZ - 0x10000 - 8
mu.mem_write(RSP_LOC, struct.pack('<Q', 0xDEAD_BEEF_CAFE_BABE))
mu.reg_write(UC_X86_REG_RSP, RSP_LOC)
mu.reg_write(UC_X86_REG_RDI, IO_VA)
mu.reg_write(UC_X86_REG_RSI, SRC_VA)
mu.reg_write(UC_X86_REG_RDX, 1)
mu.reg_write(UC_X86_REG_RCX, 1)
mu.reg_write(UC_X86_REG_R8, OUT_VA)

import time
t0 = time.time()
print(f"Starting emulation at sign_fn=0x56d81d1...")
try:
    mu.emu_start(0x56d81d1, 0xDEAD_BEEF_CAFE_BABE, count=100000000)
    elapsed = time.time() - t0
    print(f"Finished in {elapsed:.2f}s")
    out = bytes(mu.mem_read(OUT_VA, 0x300))
    sl = out[0x2FF]
    print(f"  sign_len={sl}")
    print(f"  sign={out[0x200:0x200+sl].hex() if sl else '(empty)'}")
except UcError as e:
    elapsed = time.time() - t0
    print(f"  UcError after {elapsed:.2f}s: {e}")
    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"  RIP at error: 0x{rip:x}")

print(f"\nStub calls made: {len(stub_calls)}")
for nm, c in sorted(stub_calls.items(), key=lambda x: -x[1]):
    impl = 'STUB' if nm in PLT_STUBS else 'UNHANDLED'
    print(f"  {c:>4d}x  {nm}  [{impl}]")
