"""Differential validation: run Unicorn with src=0x00 captured state but modify
the 3 stack locations to 0x42. If our emulation is correct, post-emulation
memory should match src=0x42 captured state in the dependent regions."""
import struct, json, os
from unicorn import *
from unicorn.x86_const import *
import capstone

# Both captures are at SAME process state (multi_src capture)
m_src = json.load(open('/tmp/multi_src_src_00.json'))
m_tgt = json.load(open('/tmp/multi_src_src_42.json'))
WBASE_FROM_RIP = (m_src['regs']['rip'] - 0x5ce6006)
print(f"Inferred wrapper base: 0x{WBASE_FROM_RIP:x}")

mu = Uc(UC_ARCH_X86, UC_MODE_64)
PAGE = 0x1000
def align_down(x): return x & ~(PAGE-1)
def align_up(x): return (x + PAGE - 1) & ~(PAGE-1)

# Map wrapper.node from file
WFILE = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
wdata = open(WFILE, 'rb').read()
e_phoff, = struct.unpack_from('<Q', wdata, 0x20)
e_phentsize, = struct.unpack_from('<H', wdata, 0x36)
e_phnum, = struct.unpack_from('<H', wdata, 0x38)
wrapper_va_ranges = []
for i in range(e_phnum):
    p = wdata[e_phoff + i*e_phentsize: e_phoff + (i+1)*e_phentsize]
    p_type, p_flags, p_offset, _, p_vaddr, p_filesz, p_memsz, _ = struct.unpack('<IIQQQQQQ', p)
    if p_type != 1: continue
    perms = (UC_PROT_READ if p_flags & 4 else 0) | (UC_PROT_WRITE if p_flags & 2 else 0) | (UC_PROT_EXEC if p_flags & 1 else 0)
    va_start = align_down(WBASE_FROM_RIP + p_vaddr)
    va_end = align_up(WBASE_FROM_RIP + p_vaddr + p_memsz)
    mu.mem_map(va_start, va_end - va_start, perms)
    mu.mem_write(WBASE_FROM_RIP + p_vaddr, wdata[p_offset:p_offset + p_filesz])
    wrapper_va_ranges.append((va_start, va_end))

def overlaps_wrapper(a, b):
    for ws, we in wrapper_va_ranges:
        if a < we and b > ws: return True
    return False

# Map captured ranges (from src=0x00)
for r in sorted(m_src['ranges'], key=lambda x: x['addr']):
    addr = r['addr']; size = r['size']
    page_start = align_down(addr); page_end = align_up(addr + size)
    if overlaps_wrapper(page_start, page_end): continue
    try:
        mu.mem_map(page_start, page_end - page_start, UC_PROT_READ | UC_PROT_WRITE)
        with open(r['file'], 'rb') as f: data = f.read()
        mu.mem_write(addr, data)
    except UcError: pass

# CRITICAL: modify the 3 src byte locations from 0x00 to 0x42
SRC_LOCATIONS = [0x7ffc1bdb8bb8, 0x7ffc1bdb8d30, 0x7ffc1bdb8f90]
for loc in SRC_LOCATIONS:
    try:
        mu.mem_write(loc, b'\x42')
        print(f"  Modified 0x{loc:x} from 0x00 to 0x42")
    except UcError as e:
        print(f"  FAILED to modify 0x{loc:x}: {e}")

# FS region
FS_VA = 0x70000000
mu.mem_map(FS_VA - 0x10000, 0x20000, UC_PROT_READ | UC_PROT_WRITE)
# Get canary from captured state (from rsp+0x38 or scan)
# For now use 0
mu.mem_write(FS_VA + 0x28, struct.pack('<Q', 0))
mu.reg_write(UC_X86_REG_FS_BASE, FS_VA)

# Heap for stubs
HEAP_VA = 0xb0000000
mu.mem_map(HEAP_VA, 0x10000000, UC_PROT_READ | UC_PROT_WRITE)
heap_top = [HEAP_VA]
def alloc(n):
    n = (n + 0xf) & ~0xf
    p = heap_top[0]; heap_top[0] += max(n, 16)
    return p

# Restore captured registers
regs = m_src['regs']
for k, ucr in [('rax', UC_X86_REG_RAX), ('rbx', UC_X86_REG_RBX),
               ('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX),
               ('rsi', UC_X86_REG_RSI), ('rdi', UC_X86_REG_RDI),
               ('rbp', UC_X86_REG_RBP), ('rsp', UC_X86_REG_RSP),
               ('r8', UC_X86_REG_R8),  ('r9', UC_X86_REG_R9),
               ('r10', UC_X86_REG_R10),('r11', UC_X86_REG_R11),
               ('r12', UC_X86_REG_R12),('r13', UC_X86_REG_R13),
               ('r14', UC_X86_REG_R14),('r15', UC_X86_REG_R15)]:
    if k in regs:
        mu.reg_write(ucr, regs[k])

# PLT names
import subprocess
plt_out = subprocess.check_output(['objdump', '-d', '--section=.plt', WFILE], text=True)
plt_addr_to_name = {}
for line in plt_out.split('\n'):
    if '@plt>:' in line:
        parts = line.split()
        plt_addr_to_name[int(parts[0], 16)] = parts[1].rstrip(':').strip('<>').replace('@plt', '')

WBASE = WBASE_FROM_RIP
WRAPPER_END = WBASE + 0x7dc0818
PLT_LO_VA = WBASE + 0x7ae5ba0
PLT_HI_VA = WBASE + 0x7ae5b90 + 793*16

stub_calls = {}
def stub_handle(uc, plt_va):
    plt_off = plt_va - WBASE
    plt_idx = (plt_off - 0x7ae5ba0) // 16
    plt_entry = 0x7ae5ba0 + plt_idx * 16
    name = plt_addr_to_name.get(plt_entry, f'plt+0x{plt_off:x}')
    stub_calls[name] = stub_calls.get(name, 0) + 1
    rdi = uc.reg_read(UC_X86_REG_RDI); rsi = uc.reg_read(UC_X86_REG_RSI)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    ret_val = 0
    if name in ('malloc','_Znwm','_Znam','_ZnwmRKSt9nothrow_t'):
        ret_val = alloc(rdi)
    elif name in ('memcpy','memmove'):
        if rdx > 0: uc.mem_write(rdi, bytes(uc.mem_read(rsi, rdx)))
        ret_val = rdi
    elif name == 'memset':
        if rdx > 0: uc.mem_write(rdi, bytes([rsi & 0xff]) * rdx)
        ret_val = rdi
    else:
        ret_val = alloc(256)
    uc.reg_write(UC_X86_REG_RAX, ret_val)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    rip_b = uc.mem_read(rsp, 8)
    ret_addr = struct.unpack('<Q', bytes(rip_b))[0]
    uc.reg_write(UC_X86_REG_RSP, rsp + 8)
    uc.reg_write(UC_X86_REG_RIP, ret_addr)

exec_count = [0]
def hook_code(uc, address, size, user_data):
    exec_count[0] += 1
    if PLT_LO_VA <= address < PLT_HI_VA:
        stub_handle(uc, address)
        return
    if not (WBASE <= address < WRAPPER_END):
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

import time
print(f"\nStarting at RIP=0x{regs['rip']:x}")
t0 = time.time()
try:
    mu.emu_start(regs['rip'], 0xffffffffffffffff, count=10000000)
    print(f"Finished in {time.time()-t0:.2f}s, {exec_count[0]} insns")
except UcError as e:
    print(f"  UcError after {time.time()-t0:.2f}s, {exec_count[0]} insns: {e}")

# Compare post-emulation memory with src=0x42 captured state
print(f"\nDiffing emulation result vs target src=0x42 capture:")
i_tgt = {r['addr']: r for r in m_tgt['ranges']}
i_src = {r['addr']: r for r in m_src['ranges']}
common = set(i_src.keys()) & set(i_tgt.keys())

bytes_match_tgt = 0
bytes_match_src = 0  # unchanged from src=00 input
total_diff_bytes = 0
for addr in common:
    r_src = i_src[addr]
    r_tgt = i_tgt[addr]
    sz = min(r_src['size'], r_tgt['size'])
    d_src = open(r_src['file'], 'rb').read()[:sz]
    d_tgt = open(r_tgt['file'], 'rb').read()[:sz]
    try:
        d_now = bytes(mu.mem_read(addr, sz))
    except UcError: continue
    for i in range(sz):
        if d_src[i] != d_tgt[i]:
            total_diff_bytes += 1
            if d_now[i] == d_tgt[i]: bytes_match_tgt += 1
            elif d_now[i] == d_src[i]: bytes_match_src += 1

print(f"  Total bytes differing between src=00 and src=42 captures: {total_diff_bytes}")
print(f"  Of these, post-emulation matches src=42 (target): {bytes_match_tgt} ({100*bytes_match_tgt/max(total_diff_bytes,1):.1f}%)")
print(f"  Post-emulation matches src=00 (unchanged): {bytes_match_src} ({100*bytes_match_src/max(total_diff_bytes,1):.1f}%)")
print(f"  Stubs called: {len(stub_calls)}, top: {sorted(stub_calls.items(), key=lambda x: -x[1])[:5]}")
print(f"  Invalid memory ops: {len(invalid_log)}")
