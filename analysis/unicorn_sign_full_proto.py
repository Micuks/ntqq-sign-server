"""Run Unicorn from sign_fn entry (0x56D81D1) directly, with captured memdump
+ all the stubs we've built. Capture sign output."""
import struct, json
import os as _os
from unicorn import *
from unicorn.x86_const import *
import capstone

# Use src=0x42 captured memdump (it has heap layout we'll reuse)
DUMP_PATH = '/tmp/op60_memdump.json'
m = json.load(open(DUMP_PATH))
WBASE = m['wrapper_base']
print(f"Wrapper base: 0x{WBASE:x}")

mu = Uc(UC_ARCH_X86, UC_MODE_64)
PAGE = 0x1000
def align_down(x): return x & ~(PAGE-1)
def align_up(x): return (x + PAGE - 1) & ~(PAGE-1)

# Map wrapper.node first
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
    va_start = align_down(WBASE + p_vaddr)
    va_end = align_up(WBASE + p_vaddr + p_memsz)
    mu.mem_map(va_start, va_end - va_start, perms)
    mu.mem_write(WBASE + p_vaddr, wdata[p_offset:p_offset + p_filesz])
    wrapper_va_ranges.append((va_start, va_end))

def overlaps_wrapper(a, b):
    for ws, we in wrapper_va_ranges:
        if a < we and b > ws: return True
    return False

prot_to_uc = {'r--': UC_PROT_READ, 'r-x': UC_PROT_READ | UC_PROT_EXEC,
              'rw-': UC_PROT_READ | UC_PROT_WRITE, 'rwx': UC_PROT_ALL}

# Map captured ranges (skip wrapper overlaps which are already mapped)
for r in sorted(m['ranges'], key=lambda x: x['addr']):
    addr = r['addr']; size = r['size']
    page_start = align_down(addr); page_end = align_up(addr + size)
    if overlaps_wrapper(page_start, page_end): continue
    perms = prot_to_uc.get(r['prot'], UC_PROT_READ | UC_PROT_WRITE)
    try:
        mu.mem_map(page_start, page_end - page_start, perms)
        with open(r['file'], 'rb') as f: data = f.read()
        mu.mem_write(addr, data)
    except UcError: pass

# FS region
FS_VA = 0x70000000
mu.mem_map(FS_VA - 0x10000, 0x20000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_write(FS_VA + 0x28, struct.pack('<Q', 0))  # canary = 0
mu.reg_write(UC_X86_REG_FS_BASE, FS_VA)

# Heap
HEAP_VA = 0xb0000000
mu.mem_map(HEAP_VA, 0x10000000, UC_PROT_READ | UC_PROT_WRITE)
heap_top = [HEAP_VA]
def alloc(n):
    n = (n + 0xf) & ~0xf
    p = heap_top[0]; heap_top[0] += max(n, 16)
    return p

# Input/output buffers
IO_VA = 0xc0000000
mu.mem_map(IO_VA, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
CMD_VA = IO_VA
SRC_VA = IO_VA + 0x100
OUT_VA = IO_VA + 0x1000

mu.mem_write(CMD_VA, b'wtlogin.login\x00')
SRC_BYTE = int(_os.environ.get('SRC_BYTE', '0x00'), 16)
mu.mem_write(SRC_VA, bytes([SRC_BYTE]))

# Stack
STACK_TOP = 0x90000000
mu.mem_map(STACK_TOP - 0x100000, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
RSP = STACK_TOP - 0x10000
SENTINEL = 0xDEADBEEFCAFEBABE
RSP -= 8
mu.mem_write(RSP, struct.pack('<Q', SENTINEL))
mu.reg_write(UC_X86_REG_RSP, RSP)

# Args
mu.reg_write(UC_X86_REG_RDI, CMD_VA)
mu.reg_write(UC_X86_REG_RSI, SRC_VA)
mu.reg_write(UC_X86_REG_RDX, 1)
mu.reg_write(UC_X86_REG_RCX, 1)
mu.reg_write(UC_X86_REG_R8, OUT_VA)

# PLT names
import subprocess
plt_out = subprocess.check_output(['objdump', '-d', '--section=.plt', WFILE], text=True)
plt_addr_to_name = {}
for line in plt_out.split('\n'):
    if '@plt>:' in line:
        parts = line.split()
        plt_addr_to_name[int(parts[0], 16)] = parts[1].rstrip(':').strip('<>').replace('@plt', '')

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
    rdx = uc.reg_read(UC_X86_REG_RDX); rcx = uc.reg_read(UC_X86_REG_RCX)
    ret_val = 0
    if name in ('malloc','_Znwm','_Znam','_ZnwmRKSt9nothrow_t'):
        ret_val = alloc(rdi)
    elif name in ('memcpy','memmove'):
        if rdx > 0: uc.mem_write(rdi, bytes(uc.mem_read(rsi, rdx)))
        ret_val = rdi
    elif name == 'memset':
        if rdx > 0: uc.mem_write(rdi, bytes([rsi & 0xff]) * rdx)
        ret_val = rdi
    elif name == 'strlen':
        sz = 0
        while sz < 0x10000:
            if uc.mem_read(rdi + sz, 1)[0] == 0: break
            sz += 1
        ret_val = sz
    elif name == '__stack_chk_fail':
        # Should never happen — just return
        ret_val = 0
    else:
        ret_val = alloc(256)
    uc.reg_write(UC_X86_REG_RAX, ret_val)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    rip_b = uc.mem_read(rsp, 8)
    ret_addr = struct.unpack('<Q', bytes(rip_b))[0]
    uc.reg_write(UC_X86_REG_RSP, rsp + 8)
    uc.reg_write(UC_X86_REG_RIP, ret_addr)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
exec_count = [0]
def hook_code(uc, address, size, user_data):
    exec_count[0] += 1
    if PLT_LO_VA <= address < PLT_HI_VA:
        stub_handle(uc, address)
        return
    if not (WBASE <= address < WRAPPER_END):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        stub_calls[f'extern@0x{address-WBASE:x}'] = stub_calls.get(f'extern@0x{address-WBASE:x}', 0) + 1
        uc.reg_write(UC_X86_REG_RAX, alloc(64))
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)
        return
mu.hook_add(UC_HOOK_CODE, hook_code)

invalid_log = []
def hook_invalid(uc, access, address, size, value, user_data):
    invalid_log.append((uc.reg_read(UC_X86_REG_RIP), access, address, size))
    return False
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_invalid)

import time
SIGN_FN = WBASE + 0x56D81D1
print(f"Starting sign_fn at 0x{SIGN_FN:x}")
t0 = time.time()
try:
    mu.emu_start(SIGN_FN, SENTINEL, count=20000000)
    print(f"Finished after {time.time()-t0:.2f}s, {exec_count[0]} insns")
except UcError as e:
    print(f"  UcError after {time.time()-t0:.2f}s, {exec_count[0]} insns: {e}")
    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"  RIP at error: 0x{rip:x} (offset 0x{rip-WBASE:x})")

# Read output buffer
out = bytes(mu.mem_read(OUT_VA, 0x300))
print(f"\nOutput buffer at OUT_VA=0x{OUT_VA:x}:")
print(f"  out[0x200:0x220] = {out[0x200:0x220].hex()}")
print(f"  out[0x2FF] (sign_len) = {out[0x2FF]}")
expected = bytes.fromhex('e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f')
if SRC_BYTE == 0x42:
    expected = bytes.fromhex('9fb5974211ac4e148579b26575ecc8c34f3dfd82728cecaf00ab0bfb394186e3')
print(f"  expected sign     = {expected.hex()}")
match = out[0x200:0x220] == expected
print(f"  {'✅ MATCH' if match else '❌ MISMATCH'}")

# Search for sign anywhere in our memory
print("\nSearching for expected sign in memory...")
found = []
try:
    for region in [(IO_VA, 0x10000), (HEAP_VA, heap_top[0] - HEAP_VA), (STACK_TOP - 0x100000, 0x100000)]:
        d = bytes(mu.mem_read(region[0], region[1]))
        pos = d.find(expected)
        if pos >= 0:
            found.append(region[0] + pos)
except UcError: pass
for r in m['ranges']:
    try:
        d = bytes(mu.mem_read(r['addr'], r['size']))
        pos = d.find(expected)
        if pos >= 0: found.append(r['addr'] + pos)
    except UcError: pass
print(f"  Found at {len(found)} positions: {[hex(x) for x in found[:10]]}")

print(f"\nStub call summary ({len(stub_calls)} distinct):")
for nm, c in sorted(stub_calls.items(), key=lambda x: -x[1])[:30]:
    print(f"  {c:>5d}x  {nm}")
print(f"\nInvalid memory accesses: {len(invalid_log)}")
for rip, acc, addr, sz in invalid_log[:5]:
    print(f"  RIP=0x{rip:x} ({rip-WBASE:#x} in wrapper): access={acc} addr=0x{addr:x} sz={sz}")
