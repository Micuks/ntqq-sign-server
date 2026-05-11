"""Unicorn replay v2: use full memory dump from same Frida run."""
import struct, json, os
from unicorn import *
from unicorn.x86_const import *
import capstone

import os as _os
DUMP_PATH = _os.environ.get('DUMP_PATH', '/tmp/op60_memdump.json')
m = json.load(open(DUMP_PATH))
WBASE = m['wrapper_base']
regs = m['regs']
print(f"Wrapper base in capture: 0x{WBASE:x}")
print(f"RIP at op 0x60 entry: 0x{regs['rip']:x} (offset 0x{regs['rip']-WBASE:x})")

mu = Uc(UC_ARCH_X86, UC_MODE_64)

PAGE = 0x1000
def align_down(x): return x & ~(PAGE-1)
def align_up(x): return (x + PAGE - 1) & ~(PAGE-1)

# First map wrapper.node segments from file (gives proper exec perms)
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
    print(f"  Mapped wrapper.node seg {i}: 0x{va_start:x}-0x{va_end:x} perms={perms}")

def overlaps_wrapper(a, b):
    for ws, we in wrapper_va_ranges:
        if a < we and b > ws:
            return True
    return False

# Then map captured ranges outside wrapper.node
prot_to_uc = {'r--': UC_PROT_READ, 'r-x': UC_PROT_READ | UC_PROT_EXEC,
              'rw-': UC_PROT_READ | UC_PROT_WRITE, 'rwx': UC_PROT_ALL}

ok = 0; fail = 0; skip = 0
for r in sorted(m['ranges'], key=lambda x: x['addr']):
    addr = r['addr']; size = r['size']
    page_start = align_down(addr); page_end = align_up(addr + size)
    if page_end - page_start == 0: continue
    if overlaps_wrapper(page_start, page_end):
        # Inside wrapper.node — write data on top (RW segments may have been modified)
        try:
            with open(r['file'], 'rb') as f: data = f.read()
            mu.mem_write(addr, data)
        except UcError:
            pass
        skip += 1
        continue
    perms = prot_to_uc.get(r['prot'], UC_PROT_READ | UC_PROT_WRITE)
    try:
        mu.mem_map(page_start, page_end - page_start, perms)
        with open(r['file'], 'rb') as f: data = f.read()
        mu.mem_write(addr, data)
        ok += 1
    except UcError as e:
        fail += 1

print(f"\nMapped {ok} captured ranges, {skip} overlap wrapper, {fail} failed")

# FS region for canary - allocate enough room for negative offsets too
FS_VA = 0x70000000
mu.mem_map(FS_VA - 0x10000, 0x20000, UC_PROT_READ | UC_PROT_WRITE)
# Read the actual stored canary from captured stack memory at sign() prologue [rbp]
# Locate it by scanning for non-zero qword in early stack region (canary is fixed per-thread)
canary_value = 0xf2a9867f0bf2b700  # captured at [rsp+0x30] in this dump
mu.mem_write(FS_VA + 0x28, struct.pack('<Q', canary_value))
mu.reg_write(UC_X86_REG_FS_BASE, FS_VA)

# Restore registers
for k, ucr in [('rax', UC_X86_REG_RAX), ('rbx', UC_X86_REG_RBX),
               ('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX),
               ('rsi', UC_X86_REG_RSI), ('rdi', UC_X86_REG_RDI),
               ('rbp', UC_X86_REG_RBP), ('rsp', UC_X86_REG_RSP),
               ('r8', UC_X86_REG_R8),  ('r9', UC_X86_REG_R9),
               ('r10', UC_X86_REG_R10),('r11', UC_X86_REG_R11),
               ('r12', UC_X86_REG_R12),('r13', UC_X86_REG_R13),
               ('r14', UC_X86_REG_R14),('r15', UC_X86_REG_R15),
               ('rflags', UC_X86_REG_EFLAGS)]:
    mu.reg_write(ucr, regs[k])

# Heap allocator for stubs
HEAP_VA = 0xb0000000
HEAP_SIZE = 0x10000000  # 256 MB to be safe
mu.mem_map(HEAP_VA, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
heap_top = [HEAP_VA]
def alloc(n):
    n = (n + 0xf) & ~0xf
    p = heap_top[0]; heap_top[0] += max(n, 16)
    return p

# Subprocess to load PLT names
import subprocess
plt_out = subprocess.check_output(['objdump', '-d', '--section=.plt', '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'], text=True)
plt_addr_to_name = {}
for line in plt_out.split('\n'):
    if '@plt>:' in line:
        parts = line.split()
        plt_addr_to_name[int(parts[0], 16)] = parts[1].rstrip(':').strip('<>').replace('@plt', '')

WRAPPER_END = WBASE + 0x7dc0818
WRAPPER_START = WBASE
PLT_LO_VA = WBASE + 0x7ae5ba0  # exclude header at 0x7ae5b90
PLT_HI_VA = WBASE + 0x7ae5b90 + 793*16

# Hooks
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
exec_count = [0]
stub_calls = {}

def stub_handle(uc, plt_va):
    plt_off = plt_va - WBASE
    plt_addr_no_base = plt_off  # in objdump file
    # Round to PLT entry (16-byte aligned, starting at 0x7ae5ba0)
    plt_idx = (plt_addr_no_base - 0x7ae5ba0) // 16
    plt_entry = 0x7ae5ba0 + plt_idx * 16
    name = plt_addr_to_name.get(plt_entry, f'plt+0x{plt_off:x}')
    stub_calls[name] = stub_calls.get(name, 0) + 1
    rdi = uc.reg_read(UC_X86_REG_RDI); rsi = uc.reg_read(UC_X86_REG_RSI)
    rdx = uc.reg_read(UC_X86_REG_RDX); rcx = uc.reg_read(UC_X86_REG_RCX)
    # Emulate the call
    ret_val = 0
    if name in ('malloc','_Znwm','_Znam','_ZnwmRKSt9nothrow_t'):
        ret_val = alloc(rdi)
    elif name == 'memset':
        if rdx > 0: uc.mem_write(rdi, bytes([rsi & 0xff]) * rdx)
        ret_val = rdi
    elif name in ('memcpy','memmove'):
        if rdx > 0: uc.mem_write(rdi, bytes(uc.mem_read(rsi, rdx)))
        ret_val = rdi
    elif name in ('memcmp','bcmp'):
        if rdx == 0: ret_val = 0
        else:
            A = bytes(uc.mem_read(rdi, rdx))
            B = bytes(uc.mem_read(rsi, rdx))
            ret_val = 0 if A == B else (A[0] - B[0])
    elif name == 'strlen':
        sz = 0
        while sz < 0x10000:
            if uc.mem_read(rdi + sz, 1)[0] == 0: break
            sz += 1
        ret_val = sz
    elif name == '_ZNSt6vectorIlSaIlEE12emplace_backIJRlEEES3_DpOT_':
        # std::vector<long>::emplace_back(long&)
        # rdi = this, rsi = ptr to value to insert
        this_ptr = rdi
        val_ptr = rsi
        val = struct.unpack('<q', bytes(uc.mem_read(val_ptr, 8)))[0]
        begin = struct.unpack('<Q', bytes(uc.mem_read(this_ptr, 8)))[0]
        end = struct.unpack('<Q', bytes(uc.mem_read(this_ptr+8, 8)))[0]
        cap = struct.unpack('<Q', bytes(uc.mem_read(this_ptr+16, 8)))[0]
        size = (end - begin) // 8 if begin else 0
        capacity = (cap - begin) // 8 if begin else 0
        if size < capacity:
            # In-place insert
            uc.mem_write(end, struct.pack('<q', val))
            uc.mem_write(this_ptr+8, struct.pack('<Q', end+8))
        else:
            # Reallocate
            new_cap = max(capacity * 2, 4)
            new_buf = alloc(new_cap * 8)
            if begin and size:
                old_data = bytes(uc.mem_read(begin, size*8))
                uc.mem_write(new_buf, old_data)
            uc.mem_write(new_buf + size*8, struct.pack('<q', val))
            uc.mem_write(this_ptr, struct.pack('<Q', new_buf))
            uc.mem_write(this_ptr+8, struct.pack('<Q', new_buf + (size+1)*8))
            uc.mem_write(this_ptr+16, struct.pack('<Q', new_buf + new_cap*8))
        ret_val = uc.reg_read(UC_X86_REG_RAX)  # don't care
    elif name in ('_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag',
                  '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag'):
        # std::string::_M_construct(p, q, forward_iterator_tag)
        # rdi=this, rsi=p, rdx=q
        this_ptr = rdi
        p, q = rsi, rdx
        length = q - p
        if length <= 0 or length > 0x10000:
            ret_val = 0
        else:
            chars = bytes(uc.mem_read(p, length))
            if length <= 15:
                # SSO: chars go inline at this+16
                buf_va = this_ptr + 16
                uc.mem_write(buf_va, chars + b'\x00')
                uc.mem_write(this_ptr, struct.pack('<Q', buf_va))  # _M_dataplus._M_p
                uc.mem_write(this_ptr+8, struct.pack('<Q', length))  # _M_string_length
            else:
                # Heap allocation
                buf = alloc(length + 1)
                uc.mem_write(buf, chars + b'\x00')
                uc.mem_write(this_ptr, struct.pack('<Q', buf))
                uc.mem_write(this_ptr+8, struct.pack('<Q', length))
                uc.mem_write(this_ptr+16, struct.pack('<Q', length))  # capacity
            ret_val = 0
    elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm':
        # std::string::_M_replace(this, pos, n1, p, n2): replace [pos, pos+n1) with [p, p+n2)
        # rdi=this, rsi=pos, rdx=n1, rcx=p, r8=n2
        this_ptr = rdi
        pos, n1, p, n2 = rsi, rdx, rcx, uc.reg_read(UC_X86_REG_R8)
        # Read current string state
        buf_ptr = struct.unpack('<Q', bytes(uc.mem_read(this_ptr, 8)))[0]
        cur_len = struct.unpack('<Q', bytes(uc.mem_read(this_ptr+8, 8)))[0]
        if buf_ptr and cur_len < 0x10000:
            old = bytes(uc.mem_read(buf_ptr, cur_len))
        else:
            old = b''
        # Compute new string
        new_data = bytes(uc.mem_read(p, n2)) if (p and n2) else b''
        new_str = old[:pos] + new_data + old[pos + n1:]
        new_len = len(new_str)
        if new_len <= 15:
            buf_va = this_ptr + 16
            uc.mem_write(buf_va, new_str + b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf_va))
            uc.mem_write(this_ptr+8, struct.pack('<Q', new_len))
        else:
            buf = alloc(new_len + 1)
            uc.mem_write(buf, new_str + b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf))
            uc.mem_write(this_ptr+8, struct.pack('<Q', new_len))
            uc.mem_write(this_ptr+16, struct.pack('<Q', new_len))
        ret_val = this_ptr
    elif name == '_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4findEPKcmm':
        # std::string::find(p, pos, n) const: return offset or npos
        this_ptr = rdi
        p, pos, n = rsi, rdx, rcx
        buf_ptr = struct.unpack('<Q', bytes(uc.mem_read(this_ptr, 8)))[0]
        cur_len = struct.unpack('<Q', bytes(uc.mem_read(this_ptr+8, 8)))[0]
        if buf_ptr and cur_len < 0x10000:
            haystack = bytes(uc.mem_read(buf_ptr, cur_len))
            needle = bytes(uc.mem_read(p, n)) if n > 0 else b''
            idx = haystack.find(needle, pos)
            ret_val = idx if idx >= 0 else 0xFFFFFFFFFFFFFFFF  # npos
        else:
            ret_val = 0xFFFFFFFFFFFFFFFF
    elif name in ('srand', 'madvise', '__cxa_atexit', 'pthread_once'):
        ret_val = 0
    elif name == 'rand':
        ret_val = 0  # deterministic with libfaketime
    elif name == 'getpid':
        ret_val = 1
    elif name == '_ZNSt6chrono3_V212system_clock3nowEv':
        ret_val = 0  # deterministic time
    elif name == 'snprintf':
        # snprintf(s, n, fmt, ...): write empty string
        s = rdi; n = rsi
        if s and n > 0:
            uc.mem_write(s, b'\x00')
        ret_val = 0
    elif name == '__tls_get_addr':
        # Return a small TLS slot
        ret_val = alloc(64)
    elif name == '_ZSt20__throw_system_errori':
        # Should not return — but we have to. Just return.
        ret_val = 0
    elif name == 'fopen':
        ret_val = 0  # NULL = file open failed; caller should handle
    elif name == 'fgets':
        ret_val = 0  # NULL = EOF/error
    elif name == 'fclose':
        ret_val = 0
    elif name == '_ZNSt6vectorIlSaIlEE17_M_realloc_insertIJRlEEEvN9__gnu_cxx17__normal_iteratorIPlS1_EEDpOT_':
        # std::vector<long>::_M_realloc_insert(iterator pos, long&) — same logic, simplified
        this_ptr = rdi
        # rsi = iterator (pointer), rdx = ptr to value
        val_ptr = rdx
        val = struct.unpack('<q', bytes(uc.mem_read(val_ptr, 8)))[0]
        begin = struct.unpack('<Q', bytes(uc.mem_read(this_ptr, 8)))[0]
        end = struct.unpack('<Q', bytes(uc.mem_read(this_ptr+8, 8)))[0]
        size = (end - begin) // 8 if begin else 0
        new_cap = max(size * 2, 4)
        new_buf = alloc(new_cap * 8)
        if begin and size: uc.mem_write(new_buf, bytes(uc.mem_read(begin, size*8)))
        uc.mem_write(new_buf + size*8, struct.pack('<q', val))
        uc.mem_write(this_ptr, struct.pack('<Q', new_buf))
        uc.mem_write(this_ptr+8, struct.pack('<Q', new_buf + (size+1)*8))
        uc.mem_write(this_ptr+16, struct.pack('<Q', new_buf + new_cap*8))
        ret_val = 0
    else:
        # Default: allocate a buffer (helps for unknown allocator-like calls)
        ret_val = alloc(256)
    uc.reg_write(UC_X86_REG_RAX, ret_val)
    # Pop return addr from stack and jump
    rsp = uc.reg_read(UC_X86_REG_RSP)
    rip_b = uc.mem_read(rsp, 8)
    ret_addr = struct.unpack('<Q', bytes(rip_b))[0]
    uc.reg_write(UC_X86_REG_RSP, rsp + 8)
    uc.reg_write(UC_X86_REG_RIP, ret_addr)

last_jump_log = []
def hook_code(uc, address, size, user_data):
    exec_count[0] += 1
    # Log if RIP is suspiciously low
    if address < 0x10000:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        last_jump_log.append((exec_count[0], address, rsp))
        if len(last_jump_log) > 5:
            uc.emu_stop()
    # Detect PLT entry execution
    if PLT_LO_VA <= address < PLT_HI_VA:
        stub_handle(uc, address)
        return
    # Detect execution leaving wrapper.node
    if not (WRAPPER_START <= address < WRAPPER_END):
        # Outside wrapper.node — must be a PLT-stubbed function jumped to actual lib code
        # Find caller (return address on top of stack)
        # We can't know which symbol; treat as unknown stub returning 0
        rsp = uc.reg_read(UC_X86_REG_RSP)
        rip_b = uc.mem_read(rsp, 8)
        ret_addr = struct.unpack('<Q', bytes(rip_b))[0]
        stub_calls[f'extern@0x{address-WBASE:x}'] = stub_calls.get(f'extern@0x{address-WBASE:x}', 0) + 1
        # Return 0 (or pointer to small heap buffer)
        uc.reg_write(UC_X86_REG_RAX, alloc(64))
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)
        return
    if exec_count[0] in (1, 100, 1000, 10000, 100000, 500000, 1000000, 5000000):
        try:
            b = uc.mem_read(address, size)
            ins = next(md.disasm(bytes(b), address), None)
            print(f"  [{exec_count[0]:>7d}] 0x{address:08x}: {ins.mnemonic if ins else '???'} {ins.op_str if ins else ''}")
        except: pass
mu.hook_add(UC_HOOK_CODE, hook_code)

invalid_log = []
def hook_invalid(uc, access, address, size, value, user_data):
    rip = uc.reg_read(UC_X86_REG_RIP)
    invalid_log.append((rip, access, address, size))
    if len(invalid_log) <= 5:
        print(f"  INVALID @ 0x{rip:x} (offset 0x{rip-WBASE:x}): access={access} addr=0x{address:x} sz={size}")
    return False
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_invalid)

import time
# DEFINITIVE TEST: zero out the suspected output buffer location BEFORE running.
# If emulation works, it should write the correct sign there.
SIG_LOCATIONS = {
    '/tmp/op60_memdump.json':    0x24922b0,
    '/tmp/op60_memdump_42.json': 0x2137640,
}
clear_addr = SIG_LOCATIONS.get(DUMP_PATH)
if clear_addr:
    mu.mem_write(clear_addr, b'\xCC' * 32)  # Marker bytes
    print(f"Zeroed (filled with 0xCC) buffer at 0x{clear_addr:x} before emulation")

print(f"\nStarting at RIP=0x{regs['rip']:x}")
t0 = time.time()
try:
    mu.emu_start(regs['rip'], 0xffffffffffffffff, count=10000000)
    print(f"Finished after {time.time()-t0:.2f}s, executed {exec_count[0]} instructions")
    final_rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"  Final RIP: 0x{final_rip:x}")
    print(f"  Last low-RIP jumps: {last_jump_log}")
    # Search for X_b1_init[0]=0x114D0B11 in post-emulation memory.
    # If present, op 0x60 successfully wrote the cipher init state.
    target = 0x114D0B11
    pat = struct.pack('<I', target)
    found_xb1 = []
    for rng in m['ranges']:
        try:
            d = bytes(mu.mem_read(rng['addr'], rng['size']))
            pos = 0
            while True:
                idx = d.find(pat, pos)
                if idx < 0: break
                found_xb1.append(rng['addr'] + idx)
                pos = idx + 1
        except UcError: pass
    print(f"  X_b1_init[0]=0x114D0B11 found at {len(found_xb1)} positions: {[hex(x) for x in found_xb1[:10]]}")

    # If found, dump X_b1_init[0..3] and X_b2_init[1] from those locations
    expected_xb1_for_src0 = [0x114D0B11, 0xAFFC818B, 0xFC57448F, 0x011D0687]
    expected_xb2_1 = 0x8DBF308F
    for va in found_xb1:
        try:
            xb1 = struct.unpack('<4I', bytes(mu.mem_read(va, 16)))
            if list(xb1) == expected_xb1_for_src0:
                print(f"  ✅ EXACT MATCH for X_b1_init at VA 0x{va:x}: {[hex(x) for x in xb1]}")
            else:
                print(f"     X_b1[0..3] at 0x{va:x}: {[hex(x) for x in xb1]}")
        except: pass

    # Compare entire memory before/after emulation. Bytes that DIFFER are what
    # our emulation wrote. If hash output is among them, it appears as new bytes
    # in heap/stack regions.
    _sig_map = {
        '/tmp/op60_memdump.json':    'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f',
        '/tmp/op60_memdump_42.json': '9fb5974211ac4e148579b26575ecc8c34f3dfd82728cecaf00ab0bfb394186e3',
    }
    expected_sig = bytes.fromhex(_sig_map.get(DUMP_PATH, 'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f'))
    sig_locations_after = []
    sig_locations_before = []
    for rng in m['ranges']:
        try:
            d_after = bytes(mu.mem_read(rng['addr'], rng['size']))
            d_before = open(rng['file'], 'rb').read()
            pos = 0
            while True:
                idx = d_after.find(expected_sig, pos)
                if idx < 0: break
                sig_locations_after.append(rng['addr'] + idx)
                pos = idx + 1
            pos = 0
            while True:
                idx = d_before.find(expected_sig, pos)
                if idx < 0: break
                sig_locations_before.append(rng['addr'] + idx)
                pos = idx + 1
        except UcError: pass
    new_sig_locs = set(sig_locations_after) - set(sig_locations_before)
    print(f"  Expected sign in memory BEFORE emulation: {len(sig_locations_before)} locations: {[hex(x) for x in sig_locations_before]}")
    print(f"  Expected sign in memory AFTER emulation:  {len(sig_locations_after)} locations: {[hex(x) for x in sig_locations_after]}")
    print(f"  NEW locations (only after emulation): {len(new_sig_locs)}: {[hex(x) for x in new_sig_locs]}")
except UcError as e:
    print(f"  UcError after {time.time()-t0:.2f}s, executed {exec_count[0]}: {e}")
    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"  RIP at error: 0x{rip:x} (offset 0x{rip-WBASE:x})")

# Always do hash check (even after error)
# Search for each X_b1/X_b2 value, plus the expected sign output
expected_xb1 = [0x114D0B11, 0xAFFC818B, 0xFC57448F, 0x011D0687]
expected_xb2_1 = 0x8DBF308F
_sig_map = {
    '/tmp/op60_memdump.json':    'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f',
    '/tmp/op60_memdump_42.json': '9fb5974211ac4e148579b26575ecc8c34f3dfd82728cecaf00ab0bfb394186e3',
}
expected_sig = bytes.fromhex(_sig_map.get(DUMP_PATH, 'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f'))

def find_pattern(pat):
    found = []
    for rng in m['ranges']:
        try:
            d = bytes(mu.mem_read(rng['addr'], rng['size']))
            pos = 0
            while True:
                idx = d.find(pat, pos)
                if idx < 0: break
                found.append(rng['addr'] + idx)
                pos = idx + 1
        except UcError: pass
    return found

for label, val in [('X_b1[0]=0x114D0B11', struct.pack('<I', 0x114D0B11)),
                    ('X_b1[1]=0xAFFC818B', struct.pack('<I', 0xAFFC818B)),
                    ('X_b1[2]=0xFC57448F', struct.pack('<I', 0xFC57448F)),
                    ('X_b1[3]=0x011D0687', struct.pack('<I', 0x011D0687)),
                    ('X_b2[1]=0x8DBF308F', struct.pack('<I', 0x8DBF308F))]:
    found = find_pattern(val)
    print(f"  {label}: found at {len(found)} positions")
    for va in found[:3]:
        print(f"    @ 0x{va:x}")

found_sig = find_pattern(expected_sig)
print(f"  Full sign (32B): found at {len(found_sig)} positions: {[hex(x) for x in found_sig]}")

# Also search OUR heap region (where stubs allocate)
try:
    our_heap = bytes(mu.mem_read(HEAP_VA, heap_top[0] - HEAP_VA))
    pos = our_heap.find(expected_sig)
    if pos >= 0:
        print(f"  ✅ Expected sign found in our_heap at offset 0x{pos:x} (VA 0x{HEAP_VA + pos:x})!")
    else:
        # Try shorter prefixes
        for plen in [16, 8, 4]:
            p = our_heap.find(expected_sig[:plen])
            if p >= 0:
                print(f"  Found {plen}-byte prefix in our_heap at offset 0x{p:x}")
                break
except UcError: pass

# Check final register state
print("\n  Final register state:")
for k, ucr in [('rax', UC_X86_REG_RAX), ('rbx', UC_X86_REG_RBX),
               ('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX),
               ('rsi', UC_X86_REG_RSI), ('rdi', UC_X86_REG_RDI),
               ('rbp', UC_X86_REG_RBP), ('rsp', UC_X86_REG_RSP),
               ('r8', UC_X86_REG_R8),  ('r9', UC_X86_REG_R9),
               ('r12', UC_X86_REG_R12),('r13', UC_X86_REG_R13),
               ('r14', UC_X86_REG_R14),('r15', UC_X86_REG_R15)]:
    v = mu.reg_read(ucr)
    note = ''
    if v == 0x114D0B11: note = ' ← X_b1[0]!'
    elif v == 0xAFFC818B: note = ' ← X_b1[1]!'
    elif v == 0xFC57448F: note = ' ← X_b1[2]!'
    elif v == 0x11D0687: note = ' ← X_b1[3]!'
    elif v == 0x8DBF308F: note = ' ← X_b2[1]!'
    elif (v & 0xffffffff) == 0x114D0B11: note = ' ← X_b1[0] (low 32)!'
    elif (v & 0xffffffff) == 0xFC57448F: note = ' ← X_b1[2] (low 32)!'
    print(f"    {k:>5s} = 0x{v:016x}{note}")

# Compare pre/post memory: which ranges did our emulation modify?
print("\n  Memory regions modified by emulation:")
total_changes = 0
modified_ranges = []
for rng in m['ranges']:
    try:
        d_after = bytes(mu.mem_read(rng['addr'], rng['size']))
        d_before = open(rng['file'], 'rb').read()
        if d_after != d_before:
            # Count differences
            ndiff = sum(1 for a,b in zip(d_after, d_before) if a != b)
            modified_ranges.append((rng['addr'], rng['size'], ndiff))
            total_changes += ndiff
    except UcError: pass

print(f"  Total bytes modified across all ranges: {total_changes}")
print(f"  Ranges with changes:")
for addr, sz, ndiff in sorted(modified_ranges, key=lambda x: -x[2])[:10]:
    print(f"    0x{addr:x} ({sz} bytes): {ndiff} bytes changed")

# Detailed look at heap range (0x22dd000 - 0x24b2000) byte-by-byte
heap_range = next(r for r in m['ranges'] if r['addr'] == 0x22dd000)
d_after = bytes(mu.mem_read(heap_range['addr'], heap_range['size']))
d_before = open(heap_range['file'], 'rb').read()
print(f"\n  Heap byte changes around expected sign location 0x24922b0:")
sig_offset = 0x24922b0 - 0x22dd000
# Show bytes [sig_offset - 16, sig_offset + 48]
for i in range(sig_offset - 16, sig_offset + 48, 8):
    if i < 0 or i + 8 > len(d_after): continue
    b_b = d_before[i:i+8].hex()
    a_b = d_after[i:i+8].hex()
    diff = '🔄' if b_b != a_b else '   '
    print(f"    0x{0x22dd000+i:x}: BEFORE={b_b}  AFTER={a_b} {diff}")

# Also show ALL changed positions in heap
changed_positions = [i for i in range(len(d_after)) if d_after[i] != d_before[i]]
print(f"\n  All {len(changed_positions)} changed positions in heap:")
for i in changed_positions[:30]:
    print(f"    0x{0x22dd000+i:x}: {d_before[i]:02x} -> {d_after[i]:02x}")
print(f"\nStub calls made: {len(stub_calls)}")
for nm, c in sorted(stub_calls.items(), key=lambda x: -x[1])[:30]:
    print(f"  {c:>4d}x  {nm}")
