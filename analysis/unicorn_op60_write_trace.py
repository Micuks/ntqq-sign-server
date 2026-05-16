"""Unicorn replay v2: use full memory dump from same Frida run."""
import struct, json, os
from collections import defaultdict, deque
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
guest_exec_ranges = []
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
    if perms & UC_PROT_EXEC:
        guest_exec_ranges.append((va_start, va_end))
    print(f"  Mapped wrapper.node seg {i}: 0x{va_start:x}-0x{va_end:x} perms={perms}")

def overlaps_wrapper(a, b):
    for ws, we in wrapper_va_ranges:
        if a < we and b > ws:
            return True
    return False

def is_guest_exec(addr):
    return any(start <= addr < end for start, end in guest_exec_ranges)

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
        if perms & UC_PROT_EXEC:
            guest_exec_ranges.append((page_start, page_end))
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
    if 'WATCH_ADDR' in globals() and WATCH_ADDR:
        try:
            record_watch_event('stub_alloc', mu.reg_read(UC_X86_REG_RIP), p, max(n, 16), 0, f'n={n}')
        except Exception:
            pass
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
OUT_BUF_BASE = 0x24920b0
OUT_BUF_END = OUT_BUF_BASE + 0x300

# Hooks
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
exec_count = [0]
stub_calls = {}
out_events = []
int3_events = []
extern_events = []
key_hits = defaultdict(int)
watch_events = []
fake_files = {}

def stack_qwords(uc, rsp, count=16):
    rows = []
    for off in range(0, count * 8, 8):
        try:
            val = struct.unpack('<Q', bytes(uc.mem_read(rsp + off, 8)))[0]
            note = ''
            if WRAPPER_START <= val < WRAPPER_END:
                note = f' wrapper+0x{val - WBASE:x}'
            elif val == 0x8000feff8000feff:
                note = ' sentinel'
            rows.append((off, val, note))
        except UcError:
            rows.append((off, None, ' unreadable'))
            break
    return rows

def overlaps_out(addr, size):
    return addr < OUT_BUF_END and addr + max(size, 1) > OUT_BUF_BASE

def record_out_event(kind, rip, addr, size, detail=''):
    if len(out_events) < 200:
        out_events.append((exec_count[0], kind, rip, addr, size, detail))

def overlaps_watch(addr, size):
    return WATCH_ADDR and addr < WATCH_ADDR + 0x80 and addr + max(size, 1) > WATCH_ADDR

def record_watch_event(kind, rip, addr, size, value=0, detail=''):
    if not overlaps_watch(addr, size):
        return
    if len(watch_events) >= 500:
        return
    try:
        sample = bytes(mu.mem_read(WATCH_ADDR, 0x40)).hex()
    except UcError:
        sample = '<unreadable>'
    watch_events.append((exec_count[0], kind, rip, addr, size, value, region_label(addr), sample, detail))

def read_c_string(uc, addr, max_len=0x10000):
    out = bytearray()
    for off in range(max_len):
        b = uc.mem_read(addr + off, 1)[0]
        if b == 0:
            break
        out.append(b)
    return bytes(out)

def write_c_string(uc, dst, n, data):
    if not dst or n == 0:
        return
    clipped = data[:max(n - 1, 0)]
    uc.mem_write(dst, clipped + b'\x00')
    record_watch_event('stub_c_string_out', uc.reg_read(UC_X86_REG_RIP), dst, len(clipped) + 1, 0)

def format_snprintf(uc, fmt, arg1, arg2, arg3):
    if fmt == b'/proc/%d/comm':
        return f'/proc/{arg1 & 0xffffffff}/comm'.encode()
    if fmt == b'%s:%d ':
        try:
            prefix = read_c_string(uc, arg1, 512)
        except UcError:
            prefix = b''
        return prefix + b':' + str(arg2 & 0xffffffff).encode() + b' '
    # Conservative fallback for plain strings, used by a logging vsnprintf
    # call in this replay.
    if b'%' not in fmt:
        return fmt
    return b''

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
    rsp_at_call = uc.reg_read(UC_X86_REG_RSP)
    try:
        call_ret_addr = struct.unpack('<Q', bytes(uc.mem_read(rsp_at_call, 8)))[0]
    except UcError:
        call_ret_addr = 0
    # Emulate the call
    ret_val = 0
    if name in ('malloc','_Znwm','_Znam','_ZnwmRKSt9nothrow_t'):
        ret_val = alloc(rdi)
    elif name == 'memset':
        if 0 < rdx <= 0x100000:
            uc.mem_write(rdi, bytes([rsi & 0xff]) * rdx)
            record_watch_event('stub_memset_dst', plt_va, rdi, rdx, rsi & 0xff, f'name={name}')
            if overlaps_out(rdi, rdx):
                record_out_event('stub_memset', plt_va, rdi, rdx, f'c=0x{rsi & 0xff:x}')
        elif rdx > 0x100000:
            stub_calls['memset_oversize'] = stub_calls.get('memset_oversize', 0) + 1
        ret_val = rdi
    elif name in ('memcpy','memmove'):
        if 0 < rdx <= 0x100000:
            uc.mem_write(rdi, bytes(uc.mem_read(rsi, rdx)))
            record_watch_event(f'stub_{name}_dst', plt_va, rdi, rdx, 0, f'src=0x{rsi:x}')
            record_watch_event(f'stub_{name}_src', plt_va, rsi, rdx, 0, f'dst=0x{rdi:x}')
            if overlaps_out(rdi, rdx):
                record_out_event(f'stub_{name}', plt_va, rdi, rdx, f'src=0x{rsi:x}')
        elif rdx > 0x100000:
            stub_calls[f'{name}_oversize'] = stub_calls.get(f'{name}_oversize', 0) + 1
        ret_val = rdi
    elif name in ('memcmp','bcmp'):
        if rdx == 0: ret_val = 0
        elif rdx <= 0x100000:
            A = bytes(uc.mem_read(rdi, rdx))
            B = bytes(uc.mem_read(rsi, rdx))
            if A == B:
                ret_val = 0
            else:
                idx = next(i for i in range(rdx) if A[i] != B[i])
                ret_val = (A[idx] - B[idx]) & 0xffffffffffffffff
            if stub_calls[name] <= 8:
                key_hits[f'{name}:call=0x{call_ret_addr-WBASE-5:x}:n={rdx}:ret={ret_val if ret_val < (1<<63) else ret_val-(1<<64)}'] += 1
        else:
            stub_calls[f'{name}_oversize'] = stub_calls.get(f'{name}_oversize', 0) + 1
            ret_val = 0
    elif name == 'strlen':
        sz = 0
        while sz < 0x10000:
            if uc.mem_read(rdi + sz, 1)[0] == 0: break
            sz += 1
        ret_val = sz
    elif name in ('strcmp', 'strncmp'):
        max_len = rdx if name == 'strncmp' else 0x10000
        try:
            a = read_c_string(uc, rdi, max_len)
            b = read_c_string(uc, rsi, max_len)
            if a == b:
                ret_val = 0
            else:
                aa = a + b'\x00'
                bb = b + b'\x00'
                idx = next(i for i in range(min(len(aa), len(bb))) if aa[i] != bb[i])
                ret_val = (aa[idx] - bb[idx]) & 0xffffffffffffffff
            if stub_calls[name] <= 8:
                key_hits[f'{name}:{a[:48]!r}:{b[:48]!r}:ret={ret_val if ret_val < (1<<63) else ret_val-(1<<64)}'] += 1
        except UcError:
            ret_val = 1
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
            buf_va = this_ptr + 16
            uc.mem_write(buf_va, b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf_va))
            uc.mem_write(this_ptr+8, struct.pack('<Q', 0))
            ret_val = 0
        else:
            chars = bytes(uc.mem_read(p, length))
            if length <= 15:
                # SSO: chars go inline at this+16
                buf_va = this_ptr + 16
                uc.mem_write(buf_va, chars + b'\x00')
                uc.mem_write(this_ptr, struct.pack('<Q', buf_va))  # _M_dataplus._M_p
                uc.mem_write(this_ptr+8, struct.pack('<Q', length))  # _M_string_length
                record_watch_event('stub_string_construct_inline', plt_va, buf_va, length + 1, 0, f'this=0x{this_ptr:x}')
            else:
                # Heap allocation
                buf = alloc(length + 1)
                uc.mem_write(buf, chars + b'\x00')
                uc.mem_write(this_ptr, struct.pack('<Q', buf))
                uc.mem_write(this_ptr+8, struct.pack('<Q', length))
                uc.mem_write(this_ptr+16, struct.pack('<Q', length))  # capacity
                record_watch_event('stub_string_construct_heap', plt_va, buf, length + 1, 0, f'this=0x{this_ptr:x} src=0x{p:x}')
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
            record_watch_event('stub_string_replace_inline', plt_va, buf_va, new_len + 1, 0, f'this=0x{this_ptr:x}')
        else:
            buf = alloc(new_len + 1)
            uc.mem_write(buf, new_str + b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf))
            uc.mem_write(this_ptr+8, struct.pack('<Q', new_len))
            uc.mem_write(this_ptr+16, struct.pack('<Q', new_len))
            record_watch_event('stub_string_replace_heap', plt_va, buf, new_len + 1, 0, f'this=0x{this_ptr:x} src=0x{p:x}')
        ret_val = this_ptr
    elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_assignERKS4_':
        # std::string::_M_assign(std::string const&)
        this_ptr = rdi
        other_ptr = rsi
        src_buf = struct.unpack('<Q', bytes(uc.mem_read(other_ptr, 8)))[0]
        src_len = struct.unpack('<Q', bytes(uc.mem_read(other_ptr + 8, 8)))[0]
        if src_buf and src_len <= 0x100000:
            chars = bytes(uc.mem_read(src_buf, src_len))
        else:
            src_len = 0
            chars = b''
        if src_len <= 15:
            buf_va = this_ptr + 16
            uc.mem_write(buf_va, chars + b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf_va))
            uc.mem_write(this_ptr + 8, struct.pack('<Q', src_len))
            record_watch_event('stub_string_assign_inline', plt_va, buf_va, src_len + 1, 0, f'this=0x{this_ptr:x} other=0x{other_ptr:x}')
        else:
            buf = alloc(src_len + 1)
            uc.mem_write(buf, chars + b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf))
            uc.mem_write(this_ptr + 8, struct.pack('<Q', src_len))
            uc.mem_write(this_ptr + 16, struct.pack('<Q', src_len))
            record_watch_event('stub_string_assign_heap', plt_va, buf, src_len + 1, 0, f'this=0x{this_ptr:x} other=0x{other_ptr:x} src=0x{src_buf:x}')
        if stub_calls[name] <= 4:
            key_hits[f'_M_assign:{chars[:80]!r}:len={src_len}'] += 1
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
    elif name == '_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6resizeEmc':
        # std::string::resize(n, c)
        this_ptr = rdi
        n = rsi
        fill = rdx & 0xff
        if n <= 15:
            buf_va = this_ptr + 16
            uc.mem_write(buf_va, bytes([fill]) * n + b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf_va))
            uc.mem_write(this_ptr+8, struct.pack('<Q', n))
            record_watch_event('stub_string_resize_inline', plt_va, buf_va, n + 1, fill, f'this=0x{this_ptr:x}')
        elif n <= 0x100000:
            buf = alloc(n + 1)
            uc.mem_write(buf, bytes([fill]) * n + b'\x00')
            uc.mem_write(this_ptr, struct.pack('<Q', buf))
            uc.mem_write(this_ptr+8, struct.pack('<Q', n))
            uc.mem_write(this_ptr+16, struct.pack('<Q', n))
            record_watch_event('stub_string_resize_heap', plt_va, buf, n + 1, fill, f'this=0x{this_ptr:x}')
        ret_val = 0
    elif name in ('free', '_ZdlPv', '_ZdaPv', 'srand', 'madvise', '__cxa_atexit', 'pthread_once'):
        ret_val = 0
    elif name == 'pthread_self':
        ret_val = 1
    elif (name.startswith('pthread_') or name.startswith('__pthread_') or
          name.startswith('uv_mutex_') or
          name.startswith('_ZNSt18condition_variable')):
        # Success path for synchronization primitives. Returning the default
        # heap pointer here makes callers think pthread_mutex_lock failed and
        # triggers __throw_system_errori.
        ret_val = 0
    elif name == 'rand':
        ret_val = 0  # deterministic with libfaketime
    elif name == 'getpid':
        ret_val = int(os.environ.get('EMU_GETPID', '1'))
    elif name == 'uname':
        # struct utsname is 6 fields × 65 bytes = 390 bytes.
        # Native run on this host returns nodename="idmg-monitor".
        if rdi:
            UTSNAME_FIELDLEN = 65
            buf = bytearray(b'\x00' * (UTSNAME_FIELDLEN * 6))
            sysname  = os.environ.get('EMU_SYSNAME',  'Linux').encode()
            nodename = os.environ.get('EMU_NODENAME', 'idmg-monitor').encode()
            release  = os.environ.get('EMU_RELEASE',  '5.13.0-39-generic').encode()
            version  = os.environ.get('EMU_VERSION',  '#44~20.04.1-Ubuntu SMP Mon Mar 7 19:34:14 UTC 2022').encode()
            machine  = os.environ.get('EMU_MACHINE',  'x86_64').encode()
            domain   = os.environ.get('EMU_DOMAIN',   '(none)').encode()
            for i, s in enumerate([sysname, nodename, release, version, machine, domain]):
                s = s[:UTSNAME_FIELDLEN - 1]
                buf[i*UTSNAME_FIELDLEN:i*UTSNAME_FIELDLEN+len(s)] = s
            try: uc.mem_write(rdi, bytes(buf))
            except UcError: pass
            record_watch_event('stub_uname_out', plt_va, rdi, len(buf), 0, f'nodename={nodename!r}')
        ret_val = 0
    elif name == 'time':
        if rdi:
            try: uc.mem_write(rdi, struct.pack('<Q', 0))
            except UcError: pass
            record_watch_event('stub_time_out', plt_va, rdi, 8, 0, f'name={name}')
        ret_val = 0
    elif name == 'clock_gettime':
        if rsi:
            try: uc.mem_write(rsi, struct.pack('<QQ', 0, 0))
            except UcError: pass
            record_watch_event('stub_clock_gettime_out', plt_va, rsi, 16, 0, f'name={name}')
        ret_val = 0
    elif name == 'gettimeofday':
        if rdi:
            try: uc.mem_write(rdi, struct.pack('<QQ', 0, 0))
            except UcError: pass
            record_watch_event('stub_gettimeofday_out', plt_va, rdi, 16, 0, f'name={name}')
        ret_val = 0
    elif name in ('strftime', 'strftime_l'):
        if rdi and rsi:
            try: uc.mem_write(rdi, b'\x00')
            except UcError: pass
            record_watch_event('stub_strftime_out', plt_va, rdi, 1, 0, f'name={name}')
        ret_val = 0
    elif name in ('localtime', 'localtime_r', 'gmtime', 'gmtime_r'):
        ret_val = rsi if name.endswith('_r') else 0
    elif name == '_ZNSt6chrono3_V212system_clock3nowEv':
        ret_val = 0  # deterministic time
    elif name in ('snprintf', 'vsnprintf'):
        # snprintf(s, n, fmt, ...). Only the observed formats are needed for
        # this replay; unknown formats are still logged and become empty.
        s = rdi; n = rsi
        out = b''
        try:
            fmt = read_c_string(uc, rdx, 512)
            out = format_snprintf(
                uc, fmt,
                rcx,
                uc.reg_read(UC_X86_REG_R8),
                uc.reg_read(UC_X86_REG_R9),
            )
            key_hits[
                f'{name}:call=0x{call_ret_addr-WBASE-5:x}:fmt={fmt[:96]!r}:'
                f'out={out[:96]!r}:rcx=0x{rcx:x}:r8=0x{uc.reg_read(UC_X86_REG_R8):x}:'
                f'r9=0x{uc.reg_read(UC_X86_REG_R9):x}:n={n}'
            ] += 1
        except UcError:
            pass
        if s and n > 0:
            write_c_string(uc, s, n, out)
            record_watch_event('stub_snprintf_out', plt_va, s, min(len(out) + 1, n), 0, f'name={name}')
        ret_val = len(out)
    elif name in ('sprintf', 'vsprintf'):
        if rdi:
            uc.mem_write(rdi, b'\x00')
            record_watch_event('stub_sprintf_out', plt_va, rdi, 1, 0, f'name={name}')
        ret_val = 0
    elif name in ('printf', 'fprintf', 'vfprintf', 'swprintf'):
        ret_val = 0
    elif name == 'vasprintf':
        if rdi:
            try: uc.mem_write(rdi, struct.pack('<Q', 0))
            except UcError: pass
        ret_val = -1 & 0xffffffffffffffff
    elif name in ('_ZNSt13__future_base12_Result_baseC2Ev',
                  '_ZNSt13__future_base12_Result_baseD2Ev',
                  '_ZSt20__throw_future_errori'):
        ret_val = 0
    elif name == '__tls_get_addr':
        # Return a small TLS slot
        ret_val = alloc(64)
    elif name == '_ZSt20__throw_system_errori':
        # Should not return — but we have to. Just return.
        ret_val = 0
    elif name == 'fopen':
        try:
            path = read_c_string(uc, rdi, 512)
            mode = read_c_string(uc, rsi, 32)
            key_hits[f'fopen:{path!r}:{mode!r}'] += 1
            if path.startswith(b'/proc/') and path.endswith(b'/comm') and mode.startswith(b'r'):
                ret_val = alloc(16)
                fake_files[ret_val] = b'ld-linux-x86-64\n'
            else:
                ret_val = 0
        except UcError:
            ret_val = 0
    elif name == 'fgets':
        dst = rdi
        n = rsi
        stream = rdx
        data = fake_files.get(stream)
        if data and dst and n > 0:
            write_c_string(uc, dst, n, data)
            key_hits[f'fgets:{data!r}:n={n}'] += 1
            ret_val = dst
            fake_files[stream] = b''
        else:
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
    off = address - WBASE
    if 0x56d8600 <= off <= 0x56d8680:
        key_hits[f'output_copy+0x{off - 0x56d8600:x}'] += 1
        if key_hits[f'output_copy+0x{off - 0x56d8600:x}'] <= 3:
            rsp = uc.reg_read(UC_X86_REG_RSP)
            print(f"  HIT output-copy band at off=0x{off:x} insn={exec_count[0]} rsp=0x{rsp:x}")
    # Detect execution leaving all captured executable guest code.
    if not is_guest_exec(address):
        # Outside mapped guest code — find caller on stack and ret to it.
        # Scan first 256 bytes of stack for valid wrapper.node return addr.
        rsp = uc.reg_read(UC_X86_REG_RSP)
        extern_event = {'insn': exec_count[0], 'address': address, 'rsp': rsp, 'stack': stack_qwords(uc, rsp, 12)}
        recovered = False
        for off in range(0, 256, 8):
            try:
                cand = struct.unpack('<Q', bytes(uc.mem_read(rsp + off, 8)))[0]
            except UcError:
                break
            if WRAPPER_START <= cand < WRAPPER_END:
                stub_calls[f'extern@0x{address:x}'] = stub_calls.get(f'extern@0x{address:x}', 0) + 1
                uc.reg_write(UC_X86_REG_RAX, alloc(64))
                uc.reg_write(UC_X86_REG_RSP, rsp + off + 8)
                uc.reg_write(UC_X86_REG_RIP, cand)
                recovered = True
                extern_event['recovered_off'] = off
                extern_event['target'] = cand
                break
        extern_event['recovered'] = recovered
        if len(extern_events) < 20:
            extern_events.append(extern_event)
        if recovered:
            uc.emu_stop()
            return
        # No recovery possible — abort
        uc.emu_stop()
        return
    # Detect int3 (0xcc) — placed after no-return calls. Skip 1 byte forward.
    try:
        b0 = uc.mem_read(address, 1)[0]
        if b0 == 0xcc:
            rsp = uc.reg_read(UC_X86_REG_RSP)
            if len(int3_events) < 20:
                int3_events.append((exec_count[0], address, rsp, stack_qwords(uc, rsp, 12)))
            print(f"  INT3 skip at 0x{address:x} off=0x{address-WBASE:x} insn={exec_count[0]} rsp=0x{rsp:x}")
            uc.reg_write(UC_X86_REG_RIP, address + 1)
            uc.emu_stop()
            return
    except Exception: pass
    if exec_count[0] in (1, 100, 1000, 10000, 100000, 500000, 1000000, 5000000):
        try:
            b = uc.mem_read(address, size)
            ins = next(md.disasm(bytes(b), address), None)
            print(f"  [{exec_count[0]:>7d}] 0x{address:08x}: {ins.mnemonic if ins else '???'} {ins.op_str if ins else ''}")
        except: pass
mu.hook_add(UC_HOOK_CODE, hook_code)

invalid_log = []
FORCE_RECOVER_OUTPUT = os.environ.get('FORCE_RECOVER_OUTPUT', '0') == '1'
invalid_recoveries = [0]

def find_stack_return(uc, rsp, pred, max_scan=0x1200):
    for off in range(0, max_scan, 8):
        try:
            cand = struct.unpack('<Q', bytes(uc.mem_read(rsp + off, 8)))[0]
        except UcError:
            break
        if pred(cand):
            return off, cand
    return None, None

def hook_invalid(uc, access, address, size, value, user_data):
    rip = uc.reg_read(UC_X86_REG_RIP)
    invalid_log.append((rip, access, address, size))
    rsp = uc.reg_read(UC_X86_REG_RSP)
    if len(invalid_log) <= 5:
        print(f"  INVALID @ 0x{rip:x} (offset 0x{rip-WBASE:x}): access={access} addr=0x{address:x} sz={size}")
        for off, val, note in stack_qwords(uc, rsp, 16):
            if val is None:
                print(f"      [rsp+0x{off:03x}] unreadable")
            else:
                print(f"      [rsp+0x{off:03x}] 0x{val:016x}{note}")
        ret_off, ret = find_stack_return(
            uc, rsp,
            lambda cand: WBASE + 0x56d8637 <= cand <= WBASE + 0x56d86e0,
        )
        if ret is not None:
            print(f"      output-copy return candidate [rsp+0x{ret_off:x}] = 0x{ret:x} off=0x{ret-WBASE:x}")
    if access == UC_MEM_FETCH_UNMAPPED and FORCE_RECOVER_OUTPUT:
        ret_off, ret = find_stack_return(
            uc, rsp,
            lambda cand: WBASE + 0x56d8637 <= cand <= WBASE + 0x56d86e0,
        )
        if ret is not None:
            print(f"  RECOVER fetch-unmapped to output-copy return 0x{ret:x} off=0x{ret-WBASE:x} stack_off=0x{ret_off:x}")
            caller_rsp = rsp + ret_off + 8
            uc.reg_write(UC_X86_REG_RAX, 0)
            uc.reg_write(UC_X86_REG_RSP, caller_rsp)
            # The forced return skips the callee epilogue. Rebuild the
            # caller's string-object registers from the setup immediately
            # preceding call 0x56d8632.
            if ret == WBASE + 0x56d8637:
                uc.reg_write(UC_X86_REG_R15, caller_rsp + 0xd0)
                uc.reg_write(UC_X86_REG_R14, caller_rsp + 0xb0)
                uc.reg_write(UC_X86_REG_R12, caller_rsp + 0x90)
                uc.reg_write(UC_X86_REG_RBP, caller_rsp + 0xf0)
            uc.reg_write(UC_X86_REG_RIP, ret)
            invalid_recoveries[0] += 1
            return True
    return False
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_invalid)

TRACE_WRITES_AFTER = int(os.environ.get('TRACE_WRITES_AFTER', '4000000'))
LATE_WRITES_AFTER = int(os.environ.get('LATE_WRITES_AFTER', '5000000'))
write_buckets = defaultdict(lambda: {'count': 0, 'bytes': 0, 'first': 0, 'last': 0, 'last_rip': 0})
late_bucket_masks = defaultdict(int)
late_write_events = deque(maxlen=20000)
interesting_writes = []
stack_read_events = []
WATCH_ADDR = int(os.environ.get('WATCH_ADDR', '0'), 0)

def region_label(addr):
    if HEAP_VA <= addr < heap_top[0]:
        return 'our_heap'
    if HEAP_VA <= addr < HEAP_VA + HEAP_SIZE:
        return 'our_heap_reserved'
    for rng in m['ranges']:
        if rng['addr'] <= addr < rng['addr'] + rng['size']:
            return f"dump:{rng.get('prot','???')}@0x{rng['addr']:x}"
    return 'other'

def hook_mem_write(uc, access, address, size, value, user_data):
    cnt = exec_count[0]
    if cnt < TRACE_WRITES_AFTER:
        return
    rip = uc.reg_read(UC_X86_REG_RIP)
    start_bucket = address & ~0xf
    end_bucket = (address + max(size, 1) - 1) & ~0xf
    b = start_bucket
    while b <= end_bucket:
        ent = write_buckets[b]
        ent['count'] += 1
        ent['bytes'] += size
        ent['first'] = ent['first'] or cnt
        ent['last'] = cnt
        ent['last_rip'] = rip
        if cnt >= LATE_WRITES_AFTER and size <= 0x1000:
            lo = max(address, b)
            hi = min(address + size, b + 16)
            mask = 0
            for off in range(lo - b, hi - b):
                mask |= 1 << off
            late_bucket_masks[b] |= mask
        b += 16
    if cnt >= LATE_WRITES_AFTER:
        late_write_events.append((cnt, rip, address, size, value, region_label(address)))
    if overlaps_out(address, size):
        record_out_event('guest_write', rip, address, size, f'value=0x{value:x}')
    record_watch_event('guest_write', rip, address, size, value)
    if (0x56c4000 <= rip - WBASE < 0x56d0000) or (0x56d0000 <= rip - WBASE < 0x56e0000):
        if len(interesting_writes) < 2000:
            interesting_writes.append((cnt, rip, address, size, value, region_label(address)))

mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)

WATCH_STACK_PTRS = {0x7ffeaeae2640, 0x7ffeaeae2678, 0x7ffeaeae2970}

def hook_mem_read(uc, access, address, size, value, user_data):
    if address in WATCH_STACK_PTRS or any(address < a + 8 and address + max(size, 1) > a for a in WATCH_STACK_PTRS):
        rip = uc.reg_read(UC_X86_REG_RIP)
        if len(stack_read_events) < 80:
            try:
                data = bytes(uc.mem_read(address, min(size, 16))).hex()
            except UcError:
                data = '<unreadable>'
            stack_read_events.append((exec_count[0], rip, address, size, data))
            print(f"  READ watched stack ptr off=0x{rip-WBASE:x} insn={exec_count[0]} addr=0x{address:x} size={size} data={data}")

mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

import time
# DEFINITIVE TEST: zero out the suspected output buffer location BEFORE running.
# If emulation works, it should write the correct sign there.
SIG_LOCATIONS = {
    '/tmp/op60_memdump.json':    0x24922b0,
    '/tmp/op60_memdump_42.json': 0x2137640,
}
clear_addr = SIG_LOCATIONS.get(DUMP_PATH)
# Keep captured native sign at 0x24922b0; we want to see if emulation
# either overwrites it (proving it controls that location) or doesn't.
print(f"NOT pre-filling 0x{clear_addr:x} — preserving captured native state")

print(f"\nStarting at RIP=0x{regs['rip']:x}")
t0 = time.time()
try:
    cur_pc = regs['rip']
    prev_pc = -1
    int3_skips = 0
    while exec_count[0] < 10_000_000:
        try:
            mu.emu_start(cur_pc, 0xffffffffffffffff, count=10_000_000 - exec_count[0])
        except UcError as e:
            rip_after_error = mu.reg_read(UC_X86_REG_RIP)
            print(f"  UcError after {exec_count[0]} insns: {e}, RIP=0x{rip_after_error:x}")
            if invalid_recoveries[0] and is_guest_exec(rip_after_error):
                cur_pc = rip_after_error
                invalid_recoveries[0] = 0
                continue
            break
        new_pc = mu.reg_read(UC_X86_REG_RIP)
        if new_pc == prev_pc:
            print(f"  STUCK at 0x{new_pc:x}")
            break
        if new_pc == cur_pc:
            break
        prev_pc = cur_pc
        cur_pc = new_pc
        # Track int3 skips for diagnostics
        try:
            b0 = mu.mem_read(new_pc - 1, 1)[0]
            if b0 == 0xcc:
                int3_skips += 1
        except: pass
    print(f"Finished after {time.time()-t0:.2f}s, executed {exec_count[0]} instructions, int3 skips={int3_skips}")
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

try:
    final_rsp = mu.reg_read(UC_X86_REG_RSP)
    print(f"\n  Final stack near RSP=0x{final_rsp:x}:")
    for off, val, note in stack_qwords(mu, final_rsp, 32):
        if val is None:
            print(f"    [rsp+0x{off:03x}] unreadable")
        else:
            print(f"    [rsp+0x{off:03x}] 0x{val:016x}{note}")
except UcError:
    pass

print(f"\n  INT3 events retained: {len(int3_events)}")
for cnt, rip, rsp, stk in int3_events:
    print(f"    insn={cnt:>7d} rip=0x{rip:x} off=0x{rip-WBASE:x} rsp=0x{rsp:x}")
    for off, val, note in stk[:8]:
        if val is None:
            print(f"      [rsp+0x{off:03x}] unreadable")
        else:
            print(f"      [rsp+0x{off:03x}] 0x{val:016x}{note}")

print(f"\n  External execution recoveries retained: {len(extern_events)}")
for ev in extern_events:
    status = 'recovered' if ev.get('recovered') else 'stopped'
    extra = ''
    if ev.get('recovered'):
        extra = f" target=0x{ev['target']:x} off=0x{ev['target']-WBASE:x} stack_off=0x{ev['recovered_off']:x}"
    print(f"    insn={ev['insn']:>7d} addr=0x{ev['address']:x} rsp=0x{ev['rsp']:x} {status}{extra}")
    for off, val, note in ev['stack'][:8]:
        if val is None:
            print(f"      [rsp+0x{off:03x}] unreadable")
        else:
            print(f"      [rsp+0x{off:03x}] 0x{val:016x}{note}")

print(f"\n  Watched stack pointer reads retained: {len(stack_read_events)}")
for cnt, rip, addr, size, data in stack_read_events:
    print(f"    insn={cnt:>7d} rip=0x{rip:x} off=0x{rip-WBASE:x} addr=0x{addr:x} size={size:<3d} data={data}")

if WATCH_ADDR:
    print(f"\n  WATCH_ADDR 0x{WATCH_ADDR:x} events retained: {len(watch_events)}")
    try:
        print(f"    final data: {bytes(mu.mem_read(WATCH_ADDR, 0x40)).hex()}")
    except UcError:
        print("    final data: <unreadable>")
    for cnt, kind, rip, addr, size, value, label, sample, detail in watch_events:
        print(
            f"    insn={cnt:>7d} {kind:<28s} rip=0x{rip:x} off=0x{rip-WBASE:x} "
            f"addr=0x{addr:x} size={size:<3d} value=0x{value:x} {label} "
            f"sample={sample} {detail}"
        )

print(f"\n  Key code hits: {dict(sorted(key_hits.items()))}")

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

print(f"\n  Write trace summary (emulated CPU writes after insn {TRACE_WRITES_AFTER}):")
print(f"    buckets touched: {len(write_buckets)}")
for addr, ent in sorted(write_buckets.items(), key=lambda kv: (-kv[1]['count'], kv[0]))[:40]:
    try:
        sample = bytes(mu.mem_read(addr, 32)).hex()
    except UcError:
        sample = '<unreadable>'
    print(
        f"    0x{addr:x} {region_label(addr):>24s} "
        f"count={ent['count']:>6d} bytes={ent['bytes']:>8d} "
        f"first={ent['first']:>7d} last={ent['last']:>7d} "
        f"last_rip=0x{ent['last_rip']:x} off=0x{ent['last_rip']-WBASE:x} data={sample[:64]}"
    )

def late_byte_written(addr):
    return bool(late_bucket_masks.get(addr & ~0xf, 0) & (1 << (addr & 0xf)))

full_32_windows = []
for bucket in sorted(late_bucket_masks):
    for start in range(bucket, bucket + 16):
        if all(late_byte_written(start + i) for i in range(32)):
            # Keep only first start of a run to avoid printing every overlap.
            if not full_32_windows or start > full_32_windows[-1] + 1:
                full_32_windows.append(start)

print(f"\n  Fully-written 32-byte windows after insn {LATE_WRITES_AFTER}: {len(full_32_windows)}")
for addr in full_32_windows[:80]:
    try:
        data = bytes(mu.mem_read(addr, 32)).hex()
    except UcError:
        data = '<unreadable>'
    print(f"    0x{addr:x} {region_label(addr):>24s} data={data}")

print(f"\n  Recent writes after insn {LATE_WRITES_AFTER} (last {len(late_write_events)} retained):")
for cnt, rip, addr, size, value, label in list(late_write_events)[-80:]:
    print(f"    insn={cnt:>7d} rip=0x{rip:x} off=0x{rip-WBASE:x} -> 0x{addr:x} size={size:<3d} value=0x{value:x} {label}")

print(f"\n  Writes from cipher/sign address bands retained: {len(interesting_writes)}")
for cnt, rip, addr, size, value, label in interesting_writes[:120]:
    print(f"    insn={cnt:>7d} rip=0x{rip:x} off=0x{rip-WBASE:x} -> 0x{addr:x} size={size:<3d} value=0x{value:x} {label}")

print(f"\n  OUT buffer events retained: {len(out_events)}")
for cnt, kind, rip, addr, size, detail in out_events:
    print(f"    insn={cnt:>7d} {kind:<12s} rip=0x{rip:x} off=0x{rip-WBASE:x} addr=0x{addr:x} size={size:<4d} {detail}")
try:
    out_buf = bytes(mu.mem_read(OUT_BUF_BASE, 0x300))
    print(f"  OUT[0x200:0x220] = {out_buf[0x200:0x220].hex()}")
    print(f"  OUT[0x2ff]       = 0x{out_buf[0x2ff]:02x}")
except UcError:
    pass
print(f"\nStub calls made: {len(stub_calls)}")
for nm, c in sorted(stub_calls.items(), key=lambda x: -x[1])[:30]:
    print(f"  {c:>4d}x  {nm}")
