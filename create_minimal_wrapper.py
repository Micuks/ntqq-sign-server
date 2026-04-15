#!/usr/bin/env python3
"""
Create a minimal wrapper.node by zeroing unused code pages.

Uses /proc/self/pagemap to discover which code pages are actually
accessed during sign computation, then zeros out everything else.

The result compresses from ~26MB to ~8.4MB with zstd.

Usage:
    python3 create_minimal_wrapper.py wrapper.node [output.node]
"""
import ctypes
import struct
import os
import sys


def discover_accessed_pages(wrapper_path):
    """Call sign function and discover which code pages are accessed."""
    os.chdir(os.path.dirname(wrapper_path) or '.')

    # Build stub library if needed
    stub_path = os.path.join(os.path.dirname(wrapper_path) or '.', 'libsymbols.so')
    if not os.path.exists(stub_path):
        print("Error: libsymbols.so not found. Build it first.")
        sys.exit(1)

    ctypes.CDLL(stub_path, mode=ctypes.RTLD_GLOBAL)
    for lib in ['libgnutls.so.30', 'libssl.so.3', 'libcrypto.so.3']:
        try: ctypes.CDLL(lib, mode=ctypes.RTLD_GLOBAL)
        except: pass

    h = ctypes.CDLL(wrapper_path, mode=1)
    libc = ctypes.CDLL(None)
    base = ctypes.c_ulong(0)
    CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
    @CB
    def cb(info, sz, data):
        addr = ctypes.c_ulong.from_address(info).value
        name_ptr = ctypes.c_void_p.from_address(info + 8).value
        if name_ptr:
            try:
                if 'wrapper' in ctypes.string_at(name_ptr).decode():
                    base.value = addr; return 1
            except: pass
        return 0
    libc.dl_iterate_phdr(cb, None)

    # Find RX segment
    rx_start = rx_end = rx_file_offset = None
    with open('/proc/self/maps') as f:
        for line in f:
            if os.path.basename(wrapper_path) in line and 'r-xp' in line:
                parts = line.split()
                addr_range = parts[0].split('-')
                rx_start = int(addr_range[0], 16)
                rx_end = int(addr_range[1], 16)
                rx_file_offset = int(parts[2], 16)
                break

    if not rx_start:
        print("Error: could not find RX segment")
        return set()

    # Auto-detect sign function offset
    SIGN_OFFSETS = [0x56D81D1, 0x5ADE220, 0x59660D0]
    sign_func = None
    for offset in SIGN_OFFSETS:
        try:
            SIGN = ctypes.CFUNCTYPE(ctypes.c_longlong, ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_int,
                ctypes.POINTER(ctypes.c_ubyte))(base.value + offset)
            src = (ctypes.c_ubyte * 1)(0)
            out = (ctypes.c_ubyte * 0x300)()
            SIGN(b'wtlogin.login', src, 1, 1, out)
            sign_func = SIGN
            break
        except: continue

    if not sign_func:
        print("Error: could not find sign function")
        return set()

    # Call with various inputs to touch all code paths
    test_cases = [
        (b'wtlogin.login', b'\x00'), (b'wtlogin.login', b'\x00' * 64),
        (b'MessageSvc.PbSendMsg', b'\x00'), (b'', b'\x00'),
        (b'wtlogin.login', b''),
    ]
    for cmd, src_bytes in test_cases:
        src = (ctypes.c_ubyte * max(1, len(src_bytes)))(*src_bytes)
        out = (ctypes.c_ubyte * 0x300)()
        try: sign_func(cmd, src, len(src_bytes), 1, out)
        except: pass

    # Read pagemap to find accessed pages
    PAGE = 4096
    accessed = set()
    pagemap_fd = os.open('/proc/self/pagemap', os.O_RDONLY)
    for addr in range(rx_start, rx_end, PAGE):
        offset = (addr // PAGE) * 8
        os.lseek(pagemap_fd, offset, os.SEEK_SET)
        entry = os.read(pagemap_fd, 8)
        if len(entry) == 8:
            val = struct.unpack('<Q', entry)[0]
            if val & (1 << 63):
                file_offset = rx_file_offset + (addr - rx_start)
                accessed.add(file_offset // PAGE)
    os.close(pagemap_fd)

    return accessed


def create_minimal(input_path, output_path, accessed_pages):
    """Zero out unaccessed code pages and non-essential sections."""
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    PAGE = 4096

    # Find .text segment range
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]

    text_start = text_end = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        if p_type == 1 and (p_flags & 1):  # PT_LOAD + PF_X
            text_start = struct.unpack_from('<Q', data, off + 8)[0]
            text_end = text_start + struct.unpack_from('<Q', data, off + 32)[0]
            break

    # Zero unaccessed .text pages
    zeroed = 0
    for page_start in range(text_start & ~(PAGE - 1), text_end, PAGE):
        if page_start // PAGE not in accessed_pages:
            for i in range(page_start, min(page_start + PAGE, text_end, len(data))):
                data[i] = 0
            zeroed += 1

    # Zero .eh_frame and .gcc_except_table (not needed for signing)
    eh_ranges = [(0x63D2B8, 0x9F9000), (0x118AC80, 0x1E65A3C)]
    for start, end in eh_ranges:
        for i in range(start, min(end, len(data))):
            data[i] = 0

    with open(output_path, 'wb') as f:
        f.write(data)

    total_pages = (text_end - text_start) // PAGE
    kept = total_pages - zeroed
    print(f"Zeroed {zeroed}/{total_pages} text pages, kept {kept}")
    return output_path


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <wrapper.node> [output.node]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path.replace('.node', '_minimal.node')

    print(f"Discovering accessed pages from {input_path}...")
    pages = discover_accessed_pages(input_path)
    print(f"Found {len(pages)} accessed code pages")

    print(f"Creating minimal wrapper at {output_path}...")
    create_minimal(input_path, output_path, pages)

    orig_size = os.path.getsize(input_path)
    new_size = os.path.getsize(output_path)
    print(f"Original: {orig_size / 1024 / 1024:.1f} MB")
    print(f"Minimal: {new_size / 1024 / 1024:.1f} MB")
    print(f"\nCompress with: zstd -19 {output_path}")
