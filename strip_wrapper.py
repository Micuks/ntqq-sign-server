#!/usr/bin/env python3
"""
Strip wrapper.node to minimize compressed size.

Zeroes out sections not needed for packet signing:
- .eh_frame (exception handling, ~11 MB)
- .eh_frame_hdr (exception handling index, ~1.8 MB)
- .gcc_except_table (exception tables, ~3.7 MB)

The stripped file is the same size but compresses ~20% smaller.
Use with: zstd -19 wrapper_stripped.node -o wrapper.node.zst

Usage:
    python3 strip_wrapper.py wrapper.node [output]
"""

import sys
import struct


def strip_wrapper(input_path, output_path=None):
    if output_path is None:
        output_path = input_path.replace('.node', '_stripped.node')

    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    # Verify ELF magic
    if data[:4] != b'\x7fELF':
        print("Error: not an ELF file", file=sys.stderr)
        sys.exit(1)

    original_size = len(data)

    # Read section headers
    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]

    if e_shnum == 0 or e_shoff + e_shnum * e_shentsize > len(data):
        # No section headers — use hardcoded offsets for known versions
        # These ranges cover .gcc_except_table + .eh_frame_hdr + .eh_frame
        zero_ranges = [
            (0x63D2B8, 0x9F9000),    # .gcc_except_table
            (0x118AC80, 0x1E65A3C),  # .eh_frame_hdr + .eh_frame
        ]
    else:
        # Read section name string table
        shstr_hdr = e_shoff + e_shstrndx * e_shentsize
        shstr_offset = struct.unpack_from('<Q', data, shstr_hdr + 24)[0]
        shstr_size = struct.unpack_from('<Q', data, shstr_hdr + 32)[0]
        shstrtab = data[shstr_offset:shstr_offset + shstr_size]

        zero_ranges = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_name_idx = struct.unpack_from('<I', data, off)[0]
            sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
            sh_size = struct.unpack_from('<Q', data, off + 32)[0]

            name_end = shstrtab.find(b'\x00', sh_name_idx)
            name = shstrtab[sh_name_idx:name_end].decode('ascii', errors='replace')

            if name in ('.eh_frame', '.eh_frame_hdr', '.gcc_except_table'):
                zero_ranges.append((sh_offset, sh_offset + sh_size))

    zeroed_bytes = 0
    for start, end in zero_ranges:
        end = min(end, len(data))
        for i in range(start, end):
            if data[i] != 0:
                data[i] = 0
                zeroed_bytes += 1

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"Stripped {output_path}: zeroed {zeroed_bytes / 1024 / 1024:.1f} MB of {original_size / 1024 / 1024:.1f} MB")
    print(f"Compress with: zstd -19 {output_path}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <wrapper.node> [output]")
        sys.exit(1)
    output = sys.argv[2] if len(sys.argv) > 2 else None
    strip_wrapper(sys.argv[1], output)
