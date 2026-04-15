#!/usr/bin/env python3
"""
Pure NTQQ Sign Extraction — extracts sign bytes from execution traces.

Algorithm:
1. From the bytecode VM execution trace, read table (B2=0x0B, B3=1)
2. Sign bytes at indices 0-15: use FIRST 0x32 read value
3. Sign bytes at indices 16-31: use LAST 0x32 read value
4. Result: 32-byte sign = table[0..31]

This module provides sign extraction from pre-captured traces.
For a complete sign server, pair with the dlopen oracle for trace capture.
"""

import json
import hashlib
from collections import defaultdict


def extract_sign_from_trace(trace_data):
    """Extract 32-byte sign from a bytecode execution trace.

    Args:
        trace_data: list of [dispatch_num, opcode, pc, diff_dict, instr_bytes]

    Returns:
        bytes: 32-byte sign
    """
    # Collect all 0x32 reads from table (B2=0x0B, B3=1)
    table_reads = defaultdict(list)  # index → [(step, value)]

    regs = {}
    for i in range(len(trace_data)):
        step = trace_data[i]
        # Update register state from diff
        for k_str, v in step[3].items():
            regs[int(k_str)] = v

        # Check if this is a 0x32 read from table (0x0B, 1)
        if i + 1 < len(trace_data) and step[1] == 0x32:
            ib = step[4]
            if len(ib) >= 4:
                b1, b2, b3 = ib[1], ib[2], ib[3]
                if b2 == 0x0B and b3 == 1:
                    idx = regs.get(b1, 0) & 0xFF
                    next_diff = trace_data[i + 1][3]
                    if str(b1) in next_diff:
                        val = next_diff[str(b1)] & 0xFF
                        table_reads[idx].append((i, val))

    # Build sign: first read for 0-15, last read for 16-31
    sign = bytearray(32)
    for idx in range(32):
        reads = table_reads.get(idx, [])
        if reads:
            if idx < 16:
                sign[idx] = reads[0][1]   # First read
            else:
                sign[idx] = reads[-1][1]  # Last read

    return bytes(sign)


def sign(cmd: str, src: bytes, seq: int = 1) -> tuple:
    """
    Compute NTQQ packet sign.

    Currently requires a pre-captured trace file.

    Returns:
        (sign_bytes, extra_bytes, token_bytes)
    """
    md5_hash = hashlib.md5(src).hexdigest()
    trace_path = f'/tmp/trace_{md5_hash[:8]}.json'

    try:
        with open(trace_path) as f:
            trace = json.load(f)
        sign_bytes = extract_sign_from_trace(trace)
        return sign_bytes, b"", b""
    except FileNotFoundError:
        raise RuntimeError(
            f"No trace for MD5={md5_hash}. "
            f"Capture with: LD_PRELOAD=libfaketime_zero.so python3 frida_complete_capture.py"
        )


if __name__ == '__main__':
    # Test with captured traces
    import os

    for src_hex, trace_file, expected in [
        ('00', '/tmp/complete_trace_00.json', 'e957228ae560df16aaded8b75d19773f2e8cb6c5be0e43d970bb0b02956d3c57'),
        ('01', '/tmp/complete_trace_01.json', 'cda19e727f863f5d697e1f2e3a8efb31150cf78cc9cbbac3a90ee07c919fe901'),
    ]:
        if os.path.exists(trace_file):
            with open(trace_file) as f:
                trace = json.load(f)
            result = extract_sign_from_trace(trace)
            match = result.hex() == expected
            print(f"src={src_hex}: {result.hex()} {'✓' if match else '✗'}")
        else:
            print(f"src={src_hex}: trace not found")
