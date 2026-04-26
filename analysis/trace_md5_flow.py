#!/usr/bin/env python3
"""Trace how MD5(src) bytes flow through the VM and transform into X_b1_init."""
import json, hashlib

MASK = 0xFFFFFFFF
def u32(v): return v & MASK

TRACES = {s: json.load(open(f'/tmp/complete_trace_{s}.json')) for s in ['00','01','02','ff']}

def reconstruct(trace):
    regs = {}
    states = [dict(regs)]
    for entry in trace:
        _, _, _, diff, _ = entry
        for k, v in diff.items():
            regs[int(k)] = u32(v)
        states.append(dict(regs))
    return states

states = {s: reconstruct(TRACES[s]) for s in TRACES}

# Find ALL op 0x32 ib=[50, 8, 5, 6] instances for src=00 and show byte index + byte value
print("=== op 0x32 ib=[50,8,5,6] reads ===")
for s in ['00', '01']:
    print(f"\n--- src={s} ---")
    md5_src = hashlib.md5(bytes([int(s, 16)])).digest()
    print(f"MD5(src) = {md5_src.hex()}")
    byte_reads = []
    for i, entry in enumerate(TRACES[s]):
        step, op, pc, diff, ib = entry
        if op == 0x32 and tuple(ib) == (50, 8, 5, 6):
            r6 = states[s][i].get(6)
            r8 = states[s][i].get(8)
            r5 = states[s][i].get(5)
            written = u32(diff.get('7', -1)) if '7' in diff else None
            md5_byte = md5_src[r6] if r6 is not None and r6 < 16 else None
            byte_reads.append((step, r6, r8, r5, written, md5_byte))
            if len(byte_reads) > 20:
                break
    print(f"{'step':>5} {'r6':>4} {'r8':>8} {'r5':>4} {'r7_wr':>7} {'md5[r6]':>9}")
    for step, r6, r8, r5, w, md5_b in byte_reads[:20]:
        print(f"  {step:5d} {r6:4d} 0x{r8:06x} {r5:4d} {hex(w) if w is not None else '----':>7} {hex(md5_b) if md5_b is not None else '?':>9}")

# How many total reads per src? Should be 16 if reading all MD5 bytes
for s in ['00','01','02','ff']:
    count = sum(1 for e in TRACES[s] if e[1] == 0x32 and tuple(e[4]) == (50, 8, 5, 6))
    print(f"src={s}: {count} reads of op 0x32 ib=[50,8,5,6]")

# Now look at what happens AFTER these reads — the transformation chain
# Find step where r7 contains specific MD5 byte and follow until r7 is used elsewhere
print("\n=== What does op 0x16 ib=[22, 119, 129, 0] do? ===")
# Common ib[1]=119, ib[2]=129: these are memory-related? Let's check r0 at those steps
for i, entry in enumerate(TRACES['00']):
    step, op, pc, diff, ib = entry
    if op == 0x16 and tuple(ib) == (22, 119, 129, 0):
        before = states['00'][i]
        r7 = before.get(7)
        r0 = before.get(0)
        r119 = before.get(119)
        r129 = before.get(129)
        wrote = diff.get('7', -1)
        print(f"  step {step}: r7_before=0x{r7:x} r0=0x{r0:x} r119=0x{r119:x} r129=0x{r129:x} → r7_after=0x{wrote:x} XOR_amt=0x{r7^wrote:x}")
        if step > 2400: break
