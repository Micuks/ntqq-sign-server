#!/usr/bin/env python3
"""At step 6900 (just before X_b1 build window), find which registers carry
input-dependent data across the 4 traces. These are the data inputs to the X_b1 build."""
import json, hashlib
MASK = 0xFFFFFFFF

XOR_STREAM = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

def reconstruct_at(trace, step):
    regs = {}
    for i in range(step + 1):
        diff = trace[i][3]
        for k, v in diff.items():
            regs[int(k)] = v & MASK
    return regs

# State at step 6900 for each trace
states = {}
for name in ['00','01','02','ff']:
    trace = json.load(open(f'/tmp/complete_trace_{name}.json'))
    states[name] = reconstruct_at(trace, 6900)

# Find registers that VARY across traces
all_regs = set()
for st in states.values():
    all_regs.update(st.keys())

varying = []
constant = []
for r in sorted(all_regs):
    vals = [states[n].get(r, 0) for n in ['00','01','02','ff']]
    if len(set(vals)) > 1:
        varying.append((r, vals))
    else:
        constant.append((r, vals[0]))

print(f"At step 6900: {len(varying)} varying registers, {len(constant)} constant")
print(f"\nVarying registers (the input-dependent state):")
print(f"{'reg':>4} {'00':>10} {'01':>10} {'02':>10} {'ff':>10}")
for r, vals in varying:
    print(f"{r:>4} {vals[0]:>10x} {vals[1]:>10x} {vals[2]:>10x} {vals[3]:>10x}")

# Now check: is each varying register a simple function of MD5(src)?
# Compute MD5(src) and post-XOR for each src, see if any byte/word matches
print("\n=== MD5 / post-XOR for each src ===")
for name in ['00','01','02','ff']:
    src = bytes.fromhex(name)
    md5 = hashlib.md5(src).digest()
    post = bytes(a^b for a, b in zip(md5, XOR_STREAM[:16]))
    print(f"  src={name}: MD5={md5.hex()}  post={post.hex()}")

# Check varying registers against MD5/post bytes
print("\n=== For each varying reg, is the byte present in MD5 or post-XOR? ===")
md5s = {n: hashlib.md5(bytes.fromhex(n)).digest() for n in ['00','01','02','ff']}
posts = {n: bytes(a^b for a,b in zip(md5s[n], XOR_STREAM[:16])) for n in ['00','01','02','ff']}
posts20 = {n: bytes(a^b for a,b in zip(md5s[n], XOR_STREAM[:16])) + XOR_STREAM[16:20] for n in ['00','01','02','ff']}

for r, vals in varying:
    # Take low byte across traces
    bytes_low = [v & 0xFF for v in vals]
    # Is this low byte at a fixed position in MD5 or post-XOR for each trace?
    consistent_md5 = []
    consistent_post = []
    for pos in range(16):
        if all(md5s[n][pos] == (vals[i] & 0xFF) for i, n in enumerate(['00','01','02','ff'])):
            consistent_md5.append(pos)
        if all(posts[n][pos] == (vals[i] & 0xFF) for i, n in enumerate(['00','01','02','ff'])):
            consistent_post.append(pos)
    for pos in range(20):
        if all(posts20[n][pos] == (vals[i] & 0xFF) for i, n in enumerate(['00','01','02','ff'])):
            if pos not in consistent_post:
                consistent_post.append(pos)
    if consistent_md5 or consistent_post:
        print(f"  reg[{r}] low byte: MD5 positions {consistent_md5}, post-XOR positions {consistent_post}")
