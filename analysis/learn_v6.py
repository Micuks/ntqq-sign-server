"""Add more formula candidates: target = b3, signature_ext on different operands."""
import json
from collections import defaultdict

NREGS = 150
MASK = 0xFFFFFFFF

print("Loading 16 traces...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))
n_steps = len(traces[0])

def rotl32(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & MASK

def sign_ext_8(x):
    return ((x & 0xFF) ^ 0x80) - 0x80 & MASK

# Build groups
by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

# Load existing
v5 = json.load(open('/tmp/learned_v5.json'))
already = set(eval(k) for k in v5['solved'])
more = json.load(open('/tmp/more_solved.json'))
already.update(eval(k) for k in more)
nops = json.load(open('/tmp/nop_patterns.json'))
already.update(tuple(ib) for ib in nops)
print(f"Already solved: {len(already)}")

# For unsolved, find target and try advanced formulas
new_solved = {}
for ib, steps in by_ib.items():
    if ib in already: continue
    op, b1, b2, b3 = ib
    
    # Find changed registers
    target_changes = defaultdict(list)
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    target_changes[r].append((before, after))
    if not target_changes: continue
    target = max(target_changes, key=lambda r: len(target_changes[r]))
    
    obs = []
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            obs.append((before, after))
    
    # Test formulas
    def test(fn):
        for b, a in obs:
            try:
                v = fn(b, a) & MASK
                if v != a[target]: return False
            except: return False
        return True
    
    src_a = b2 if b2 < NREGS else None
    src_b = b3 if b3 < NREGS else None
    
    formulas = []
    # Sign extend on b3 register
    if b3 < NREGS:
        formulas.append(('target = sign_ext_8(b3)', lambda b, a, b3=b3: sign_ext_8(b[b3])))
        formulas.append(('target = sign_ext_8(target)', lambda b, a, tg=target: sign_ext_8(b[tg])))
    if b2 < NREGS:
        formulas.append(('target = sign_ext_8(b2)', lambda b, a, b2=b2: sign_ext_8(b[b2])))
    # b1 register operations
    if b1 < NREGS and b1 != target:
        formulas.append(('target = sign_ext_8(b1)', lambda b, a, b1=b1: sign_ext_8(b[b1])))
        formulas.append(('target = b1', lambda b, a, b1=b1: b[b1]))
        formulas.append(('target = b1 ^ b2', lambda b, a, b1=b1, b2=b2: b[b1] ^ (b[b2] if b2 < NREGS else b2)))
    # In-place ops
    if src_a is not None:
        formulas.append(('target ^= b3', lambda b, a, sa=src_a, b3=b3, tg=target: b[tg] ^ b3))
        formulas.append(('target |= src_a', lambda b, a, sa=src_a, tg=target: b[tg] | b[sa]))
        formulas.append(('target &= src_a', lambda b, a, sa=src_a, tg=target: b[tg] & b[sa]))
    # Bit-field operations
    if src_a is not None:
        for bp in range(4):
            sh = bp * 8
            mask_in = 0xFF << sh
            mask_out = (~mask_in) & MASK
            formulas.append((f'tgt = (src_a>>{sh}) & 0xFF', lambda b, a, sa=src_a, sh=sh: (b[sa] >> sh) & 0xFF))
            formulas.append((f'tgt = (src_a & {hex(mask_in)})', lambda b, a, sa=src_a, m=mask_in: b[sa] & m))
    # Combine src_a and tgt for byte insert
    if src_a is not None:
        for bp in range(4):
            sh = bp * 8
            mask_in = 0xFF << sh
            mask_out = (~mask_in) & MASK
            formulas.append(
                (f'byte_insert from src_a low byte at pos {bp}',
                 lambda b, a, sa=src_a, sh=sh, m=mask_out, tg=target: (b[tg] & m) | ((b[sa] & 0xFF) << sh))
            )
            formulas.append(
                (f'byte_insert from src_a byte at same pos {bp}',
                 lambda b, a, sa=src_a, sh=sh, m=mask_out, mi=mask_in, tg=target: (b[tg] & m) | (b[sa] & mi))
            )
    # b3 as constant byte to insert
    if b3 < 256 and target is not None:
        for bp in range(4):
            sh = bp * 8
            m = (~(0xFF << sh)) & MASK
            formulas.append(
                (f'tgt[byte{bp}] = b3',
                 lambda b, a, m=m, sh=sh, b3=b3, tg=target: (b[tg] & m) | (b3 << sh))
            )
    # b2 as constant byte to insert
    if b2 < 256:
        for bp in range(4):
            sh = bp * 8
            m = (~(0xFF << sh)) & MASK
            formulas.append(
                (f'tgt[byte{bp}] = b2',
                 lambda b, a, m=m, sh=sh, b2=b2, tg=target: (b[tg] & m) | (b2 << sh))
            )

    found = None
    for name, fn in formulas:
        if test(fn):
            found = (name, target)
            break
    
    if found:
        new_solved[ib] = found

print(f"Newly solved: {len(new_solved)}")
from collections import Counter
op_solve = Counter(ib[0] for ib in new_solved)
for op, cnt in sorted(op_solve.items(), key=lambda x: -x[1])[:15]:
    print(f"  op 0x{op:02x}: {cnt}")

# Save
saved = {}
for ib, (formula, target) in new_solved.items():
    saved[str(ib)] = [formula, target]
json.dump(saved, open('/tmp/v6_solved.json','w'))
print(f"\nSaved /tmp/v6_solved.json")
