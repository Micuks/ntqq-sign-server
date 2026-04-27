"""Aggressive formula search for byte-manipulation opcodes (0x01, 0x29, 0x2b, etc.)."""
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

# Load existing solved
v5 = json.load(open('/tmp/learned_v5.json'))
already = set(eval(k) for k in v5['solved'])
more = json.load(open('/tmp/more_solved.json'))
already.update(eval(k) for k in more)
nops = json.load(open('/tmp/nop_patterns.json'))
already.update(tuple(ib) for ib in nops)

# Get unsolved
by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

unsolved = [(ib, steps) for ib, steps in by_ib.items() if ib not in already]
print(f"Unsolved: {len(unsolved)}")

# For each unsolved, find target reg + try byte-insert formulas
solved_byte = {}

for ib, steps in unsolved:
    op, b1, b2, b3 = ib
    
    # Find target reg
    obs = []
    target_changes = defaultdict(list)
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    target_changes[r].append((before, after))
            obs.append((before, after))
    
    if not target_changes: continue
    target = max(target_changes, key=lambda r: len(target_changes[r]))
    
    obs_t = [(b, a, a[target]) for b, a in obs if b[target] != a[target] or len(target_changes[target]) == len(obs)]
    if not obs_t: continue
    
    src_a = b2 if b2 < NREGS else None
    src_b = b3 if b3 < NREGS else None
    
    # Test formulas
    def test(fn):
        for b, a, t in obs_t:
            try:
                v = fn(b, a) & MASK
                if v != t: return False
            except: return False
        return True
    
    formulas = []
    # Byte-insert at various positions
    if src_a is not None:
        for bp in range(4):  # byte position 0..3
            shift = bp * 8
            mask = ~(0xFF << shift) & MASK
            # target = (target & mask) | ((src_a & 0xFF) << shift)
            formulas.append(
                (f'byte_insert(tgt, src_a, pos={bp})',
                 lambda b, a, sa=src_a, m=mask, sh=shift, tg=target: (b[tg] & m) | ((b[sa] & 0xFF) << sh))
            )
            # target = (target & ~mask) | (src_a & 0xFF<<shift)
            formulas.append(
                (f'byte_insert(tgt, src_a >> ?, pos={bp})',
                 lambda b, a, sa=src_a, m=mask, sh=shift, tg=target: (b[tg] & m) | (b[sa] & (0xFF << sh)))
            )
            # target = (target | (src_a & 0xFF) << shift)
            formulas.append(
                (f'byte_or(tgt, src_a<<{shift})',
                 lambda b, a, sa=src_a, sh=shift, tg=target: b[tg] | ((b[sa] & 0xFF) << sh))
            )
        # XOR shifted
        for sh in range(0, 25, 8):
            formulas.append(
                (f'tgt ^ (src_a<<{sh})',
                 lambda b, a, sa=src_a, sh=sh, tg=target: b[tg] ^ ((b[sa]) << sh) & MASK)
            )
            formulas.append(
                (f'tgt | (src_a<<{sh})',
                 lambda b, a, sa=src_a, sh=sh, tg=target: b[tg] | ((b[sa]) << sh) & MASK)
            )
    if src_a is not None and src_b is not None:
        # target = src_a + (src_b << shift)
        for sh in [0, 8, 16, 24]:
            formulas.append(
                (f'src_a + (src_b<<{sh})',
                 lambda b, a, sa=src_a, sb=src_b, sh=sh: (b[sa] + ((b[sb] << sh) & MASK)) & MASK)
            )
        # target = src_a XOR (src_b << shift)  
        for sh in [0, 8, 16, 24]:
            formulas.append(
                (f'src_a ^ (src_b<<{sh})',
                 lambda b, a, sa=src_a, sb=src_b, sh=sh: b[sa] ^ ((b[sb] << sh) & MASK))
            )
        # target = (src_a >> shift) op src_b
        for sh in range(0, 25, 8):
            formulas.append(
                (f'(src_a>>{sh}) ^ src_b',
                 lambda b, a, sa=src_a, sb=src_b, sh=sh: (b[sa] >> sh) ^ b[sb])
            )
        # rotl(src_a, src_b)
        formulas.append(
            ('rotl(src_a, src_b & 31)',
             lambda b, a, sa=src_a, sb=src_b: rotl32(b[sa], b[sb] & 31))
        )
        # Multi-input: src_a ^ src_b ^ tgt
        formulas.append(
            ('tgt ^ src_a ^ src_b',
             lambda b, a, sa=src_a, sb=src_b, tg=target: b[tg] ^ b[sa] ^ b[sb])
        )
    # b3-byte-insert: (target & ~mask) | b3
    if b3 < 256:
        for bp in range(4):
            shift = bp * 8
            mask = ~(0xFF << shift) & MASK
            formulas.append(
                (f'byte_insert(tgt, b3, pos={bp})',
                 lambda b, a, m=mask, sh=shift, b3=b3, tg=target: (b[tg] & m) | (b3 << sh))
            )
    
    found = None
    for name, fn in formulas:
        if test(fn):
            found = name
            break
    
    if found:
        solved_byte[ib] = (found, target)

print(f"\nByte-formulas solved: {len(solved_byte)}")
from collections import Counter
op_solve = Counter(ib[0] for ib in solved_byte)
for op, cnt in sorted(op_solve.items(), key=lambda x: -x[1])[:20]:
    print(f"  op 0x{op:02x}: {cnt}")

# Save
saved = {}
for ib, (formula, target) in solved_byte.items():
    saved[str(ib)] = [formula, target]
json.dump(saved, open('/tmp/byte_solved.json','w'))
print(f"\nSaved /tmp/byte_solved.json")
