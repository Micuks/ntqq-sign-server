#!/usr/bin/env python3
"""Extended automatic opcode formula tester.
Try MANY more candidate formulas, including cipher SBOX / L function /
byte permutation / shift+OR / etc.
"""
import json
import sys
from collections import defaultdict
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_cipher
MASK = 0xFFFFFFFF

names = ['00', '01', '02', 'ff']
traces = {n: json.load(open(f'/tmp/complete_trace_{n}.json')) for n in names}

def reconstruct(trace):
    regs = {}
    states = []
    for entry in trace:
        diff = entry[3]
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        states.append(dict(regs))
    return states

states = {n: reconstruct(t) for n, t in traces.items()}
n_steps = len(traces['00'])


def rotl32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK


def gather_examples(op, ib_pattern):
    examples = []
    for i in range(n_steps):
        e = traces['00'][i]
        if e[1] != op: continue
        if tuple(e[4]) != ib_pattern: continue
        for n in names:
            before = dict(states[n][i-1] if i > 0 else {})
            diff = {int(k): v & MASK for k, v in traces[n][i][3].items()}
            examples.append((before, diff, ib_pattern))
    return examples


def test_formula(examples, formula_fn):
    for before, actual_diff, ib in examples:
        try:
            predicted = formula_fn(before, ib)
        except Exception:
            return False
        if predicted is None:
            return False
        if predicted != actual_diff:
            return False
    return True


# Extended formulas
def f_xor3(d, a, b, c):
    """r[d] = r[a] ^ r[b] ^ r[c]"""
    def fn(before, ib):
        va = before.get(ib[a]); vb = before.get(ib[b]); vc = before.get(ib[c])
        if None in (va, vb, vc): return None
        return {ib[d]: (va ^ vb ^ vc) & MASK}
    return fn

def f_sbox(d, a):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: pure_cipher.sbox_word(va)}
    return fn

def f_L(d, a):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: pure_cipher.L(va)}
    return fn

def f_L_sbox(d, a):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: pure_cipher.L(pure_cipher.sbox_word(va))}
    return fn

def f_xor_imm(d, a, imm_pos):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: (va ^ ib[imm_pos]) & MASK}
    return fn

def f_add_imm(d, a, imm_pos):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: (va + ib[imm_pos]) & MASK}
    return fn

def f_sub_imm(d, a, imm_pos):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: (va - ib[imm_pos]) & MASK}
    return fn

def f_byte_extract(d, a, byte_pos):
    """r[d] = (r[a] >> (byte_pos*8)) & 0xFF"""
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        bp = ib[byte_pos]
        if bp > 3: return None
        return {ib[d]: (va >> (bp * 8)) & 0xFF}
    return fn

def f_byte_insert(d, a, byte_pos):
    """r[d] = (r[d] & ~(0xFF<<(bp*8))) | ((r[a] & 0xFF) << (bp*8))"""
    def fn(before, ib):
        va = before.get(ib[a])
        vd = before.get(ib[d])
        if va is None or vd is None: return None
        bp = ib[byte_pos]
        if bp > 3: return None
        mask = ~(0xFF << (bp*8)) & MASK
        return {ib[d]: ((vd & mask) | ((va & 0xFF) << (bp*8))) & MASK}
    return fn

def f_const_byte(d, byte_pos, byte_val):
    """r[d] = imm_byte"""
    def fn(before, ib):
        return {ib[d]: ib[byte_val] & MASK}
    return fn

def f_low_byte(d, a):
    """r[d] = r[a] & 0xFF"""
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: va & 0xFF}
    return fn

def f_zero(d):
    def fn(before, ib):
        return {ib[d]: 0}
    return fn

def f_const(d, value):
    def fn(before, ib):
        return {ib[d]: value & MASK}
    return fn


# Build formula list
formulas = []
for d in [1, 2, 3]:
    for a in [1, 2, 3]:
        if a == d: continue
        formulas.append((f"r[{d}] = sbox(r[{a}])", f_sbox(d, a)))
        formulas.append((f"r[{d}] = L(r[{a}])", f_L(d, a)))
        formulas.append((f"r[{d}] = L(sbox(r[{a}]))", f_L_sbox(d, a)))
        formulas.append((f"r[{d}] = r[{a}] & 0xFF", f_low_byte(d, a)))
        for ip in [1, 2, 3]:
            if ip in (d, a): continue
            formulas.append((f"r[{d}] = r[{a}] ^ ib[{ip}]", f_xor_imm(d, a, ip)))
            formulas.append((f"r[{d}] = r[{a}] + ib[{ip}]", f_add_imm(d, a, ip)))
            formulas.append((f"r[{d}] = r[{a}] - ib[{ip}]", f_sub_imm(d, a, ip)))
            formulas.append((f"r[{d}].byte[ib[{ip}]] = r[{a}]&0xff", f_byte_insert(d, a, ip)))
            formulas.append((f"r[{d}] = (r[{a}]>>(ib[{ip}]*8))&0xff", f_byte_extract(d, a, ip)))

    for b in [1, 2, 3]:
        if b in (d, a): continue
        for c in [1, 2, 3]:
            if c in (d, a, b): continue
            formulas.append((f"r[{d}] = r[{a}]^r[{b}]^r[{c}]", f_xor3(d, a, b, c)))


# Plus all the simple ones from v1
def f_xor(d, a, b):
    def fn(before, ib):
        va = before.get(ib[a]); vb = before.get(ib[b])
        if va is None or vb is None: return None
        return {ib[d]: (va ^ vb) & MASK}
    return fn

def f_xor_self(d_a, b):
    def fn(before, ib):
        va = before.get(ib[d_a]); vb = before.get(ib[b])
        if va is None or vb is None: return None
        return {ib[d_a]: (va ^ vb) & MASK}
    return fn

def f_mov(d, s):
    def fn(before, ib):
        v = before.get(ib[s])
        if v is None: return None
        return {ib[d]: v & MASK}
    return fn

def f_add(d, a, b):
    def fn(before, ib):
        va = before.get(ib[a]); vb = before.get(ib[b])
        if va is None or vb is None: return None
        return {ib[d]: (va + vb) & MASK}
    return fn

def f_sub(d, a, b):
    def fn(before, ib):
        va = before.get(ib[a]); vb = before.get(ib[b])
        if va is None or vb is None: return None
        return {ib[d]: (va - vb) & MASK}
    return fn

def f_or(d, a, b):
    def fn(before, ib):
        va = before.get(ib[a]); vb = before.get(ib[b])
        if va is None or vb is None: return None
        return {ib[d]: (va | vb) & MASK}
    return fn

def f_and(d, a, b):
    def fn(before, ib):
        va = before.get(ib[a]); vb = before.get(ib[b])
        if va is None or vb is None: return None
        return {ib[d]: (va & vb) & MASK}
    return fn

def f_shl(d, a, sp):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: (va << ib[sp]) & MASK}
    return fn

def f_shr(d, a, sp):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: (va >> ib[sp]) & MASK}
    return fn

def f_rotl_imm(d, a, sp):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: rotl32(va, ib[sp])}
    return fn

def f_neg(d, a):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: (-va) & MASK}
    return fn

def f_not(d, a):
    def fn(before, ib):
        va = before.get(ib[a])
        if va is None: return None
        return {ib[d]: (~va) & MASK}
    return fn


for d in [1, 2, 3]:
    for a in [1, 2, 3]:
        if a == d: continue
        for b in [1, 2, 3]:
            if b in (d, a): continue
            formulas.append((f"r[{d}] = r[{a}] ^ r[{b}]", f_xor(d, a, b)))
            formulas.append((f"r[{d}] = r[{a}] + r[{b}]", f_add(d, a, b)))
            formulas.append((f"r[{d}] = r[{a}] - r[{b}]", f_sub(d, a, b)))
            formulas.append((f"r[{d}] = r[{a}] | r[{b}]", f_or(d, a, b)))
            formulas.append((f"r[{d}] = r[{a}] & r[{b}]", f_and(d, a, b)))
        formulas.append((f"r[{d}] = r[{a}]", f_mov(d, a)))
        formulas.append((f"r[{d}] = -r[{a}]", f_neg(d, a)))
        formulas.append((f"r[{d}] = ~r[{a}]", f_not(d, a)))

for d in [1, 2, 3]:
    for b in [1, 2, 3]:
        if b == d: continue
        formulas.append((f"r[{d}] ^= r[{b}]", f_xor_self(d, b)))


for d in [1, 2, 3]:
    for a in [1, 2, 3]:
        if a == d: continue
        for sp in [1, 2, 3]:
            if sp in (d, a): continue
            formulas.append((f"r[{d}] = r[{a}] << ib[{sp}]", f_shl(d, a, sp)))
            formulas.append((f"r[{d}] = r[{a}] >> ib[{sp}]", f_shr(d, a, sp)))
            formulas.append((f"r[{d}] = rotl(r[{a}], ib[{sp}])", f_rotl_imm(d, a, sp)))


# Collect unique patterns
unique_patterns = set()
for i in range(n_steps):
    e = traces['00'][i]
    unique_patterns.add((e[1], tuple(e[4])))


# Test each pattern
results = {}
for op, ib in sorted(unique_patterns):
    examples = gather_examples(op, ib)
    if not examples: continue
    matched = []
    for label, fn in formulas:
        if test_formula(examples, fn):
            matched.append(label)
    if matched:
        # Pick the simplest (shortest label) match
        matched.sort(key=len)
        results[(op, ib)] = matched

print(f"Total unique (op, ib) patterns: {len(unique_patterns)}")
print(f"Patterns with matching formula: {len(results)}")
print()

# Group by opcode
op_summary = defaultdict(list)
for (op, ib), formulas_matched in results.items():
    op_summary[op].append((ib, formulas_matched[0]))

# Per-opcode stats
op_total = defaultdict(int)
for op, ib in unique_patterns:
    op_total[op] += 1
op_matched = defaultdict(int)
for (op, ib), _ in results.items():
    op_matched[op] += 1

print(f"{'op':>4} {'matched':>8}/{'total':>5} most_common_formula")
for op in sorted(op_total):
    pct = 100*op_matched[op]/op_total[op]
    formulas_for_op = [f for ib, f in op_summary.get(op, [])]
    if formulas_for_op:
        from collections import Counter
        common = Counter(formulas_for_op).most_common(1)[0][0]
    else:
        common = ''
    print(f"{hex(op):>4} {op_matched[op]:>8}/{op_total[op]:>5} {common}")
