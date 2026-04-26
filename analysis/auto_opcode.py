#!/usr/bin/env python3
"""For each unique (op, ib) pattern across the 4 traces, automatically test
many candidate formulas. Report which formula fits each pattern.

Formulas tested are over (before_regs, ib) → (changed_regs).
"""
import json
from collections import defaultdict
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
    """For all instances matching (op, ib_pattern) across traces, collect
    (full_before_regs, after_diff) for each trace."""
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


def test_formula(examples, formula_fn, formula_label, ib_pattern):
    """formula_fn takes (before, ib) → expected_diff dict.
    Returns True if all examples match."""
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


# === Common formulas ===

def f_xor(reg_dst, reg_a, reg_b):
    """r[dst] = r[a] ^ r[b]"""
    def fn(before, ib):
        a = before.get(ib[reg_a])
        b = before.get(ib[reg_b])
        if a is None or b is None: return None
        return {ib[reg_dst]: (a ^ b) & MASK}
    return fn


def f_xor_dst_eq_a(reg_dst_a, reg_b):
    """r[dst] ^= r[b]"""
    def fn(before, ib):
        a = before.get(ib[reg_dst_a])
        b = before.get(ib[reg_b])
        if a is None or b is None: return None
        return {ib[reg_dst_a]: (a ^ b) & MASK}
    return fn


def f_add(reg_dst, reg_a, reg_b):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        b = before.get(ib[reg_b])
        if a is None or b is None: return None
        return {ib[reg_dst]: (a + b) & MASK}
    return fn


def f_sub(reg_dst, reg_a, reg_b):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        b = before.get(ib[reg_b])
        if a is None or b is None: return None
        return {ib[reg_dst]: (a - b) & MASK}
    return fn


def f_or(reg_dst, reg_a, reg_b):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        b = before.get(ib[reg_b])
        if a is None or b is None: return None
        return {ib[reg_dst]: (a | b) & MASK}
    return fn


def f_and(reg_dst, reg_a, reg_b):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        b = before.get(ib[reg_b])
        if a is None or b is None: return None
        return {ib[reg_dst]: (a & b) & MASK}
    return fn


def f_mov(reg_dst, reg_src):
    """r[dst] = r[src]"""
    def fn(before, ib):
        s = before.get(ib[reg_src])
        if s is None: return None
        return {ib[reg_dst]: s & MASK}
    return fn


def f_imm(reg_dst, imm_pos):
    """r[dst] = ib[imm_pos]"""
    def fn(before, ib):
        return {ib[reg_dst]: ib[imm_pos] & MASK}
    return fn


def f_shl(reg_dst, reg_a, shift_pos):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        if a is None: return None
        return {ib[reg_dst]: (a << ib[shift_pos]) & MASK}
    return fn


def f_shr(reg_dst, reg_a, shift_pos):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        if a is None: return None
        return {ib[reg_dst]: (a >> ib[shift_pos]) & MASK}
    return fn


def f_rotl_imm(reg_dst, reg_a, shift_pos):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        if a is None: return None
        return {ib[reg_dst]: rotl32(a, ib[shift_pos])}
    return fn


def f_neg(reg_dst, reg_a):
    """r[dst] = -r[a]"""
    def fn(before, ib):
        a = before.get(ib[reg_a])
        if a is None: return None
        return {ib[reg_dst]: (-a) & MASK}
    return fn


def f_not(reg_dst, reg_a):
    def fn(before, ib):
        a = before.get(ib[reg_a])
        if a is None: return None
        return {ib[reg_dst]: (~a) & MASK}
    return fn


def f_low_byte_or(reg_dst, reg_a, byte_pos):
    """r[dst] = (r[dst] & ~0xFF) | (r[ib[reg_a]] & 0xFF) — but with byte_pos shift"""
    def fn(before, ib):
        a = before.get(ib[reg_a])
        d = before.get(ib[reg_dst])
        if a is None or d is None: return None
        pos = ib[byte_pos]
        if pos > 3: return None
        # set byte at position pos in d to low byte of a
        mask = ~(0xFF << (pos*8)) & MASK
        result = (d & mask) | ((a & 0xFF) << (pos*8))
        return {ib[reg_dst]: result & MASK}
    return fn


# Many formula candidates; key = label
formula_candidates = []

# Try all permutations of operand positions (1, 2, 3)
for dst in [1, 2, 3]:
    for a in [1, 2, 3]:
        if a == dst: continue
        for b in [1, 2, 3]:
            if b in (dst, a): continue
            formula_candidates.append((f"r[{dst}] = r[{a}] ^ r[{b}]", f_xor(dst, a, b)))
            formula_candidates.append((f"r[{dst}] = r[{a}] + r[{b}]", f_add(dst, a, b)))
            formula_candidates.append((f"r[{dst}] = r[{a}] - r[{b}]", f_sub(dst, a, b)))
            formula_candidates.append((f"r[{dst}] = r[{a}] | r[{b}]", f_or(dst, a, b)))
            formula_candidates.append((f"r[{dst}] = r[{a}] & r[{b}]", f_and(dst, a, b)))
        formula_candidates.append((f"r[{dst}] = r[{a}]", f_mov(dst, a)))
        formula_candidates.append((f"r[{dst}] = -r[{a}]", f_neg(dst, a)))
        formula_candidates.append((f"r[{dst}] = ~r[{a}]", f_not(dst, a)))

# Self-modifying (r[dst] ^= r[other])
for dst in [1, 2, 3]:
    for b in [1, 2, 3]:
        if b == dst: continue
        formula_candidates.append((f"r[{dst}] ^= r[{b}]", f_xor_dst_eq_a(dst, b)))

# Shifts where ib[shift_pos] is immediate (0..31)
for dst in [1, 2, 3]:
    for a in [1, 2, 3]:
        if a == dst: continue
        for sp in [1, 2, 3]:
            if sp in (dst, a): continue
            formula_candidates.append((f"r[{dst}] = r[{a}] << ib[{sp}]", f_shl(dst, a, sp)))
            formula_candidates.append((f"r[{dst}] = r[{a}] >> ib[{sp}]", f_shr(dst, a, sp)))
            formula_candidates.append((f"r[{dst}] = rotl(r[{a}], ib[{sp}])", f_rotl_imm(dst, a, sp)))


# Collect all unique (op, ib) patterns
unique_patterns = set()
for i in range(n_steps):
    e = traces['00'][i]
    unique_patterns.add((e[1], tuple(e[4])))

print(f"Total unique (op, ib) patterns: {len(unique_patterns)}")

# For each pattern, find matching formula
results = {}
for op, ib in sorted(unique_patterns):
    examples = gather_examples(op, ib)
    if not examples: continue
    matched = []
    for label, fn in formula_candidates:
        if test_formula(examples, fn, label, ib):
            matched.append(label)
    if matched:
        results[(op, ib)] = matched

# Group results by opcode
op_summary = defaultdict(list)
for (op, ib), formulas in results.items():
    op_summary[op].append((ib, formulas))

print(f"\n=== Patterns with matching formulas ({len(results)}/{len(unique_patterns)}) ===\n")
for op in sorted(op_summary):
    print(f"\n--- op {hex(op)} ---")
    for ib, formulas in sorted(op_summary[op]):
        print(f"  ib={list(ib)}: {formulas[0]}{'  (+%d others)' % (len(formulas)-1) if len(formulas)>1 else ''}")

print(f"\n=== Patterns without matching formula ===\n")
no_match = [(op, ib) for op, ib in sorted(unique_patterns) if (op, ib) not in results]
for op, ib in no_match[:30]:
    print(f"  op={hex(op)} ib={list(ib)}")
print(f"... total {len(no_match)}")
