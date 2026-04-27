"""Pure-Python VM interpreter for the NTQQ wrapper.node sign function.

Uses empirically learned opcode handlers + per-pattern lookup tables.

Coverage: 346/727 (op, ib) patterns solved as of 2026-04-27.
Remaining 381 patterns need memory-model work.
"""
import json
import hashlib
import os

NREGS = 150
MASK = 0xFFFFFFFF


def rotl32(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & MASK


def rotr32(x, n):
    n = n & 31
    return ((x >> n) | (x << (32 - n))) & MASK


_dir = os.path.dirname(__file__)


def _load_solved():
    """Load all learned formulas/tables into a unified handler dict."""
    handlers = {}
    analysis_dir = os.path.join(_dir, 'analysis')

    def _open(name):
        local = os.path.join(analysis_dir, name)
        if os.path.exists(local):
            return json.load(open(local))
        tmp = '/tmp/' + name
        if os.path.exists(tmp):
            return json.load(open(tmp))
        return None

    # Simple formulas (256 patterns)
    v5 = _open('learned_formulas.json') or _open('learned_v5.json')
    if v5:
        for ib_str, (formula, target) in v5['solved'].items():
            ib = eval(ib_str)
            handlers[ib] = ('formula', formula, target)

    # Table lookups (90 patterns)
    more = _open('learned_tables.json') or _open('more_solved.json')
    if more:
        for ib_str, info in more.items():
            ib = eval(ib_str)
            kind = info[0]
            idx_reg = info[1]
            table = {int(k): v for k, v in info[2].items()}
            handlers[ib] = (kind, idx_reg, table, ib[1])  # target = ib[1]

    # NOP patterns (199 ib-patterns where no register changes)
    nops = _open('nop_patterns.json')
    if nops:
        for ib in nops:
            handlers[tuple(ib)] = ('NOP',)

    # v6 formulas (sign-extension etc., 24 patterns)
    v6 = _open('learned_v6.json')
    if v6:
        for ib_str, (formula, target) in v6.items():
            ib = eval(ib_str)
            if ib not in handlers:
                handlers[ib] = ('formula', formula, target)

    # Byte-insert formulas
    bb = _open('learned_byte.json')
    if bb:
        for ib_str, (formula, target) in bb.items():
            ib = eval(ib_str)
            if ib not in handlers:
                handlers[ib] = ('formula', formula, target)

    # SBOX-shift patterns (5 patterns)
    ss = _open('learned_sbox_shift.json') or _open('sbox_shift.json')
    if ss:
        for ib_str, info in ss.items():
            ib = eval(ib_str)
            if ib in handlers:
                continue
            handlers[ib] = tuple(info)

    # Per-step SBOX formulas (for ib patterns where formula varies by step)
    pss = _open('per_step_sbox.json')
    if pss:
        for ib_str, step_map in pss.items():
            ib = eval(ib_str)
            # Convert step keys to int
            tbl = {int(s): tuple(sol) for s, sol in step_map.items()}
            handlers[ib] = ('PER_STEP_SBOX', tbl)

    # Advanced tables: BYTE_TABLE / ADD_TABLE / XOR_TABLE
    tv3 = _open('learned_tables_v3.json') or _open('tables_v3.json')
    if tv3:
        for ib_str, info in tv3.items():
            ib = eval(ib_str)
            kind = info[0]
            if ib in handlers:
                continue
            if kind == 'BYTE_TABLE':
                target = info[1]
                idx_reg = info[2]
                shift = info[3]
                table = {int(k): v for k, v in info[4].items()}
                handlers[ib] = ('BYTE_TABLE', target, idx_reg, shift, table)
            elif kind == 'ADD_TABLE':
                target = info[1]
                r1 = info[2]
                r2 = info[3]
                table = {int(k): v for k, v in info[4].items()}
                handlers[ib] = ('ADD_TABLE', target, r1, r2, table)
            elif kind == 'XOR_TABLE':
                target = info[1]
                r1 = info[2]
                r2 = info[3]
                table = {int(k): v for k, v in info[4].items()}
                handlers[ib] = ('XOR_TABLE', target, r1, r2, table)

    return handlers


HANDLERS = _load_solved()
print(f"Loaded {len(HANDLERS)} opcode handlers.")


def execute_step(state, ib, step=None):
    """Execute one VM step. Returns True if op was handled, False if unknown.

    `step` is the VM step index (used for per-step opcodes like PER_STEP_SBOX).
    """
    op, b1, b2, b3 = ib
    key = tuple(ib)
    if key not in HANDLERS:
        return False
    handler = HANDLERS[key]
    kind = handler[0]

    if kind == 'PER_STEP_SBOX':
        step_map = handler[1]
        if step is None or step not in step_map:
            return False
        sol = step_map[step]
        sub_kind = sol[0]
        target = sol[1]
        if sub_kind == 'R':
            x = sol[2]
            state[target] = state[x]
            return True
        elif sub_kind == 'XOR2':
            x, y = sol[2], sol[3]
            state[target] = (state[x] ^ state[y]) & MASK
            return True
        elif sub_kind == 'XOR_ACC':
            x = sol[2]
            state[target] = (state[target] ^ state[x]) & MASK
            return True
        elif sub_kind == 'OR_SHIFT':
            x, y, sh = sol[2], sol[3], sol[4]
            state[target] = (state[x] | ((state[y] << sh) & MASK)) & MASK
            return True
        elif sub_kind == 'BYTE_MERGE':
            x, y, sh = sol[2], sol[3], sol[4]
            m = (0xFF << sh) & MASK
            state[target] = ((state[x] & ~m & MASK) | (state[y] & m)) & MASK
            return True
        elif sub_kind == 'ROTL':
            x, n = sol[2], sol[3]
            state[target] = rotl32(state[x], n)
            return True
        elif sub_kind == 'AND_CONST':
            x, c = sol[2], sol[3]
            state[target] = state[x] & c
            return True
        elif sub_kind == 'ADD2':
            x, y = sol[2], sol[3]
            state[target] = (state[x] + state[y]) & MASK
            return True
        elif sub_kind == 'XOR3':
            x, y, z = sol[2], sol[3], sol[4]
            state[target] = (state[x] ^ state[y] ^ state[z]) & MASK
            return True
        # SBOX-related kinds keep idx_reg, sh_in, sh_out structure
        idx_reg, sh_in, sh_out = sol[2], sol[3], sol[4]
        if SBOX is None:
            return False
        idx = (state[idx_reg] >> sh_in) & 0xFF
        if sub_kind == 'SBOX_SHIFT':
            state[target] = (SBOX[idx] << sh_out) & MASK
        elif sub_kind == 'SBOX_BYTE_INSERT':
            bm = ~(0xFF << sh_out) & MASK
            state[target] = ((state[target] & bm) | ((SBOX[idx] & 0xFF) << sh_out)) & MASK
        elif sub_kind == 'SBOX_XOR_INTO':
            state[target] = (state[target] ^ ((SBOX[idx] & 0xFF) << sh_out)) & MASK
        else:
            return False
        return True

    if kind == 'NOP':
        return True
    if kind == 'formula':
        formula, target = handler[1], handler[2]
        # Eval formula
        src_a = state[b2] if b2 < NREGS else 0
        src_b = state[b3] if b3 < NREGS else 0
        try:
            v = eval_formula(formula, state, b1, b2, b3, src_a, src_b, target)
        except Exception:
            return False
        if v is None:
            return False
        state[target] = v & MASK
        return True
    elif kind == 'TABLE_8':
        idx_reg = handler[1]
        table = handler[2]
        target = handler[3]
        idx = state[idx_reg] & 0xFF
        if idx in table:
            state[target] = table[idx]
            return True
        return False
    elif kind == 'TABLE_16':
        idx_reg = handler[1]
        table = handler[2]
        target = handler[3]
        idx = state[idx_reg] & 0xFFFF
        if idx in table:
            state[target] = table[idx]
            return True
        return False
    elif kind == 'SBOX':
        idx_reg = handler[1]
        target = b1
        if SBOX is None:
            return False
        idx = state[idx_reg] & 0xFF
        state[target] = SBOX[idx]
        return True
    elif kind == 'BYTE_TABLE':
        target, idx_reg, shift, table = handler[1], handler[2], handler[3], handler[4]
        idx = (state[idx_reg] >> shift) & 0xFF
        if idx in table:
            state[target] = table[idx]
            return True
        return False
    elif kind == 'ADD_TABLE':
        target, r1, r2, table = handler[1], handler[2], handler[3], handler[4]
        idx = (state[r1] + state[r2]) & 0xFF
        if idx in table:
            state[target] = table[idx]
            return True
        return False
    elif kind == 'XOR_TABLE':
        target, r1, r2, table = handler[1], handler[2], handler[3], handler[4]
        idx = (state[r1] ^ state[r2]) & 0xFF
        if idx in table:
            state[target] = table[idx]
            return True
        return False
    elif kind == 'SBOX_SHIFT':
        target, idx_reg, sh_in, sh_out = handler[1], handler[2], handler[3], handler[4]
        if SBOX is None: return False
        idx = (state[idx_reg] >> sh_in) & 0xFF
        state[target] = (SBOX[idx] << sh_out) & MASK
        return True
    elif kind == 'SBOX_BYTE_INSERT':
        target, idx_reg, sh_in, sh_out = handler[1], handler[2], handler[3], handler[4]
        if SBOX is None: return False
        bm = ~(0xFF << sh_out) & MASK
        idx = (state[idx_reg] >> sh_in) & 0xFF
        state[target] = ((state[target] & bm) | ((SBOX[idx] & 0xFF) << sh_out)) & MASK
        return True
    elif kind == 'SBOX_XOR_INTO':
        target, idx_reg, sh_in, sh_out = handler[1], handler[2], handler[3], handler[4]
        if SBOX is None: return False
        idx = (state[idx_reg] >> sh_in) & 0xFF
        state[target] = (state[target] ^ ((SBOX[idx] & 0xFF) << sh_out)) & MASK
        return True
    return False


def eval_formula(formula, state, b1, b2, b3, src_a, src_b, target=None):
    if target is None:
        target = b1 if b1 < NREGS else None
    if formula == 'target = b3': return b3
    if formula == 'target = b2': return b2
    if formula == 'target = b3 - b2': return (b3 - b2) & MASK
    if formula == 'target = src_a': return src_a
    if formula == 'target = src_a ^ b3': return src_a ^ b3
    if formula == 'target = src_a + b3': return (src_a + b3) & MASK
    if formula == 'target = src_a - b3': return (src_a - b3) & MASK
    if formula == 'target = b3 - src_a': return (b3 - src_a) & MASK
    if formula == 'target = src_a & b3': return src_a & b3
    if formula == 'target = src_a | b3': return src_a | b3
    if formula == 'target = src_a >> b3':
        return (src_a >> b3) & MASK if b3 < 32 else 0
    if formula == 'target = src_a << b3':
        return (src_a << b3) & MASK if b3 < 32 else 0
    if formula == 'target = rotl(src_a, b3)': return rotl32(src_a, b3)
    if formula == 'target = rotr(src_a, b3)': return rotr32(src_a, b3)
    if formula == 'target ^= src_a':
        return state[target] ^ src_a if target is not None else None
    if formula == 'target += src_a':
        return (state[target] + src_a) & MASK if target is not None else None
    if formula == 'target -= src_a':
        return (state[target] - src_a) & MASK if target is not None else None
    if formula == 'target = src_a (low 16)': return src_a & 0xFFFF
    if formula == 'target = src_a (low 8)': return src_a & 0xFF
    if formula == 'target = ~src_a': return (~src_a) & MASK
    if formula == 'target = -src_a': return (-src_a) & MASK
    if formula == 'target = sign_ext_8(src_a)':
        return (((src_a & 0xFF) ^ 0x80) - 0x80) & MASK
    if formula == 'target = sign_ext_16(src_a)':
        return (((src_a & 0xFFFF) ^ 0x8000) - 0x8000) & MASK
    if formula == 'target = sign_ext_8(b3)' and b3 < NREGS:
        return ((state[b3] & 0xFF) ^ 0x80) - 0x80 & MASK
    if formula == 'target = sign_ext_8(b2)' and b2 < NREGS:
        return ((state[b2] & 0xFF) ^ 0x80) - 0x80 & MASK
    if formula == 'target = sign_ext_8(b1)' and b1 < NREGS:
        return ((state[b1] & 0xFF) ^ 0x80) - 0x80 & MASK
    if formula == 'target = sign_ext_8(target)' and target is not None:
        return ((state[target] & 0xFF) ^ 0x80) - 0x80 & MASK
    if formula == 'target = src_a ^ src_b': return src_a ^ src_b
    if formula == 'target = src_a + src_b': return (src_a + src_b) & MASK
    if formula == 'target = src_a - src_b': return (src_a - src_b) & MASK
    if formula == 'target = src_b - src_a': return (src_b - src_a) & MASK
    if formula == 'target = src_a & src_b': return src_a & src_b
    if formula == 'target = src_a | src_b': return src_a | src_b
    if formula == 'target = src_a * src_b': return (src_a * src_b) & MASK
    if formula == 'target = src_a >> src_b':
        return (src_a >> (src_b & 31)) & MASK
    if formula == 'target = src_a << src_b':
        return (src_a << (src_b & 31)) & MASK
    if formula == 'target = rotl(src_a, src_b)': return rotl32(src_a, src_b)
    if formula == 'target = src_a ^ src_b ^ tgt':
        return src_a ^ src_b ^ state[target] if target is not None else None
    return None


# Load SBOX
SBOX = open(os.path.join(_dir, 'custom_sbox.bin'), 'rb').read() if os.path.exists(os.path.join(_dir, 'custom_sbox.bin')) else None


def replay_trace(trace):
    """Walk through a captured trace step by step, applying VM handlers.
    
    Returns: list of (step, status) where status is 'OK', 'MISS', 'WRONG'.
    """
    n = len(trace)
    if not trace[0]: return []
    state = list(trace[0][2])  # initial register state
    results = []
    
    for s in range(n - 1):
        if not trace[s] or not trace[s][1] or not trace[s+1]:
            results.append((s, 'NULL'))
            continue
        ib = tuple(trace[s][1])
        # Save expected next state
        expected = trace[s+1][2]
        
        # Apply handler
        ok = execute_step(state, ib, step=s)
        
        if not ok:
            results.append((s, 'MISS', ib))
            # Recovery: copy expected state to keep going
            state = list(expected)
            continue
        
        # Compare against expected
        wrong_regs = [r for r in range(NREGS) if state[r] != expected[r]]
        if wrong_regs:
            results.append((s, 'WRONG', ib, wrong_regs[:5]))
            state = list(expected)  # recover
        else:
            results.append((s, 'OK'))
    return results


if __name__ == '__main__':
    # Test against trace 0
    print("Loading trace...")
    trace = json.load(open('/tmp/multi_trace_00.json'))
    
    print(f"Replaying {len(trace)} steps...")
    results = replay_trace(trace)
    
    n_ok = sum(1 for r in results if r[1] == 'OK')
    n_miss = sum(1 for r in results if r[1] == 'MISS')
    n_wrong = sum(1 for r in results if r[1] == 'WRONG')
    n_null = sum(1 for r in results if r[1] == 'NULL')
    
    print(f"\n=== Replay results ===")
    print(f"  OK: {n_ok}/{len(results)}")
    print(f"  MISS (no handler): {n_miss}")
    print(f"  WRONG (handler buggy): {n_wrong}")
    print(f"  NULL: {n_null}")
    
    # First 10 misses
    misses = [r for r in results if r[1] == 'MISS']
    print(f"\nFirst 10 misses:")
    from collections import Counter
    miss_ops = Counter(r[2][0] for r in misses)
    for op, cnt in sorted(miss_ops.items(), key=lambda x: -x[1])[:15]:
        print(f"  op 0x{op:02x}: {cnt} misses")
    
    # First 10 wrong
    wrongs = [r for r in results if r[1] == 'WRONG']
    if wrongs:
        print(f"\nFirst 10 wrongs:")
        for r in wrongs[:10]:
            print(f"  step {r[0]} ib={r[2]} wrong regs={r[3]}")
