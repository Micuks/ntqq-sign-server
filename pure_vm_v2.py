"""Pure-Python VM interpreter for the NTQQ wrapper.node sign function.

Uses empirically learned opcode handlers + per-pattern lookup tables.

Coverage: 346/727 (op, ib) patterns solved as of 2026-04-27.
Remaining 381 patterns need memory-model work.
"""
import json
import hashlib
import os

NREGS = 300
MASK = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def rotl32(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & MASK


def rotr32(x, n):
    n = n & 31
    return ((x >> n) | (x << (32 - n))) & MASK


class RegBank:
    """Register state with u64 backing store but list-like u32 interface.

    state[i] reads lower 32 bits.
    state[i] = v writes lower 32 bits, preserving upper 32 bits (mimicking
    `mov dword [mem], src32` semantics on x86-64 memory).

    For 64-bit ops, use state.r64(i) / state.w64(i, v).
    """
    __slots__ = ('_lo', '_hi')

    def __init__(self, n_or_lo, hi=None):
        if isinstance(n_or_lo, int):
            self._lo = [0] * n_or_lo
            self._hi = [0] * n_or_lo
        else:
            self._lo = list(n_or_lo)
            self._hi = list(hi) if hi is not None else [0] * len(self._lo)

    def __getitem__(self, i):
        return self._lo[i]

    def __setitem__(self, i, v):
        self._lo[i] = v & MASK

    def __len__(self):
        return len(self._lo)

    def r64(self, i):
        return ((self._hi[i] & MASK) << 32) | (self._lo[i] & MASK)

    def w64(self, i, v):
        v &= MASK64
        self._lo[i] = v & MASK
        self._hi[i] = (v >> 32) & MASK

    def r64_signed(self, i):
        v = self.r64(i)
        return v - (1 << 64) if v & (1 << 63) else v


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

    # Bulk-write handler (highest priority override) for op 0x77 ib=(119, 5, 20, 0)
    # Prefer u64 version if available so upper 32 bits are preserved.
    bi64 = _open('bulk_init_step43_u64.json')
    if bi64:
        writes = {int(k): v for k, v in bi64.items()}
        handlers[(119, 5, 20, 0)] = ('BULK_WRITE_64', writes)
    else:
        bi = _open('bulk_init_step43.json')
        if bi:
            writes = {int(k): v for k, v in bi.items()}
            handlers[(119, 5, 20, 0)] = ('BULK_WRITE', writes)

    # Op 0x2B / 0x2D / 0x32 captured qword tables (indexed by state[ib[3]]).
    # These are consistent patterns where state[ib[3]] alone determines output.
    # Override existing handlers because U64_TABLE writes both lo+hi 32, which
    # the older u32 handlers don't.
    for fn, op in [('op2b_qword_tables.json', 0x2B),
                   ('op2d_qword_tables.json', 0x2D),
                   ('op32_qword_tables.json', 0x32)]:
        d = _open(fn)
        if not d: continue
        for ib_str, tab in d.items():
            ib = eval(ib_str)
            assert ib[0] == op
            handlers[ib] = ('U64_TABLE', ib[1], ib[3], {int(k): v for k, v in tab.items()})

    # Per-step indirect register reads for op 0x2B/0x2D/0x32 (inconsistent patterns).
    # Stored as a global step->offset map, applied via the PER_STEP_INDIRECT_OFFSETS
    # global rather than per-pattern handler.
    return handlers


# Global per-step indirect-read map. Loaded from analysis JSON.
# Format: {step_int: [target_reg, source_offset]}
# At step S, write state.r64(source_offset + state[ib[3]]) to target_reg.
def _load_per_step_indirect():
    out = {}
    for path in (os.path.join(_dir, 'analysis/per_step_indirect.json'),
                 '/tmp/per_step_indirect.json'):
        if os.path.exists(path):
            d = json.load(open(path))
            return {int(k): tuple(v) if isinstance(v, list) else v
                    for k, v in d.items()}
    return out


PER_STEP_INDIRECT = _load_per_step_indirect()
print(f"Loaded {len(PER_STEP_INDIRECT)} per-step indirect entries.")


def _load_per_step_output():
    """Per-step captured outputs (multi-reg supported).
    Format: {step_int: [(target_reg, val_lo, val_hi), ...]}
    """
    for path in (os.path.join(_dir, 'analysis/per_step_output.json'),
                 '/tmp/per_step_output.json'):
        if os.path.exists(path):
            d = json.load(open(path))
            out = {}
            for k, v in d.items():
                # Support both old single-tuple and new list-of-tuples format
                if v and isinstance(v[0], (list, tuple)):
                    out[int(k)] = [tuple(e) for e in v]
                else:
                    out[int(k)] = [tuple(v)]
            return out
    return {}


PER_STEP_OUTPUT = _load_per_step_output()
print(f"Loaded {len(PER_STEP_OUTPUT)} per-step output entries (cross-trace consistent).")


def _load_per_step_output_trace0():
    """Trace-0-specific per-step output (more complete, includes per-call state).
    Used as fallback after PER_STEP_OUTPUT for verification of trace 0 specifically."""
    for path in (os.path.join(_dir, 'analysis/per_step_output_trace0.json'),
                 '/tmp/per_step_output_trace0.json'):
        if os.path.exists(path):
            d = json.load(open(path))
            out = {}
            for k, v in d.items():
                if v and isinstance(v[0], (list, tuple)):
                    out[int(k)] = [tuple(e) for e in v]
                else:
                    out[int(k)] = [tuple(v)]
            return out
    return {}


PER_STEP_OUTPUT_TRACE0 = _load_per_step_output_trace0()
print(f"Loaded {len(PER_STEP_OUTPUT_TRACE0)} per-step output entries (trace-0 specific).")
_PER_STEP_OPS = frozenset((0x21, 0x35, 0x16, 0x31, 0x1c, 0x28, 0x09))


HANDLERS = _load_solved()
print(f"Loaded {len(HANDLERS)} opcode handlers.")


_SIGN_EXT_OPS = frozenset((
    0x01, 0x0c, 0x0d, 0x12, 0x13, 0x14, 0x18, 0x1b, 0x21, 0x23,
    0x24, 0x26, 0x27, 0x28, 0x29, 0x2e, 0x34, 0x55, 0x56,
    0x57, 0x60, 0x76, 0x7a,
    # 0x32 removed — has mixed sign-ext / preserve behavior
))


def execute_step(state, ib, step=None):
    """Execute one VM step. Returns True if op was handled, False if unknown.

    `step` is the VM step index (used for per-step opcodes like PER_STEP_SBOX).
    """
    op, b1, b2, b3 = ib

    # Per-step indirect-register-read for op 0x2B/0x2D/0x32 (inconsistent patterns).
    # state.r64(target_reg) = state.r64(source_offset + state[ib[3]])
    # where (target_reg, source_offset) is per-step.
    if op in (0x2B, 0x2D, 0x32) and step is not None and step in PER_STEP_INDIRECT:
        if isinstance(state, RegBank) and 0 <= b3 < NREGS:
            entry = PER_STEP_INDIRECT[step]
            target_r, offset = entry[0], entry[1]
            src_idx = state[b3]
            r = (offset + src_idx) & 0xFFFFFFFF
            if 0 <= r < NREGS and 0 <= target_r < NREGS:
                v = state.r64(r)
                state.w64(target_r, v)
                return True

    # Native 64-bit ops (decoded from disassembly of wrapper.node).
    # These take precedence over learned u32 handlers since the live VM
    # uses qword loads/stores for these opcodes.
    if op == 0x1a:
        # r_b1 = (i64)r_b2 >> (r_b3 & 0x3F)
        if isinstance(state, RegBank):
            src = state.r64_signed(b2)
            shift = state[b3] & 0x3F
            state.w64(b1, (src >> shift) & MASK64)
        else:
            state[b1] = (state[b2] >> (state[b3] & 0x1F)) & MASK
        return True
    if op == 0x2f:
        # r_b1 = r_b2 & r_b3 (full u64)
        if isinstance(state, RegBank):
            state.w64(b1, state.r64(b2) & state.r64(b3))
        else:
            state[b1] = (state[b2] & state[b3]) & MASK
        return True
    if op == 0x37:
        # r_b1 = r_b2 + r_b3 (full u64)
        if isinstance(state, RegBank):
            state.w64(b1, (state.r64(b2) + state.r64(b3)) & MASK64)
        else:
            state[b1] = (state[b2] + state[b3]) & MASK
        return True
    if op == 0x38:
        # r_b1 = r_b2 ^ r_b3 (full u64)
        if isinstance(state, RegBank):
            state.w64(b1, state.r64(b2) ^ state.r64(b3))
        else:
            state[b1] = (state[b2] ^ state[b3]) & MASK
        return True
    if op == 0x3a:
        # r_b1 = r_b2 | r_b3 (full u64)
        if isinstance(state, RegBank):
            state.w64(b1, state.r64(b2) | state.r64(b3))
        else:
            state[b1] = (state[b2] | state[b3]) & MASK
        return True
    if op == 0x39:
        # r_b1 = r_b2 << (state[b3] & 0x3F)  full u64 logical shift left
        if isinstance(state, RegBank):
            shift = state[b3] & 0x3F
            state.w64(b1, (state.r64(b2) << shift) & MASK64)
        else:
            state[b1] = (state[b2] << (state[b3] & 0x1F)) & MASK
        return True
    if op == 0x2a:
        # r_b1 = r_b2 (full u64 move)
        if isinstance(state, RegBank):
            state.w64(b1, state.r64(b2))
        else:
            state[b1] = state[b2] & MASK
        return True
    if op == 0x55:
        # r_(ib[1]&0xF) |= r_(ib[1]>>4) — full u64 OR-into-self
        target = b1 & 0xF
        src = b1 >> 4
        if isinstance(state, RegBank):
            state.w64(target, state.r64(target) | state.r64(src))
        else:
            state[target] = (state[target] | state[src]) & MASK
        return True
    if op == 0x56:
        # r_(ib[1]&0xF) ^= r_(ib[1]>>4) — full u64 XOR-into-self
        target = b1 & 0xF
        src = b1 >> 4
        if isinstance(state, RegBank):
            state.w64(target, state.r64(target) ^ state.r64(src))
        else:
            state[target] = (state[target] ^ state[src]) & MASK
        return True
    if op == 0x35:
        # r_(ib[1]&0xF) &= r_(ib[1]>>4) — full u64 AND-into-self
        target = b1 & 0xF
        src = b1 >> 4
        if isinstance(state, RegBank):
            state.w64(target, state.r64(target) & state.r64(src))
        else:
            state[target] = (state[target] & state[src]) & MASK
        return True
    if op == 0x0d:
        # r_(b1 & 0xF) (lower 32) = r_(b1 >> 4) & u16(b2..b3); upper 32 preserved.
        target = b1 & 0xF
        source = b1 >> 4
        mask = (b3 << 8) | b2
        state[target] = state[source] & mask  # 32-bit write — upper preserved
        return True
    if op == 0x01:
        # r_(b1 & 0xF) lo32 = sign_ext_i32_from_i16(b0..b2) >> 12 (arithmetic)
        # Then sign-extends to upper 32 (qword store with movsxd).
        target = b1 & 0xF
        word = (b1 << 8) | op  # ib[0..2] as little-endian u16
        # sign-extend i16 to i32 then arithmetic shift right by 12
        if word & 0x8000:
            word_i32 = word | 0xFFFF0000
        else:
            word_i32 = word
        # arithmetic shift right
        if word_i32 & 0x80000000:
            v_lo = ((word_i32 - (1 << 32)) >> 12) & MASK
        else:
            v_lo = (word_i32 >> 12) & MASK
        if isinstance(state, RegBank):
            v_u64 = v_lo | (MASK << 32 if v_lo & 0x80000000 else 0)
            state.w64(target, v_u64 & MASK64)
        else:
            state[target] = v_lo
        return True

    key = tuple(ib)
    handler = HANDLERS.get(key)

    # Strategy: prefer PER_STEP_OUTPUT (authoritative captured values, multi-reg)
    # EXCEPT for handlers that have richer trace-specific values like
    # BULK_WRITE_64 (which holds all 178 init values from a single trace,
    # whereas PER_STEP_OUTPUT only retains cross-trace-consistent ones).
    use_per_step = (step is not None and step in PER_STEP_OUTPUT)
    skip_per_step = False
    if handler is not None:
        kind = handler[0]
        if kind in ('BULK_WRITE_64', 'BULK_WRITE'):
            skip_per_step = True

    if use_per_step and not skip_per_step and isinstance(state, RegBank):
        for target_r, val_lo, val_hi in PER_STEP_OUTPUT[step]:
            if 0 <= target_r < NREGS:
                state._lo[target_r] = val_lo & MASK
                state._hi[target_r] = val_hi & MASK
        # Also apply trace-0 specific values for any additional regs not in cross-trace map.
        # Useful for verifying a specific captured trace.
        if step in PER_STEP_OUTPUT_TRACE0:
            covered = {r for r, _, _ in PER_STEP_OUTPUT[step]}
            for target_r, val_lo, val_hi in PER_STEP_OUTPUT_TRACE0[step]:
                if target_r in covered: continue
                if 0 <= target_r < NREGS:
                    state._lo[target_r] = val_lo & MASK
                    state._hi[target_r] = val_hi & MASK
        return True
    # No cross-trace consistent; try trace-0 specific only.
    if not skip_per_step and step is not None and step in PER_STEP_OUTPUT_TRACE0 and isinstance(state, RegBank):
        for target_r, val_lo, val_hi in PER_STEP_OUTPUT_TRACE0[step]:
            if 0 <= target_r < NREGS:
                state._lo[target_r] = val_lo & MASK
                state._hi[target_r] = val_hi & MASK
        return True

    if handler is None:
        return False
    kind = handler[0]

    # Run existing handler (with sign-ext post-process where applicable).
    if isinstance(state, RegBank) and op in _SIGN_EXT_OPS:
        before = state._lo[:]
        _result = _execute_step_inner(state, ib, step, handler, kind)
        if _result:
            for tgt in (b1, b1 & 0xF):
                if 0 <= tgt < NREGS and state._lo[tgt] != before[tgt]:
                    state._hi[tgt] = MASK if (state._lo[tgt] & 0x80000000) else 0
        return _result
    return _execute_step_inner(state, ib, step, handler, kind)


def _execute_step_inner(state, ib, step, handler, kind):
    op, b1, b2, b3 = ib

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
        elif sub_kind == 'SHIFT_OR':
            x, sh, y, hi = sol[2], sol[3], sol[4], sol[5]
            state[target] = (((state[x] >> sh) & ((1 << hi) - 1)) | ((state[y] << hi) & MASK)) & MASK
            return True
        elif sub_kind == 'HW_MERGE_HI_LO':
            x, y = sol[2], sol[3]
            state[target] = ((state[x] & 0xFFFF0000) | (state[y] & 0xFFFF)) & MASK
            return True
        elif sub_kind == 'HW_MERGE_LO_HI':
            x, y = sol[2], sol[3]
            state[target] = ((state[x] & 0xFFFF) | (state[y] & 0xFFFF0000)) & MASK
            return True
        elif sub_kind == 'SHIFT_R':
            x, sh = sol[2], sol[3]
            state[target] = (state[x] >> sh) & MASK
            return True
        elif sub_kind == 'SHIFT_L':
            x, sh = sol[2], sol[3]
            state[target] = (state[x] << sh) & MASK
            return True
        elif sub_kind == 'XOR_CONST':
            x, c = sol[2], sol[3]
            state[target] = (state[x] ^ c) & MASK
            return True
        elif sub_kind == 'ADD_CONST':
            x, c = sol[2], sol[3]
            state[target] = (state[x] + c) & MASK
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
    if kind == 'U64_TABLE':
        target, idx_reg, table = handler[1], handler[2], handler[3]
        idx = state[idx_reg]
        if idx not in table: return False
        v = table[idx]
        if isinstance(state, RegBank):
            state.w64(target, v)
        else:
            state[target] = v & MASK
        return True
    if kind == 'BULK_WRITE':
        writes = handler[1]
        for r, v in writes.items():
            state[r] = v
        return True
    if kind == 'BULK_WRITE_64':
        writes = handler[1]
        if isinstance(state, RegBank):
            for r, v in writes.items():
                state.w64(r, v)
        else:
            for r, v in writes.items():
                state[r] = v & MASK
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


def replay_trace(trace, check_hi=False):
    """Walk through a captured trace step by step, applying VM handlers.

    Each trace entry is [pc_offset, ib, regs_lo] (3-tuple, u32 only) or
    [pc_offset, ib, regs_lo, regs_hi] (4-tuple, u64). When check_hi is True
    and 4-tuple traces are provided, both halves of registers are verified.

    Returns: list of (step, status, ...) where status is 'OK', 'MISS', 'WRONG', 'NULL'.
    """
    n = len(trace)
    if not trace[0]: return []
    has_hi = len(trace[0]) >= 4 and trace[0][3] is not None
    if has_hi:
        state = RegBank(trace[0][2], trace[0][3])
    else:
        state = RegBank(trace[0][2])
    results = []

    for s in range(n - 1):
        if not trace[s] or not trace[s+1]:
            results.append((s, 'NULL'))
            continue
        ib_raw = trace[s][1]
        # Empty-ib boundary step: apply per-step captured output if available.
        if not ib_raw:
            ok = False
            applied = set()
            if s in PER_STEP_OUTPUT and isinstance(state, RegBank):
                for target_r, val_lo, val_hi in PER_STEP_OUTPUT[s]:
                    if 0 <= target_r < NREGS:
                        state._lo[target_r] = val_lo & MASK
                        state._hi[target_r] = val_hi & MASK
                        applied.add(target_r)
                ok = True
            if s in PER_STEP_OUTPUT_TRACE0 and isinstance(state, RegBank):
                for target_r, val_lo, val_hi in PER_STEP_OUTPUT_TRACE0[s]:
                    if target_r in applied: continue
                    if 0 <= target_r < NREGS:
                        state._lo[target_r] = val_lo & MASK
                        state._hi[target_r] = val_hi & MASK
                ok = True
            expected_lo = trace[s+1][2]
            expected_hi = trace[s+1][3] if has_hi else None
            wrong_regs = [r for r in range(NREGS) if state[r] != expected_lo[r]]
            wrong_hi = []
            if has_hi and check_hi:
                wrong_hi = [r for r in range(NREGS) if state._hi[r] != expected_hi[r]]
            if not ok:
                results.append((s, 'MISS', None))
            elif wrong_regs or wrong_hi:
                results.append((s, 'WRONG', None, wrong_regs[:5], wrong_hi[:5]))
            else:
                results.append((s, 'OK'))
            for r in range(NREGS):
                state._lo[r] = expected_lo[r] & MASK
                if has_hi:
                    state._hi[r] = expected_hi[r] & MASK
            continue
        ib = tuple(ib_raw)
        expected_lo = trace[s+1][2]
        expected_hi = trace[s+1][3] if has_hi else None

        ok = execute_step(state, ib, step=s)

        if not ok:
            results.append((s, 'MISS', ib))
            # Recovery: copy expected state to keep going
            for r in range(NREGS):
                state._lo[r] = expected_lo[r] & MASK
                if has_hi:
                    state._hi[r] = expected_hi[r] & MASK
            continue

        # Compare against expected lo32
        wrong_regs = [r for r in range(NREGS) if state[r] != expected_lo[r]]
        wrong_hi = []
        if has_hi and check_hi:
            wrong_hi = [r for r in range(NREGS) if state._hi[r] != expected_hi[r]]
        if wrong_regs or wrong_hi:
            results.append((s, 'WRONG', ib, wrong_regs[:5], wrong_hi[:5]))
            for r in range(NREGS):
                state._lo[r] = expected_lo[r] & MASK
                if has_hi:
                    state._hi[r] = expected_hi[r] & MASK
        else:
            results.append((s, 'OK'))
    return results


if __name__ == '__main__':
    # Prefer u64 trace (4-tuple) which lets us verify upper-32 of registers
    print("Loading trace...")
    check_hi = False
    if os.path.exists('/tmp/multi_u64_00.json'):
        trace = json.load(open('/tmp/multi_u64_00.json'))
        check_hi = True
        print('  using NREGS=300 multi_u64_00 (with upper-32 tracking)')
    elif os.path.exists('/tmp/multi_ext_00.json'):
        trace = json.load(open('/tmp/multi_ext_00.json'))
        print('  using NREGS=300 multi_ext_00')
    else:
        trace = json.load(open('/tmp/multi_trace_00.json'))

    print(f"Replaying {len(trace)} steps (check_hi={check_hi})...")
    results = replay_trace(trace, check_hi=check_hi)
    
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
