"""Pure-Python interpreter for the NTQQ wrapper.node VM.

The VM runs a fixed bytecode (same across QQ versions, just at different memory
offsets). Each step has:
  - opcode (op): 1 byte
  - ib (instruction bytes): 4 bytes at PC, ib[0] == op, ib[1..3] are operands
  - register file: 150 u32 entries

Strategy:
  - The (op, ib) sequence is identical across all inputs (verified on 4 traces).
  - We hardcode the sequence (~16,186 steps).
  - For each step, we apply an opcode handler that reads/writes registers.
  - Memory operations (cipher SBOX lookups etc.) are modeled with constant
    tables.

This is a work in progress: opcodes are implemented incrementally.
"""

import json
import os

MASK = 0xFFFFFFFF
NREGS = 150


# Load the bytecode (op, ib) sequence + the input-independent register diffs
# from the OLD trace (used as ground truth oracle for validation).
_TRACE_PATH = "/tmp/complete_trace_00.json"

_op_handlers = {}


def opcode(op_byte):
    """Decorator to register an opcode handler."""
    def deco(fn):
        _op_handlers[op_byte] = fn
        return fn
    return deco


# ---- Opcode handlers ----
# Each handler takes (regs: list[int], ib: list[int]) and modifies regs in place.
# Returns nothing.

@opcode(0x38)
def op_38(regs, ib):
    """ib=[56, dst, a, b]: regs[dst] = regs[a] ^ regs[b].

    Hypothesis from project memory: op 0x13 ib=[19,44,6,31] is r42 ^= r38 (XOR).
    Op 0x38 is similar — extracted from cipher rounds.

    Actually, learn from data: across 4 traces, find pattern.
    For now, leave as TBD and let validator catch.
    """
    raise NotImplementedError("op 0x38")


# ---- Register state reconstruction ----

def reconstruct_states(trace):
    """Given a trace, return list of register states (one per step)."""
    regs = {}
    states = [dict(regs)]  # state before step 0 = empty
    for entry in trace:
        diff = entry[3]
        for k, v in diff.items():
            regs[int(k)] = v & MASK
        states.append(dict(regs))
    return states


# ---- Trace replay validator ----

def replay_trace(trace, opcode_handlers, initial_state=None, stop_at=None):
    """Replay the trace, applying opcode handlers. Validate against the trace's
    expected after-state. Returns list of mismatches.

    For unimplemented opcodes, fall back to applying the trace's diff directly.
    """
    if initial_state is None:
        initial_state = {}
    regs = dict(initial_state)
    mismatches = []
    n_implemented = 0
    n_replayed = 0

    for i, entry in enumerate(trace):
        if stop_at is not None and i >= stop_at:
            break
        step, op, pc, diff, ib = entry
        # Save before state
        before = dict(regs)
        # Try to apply opcode
        if op in opcode_handlers:
            try:
                opcode_handlers[op](regs, ib)
                n_implemented += 1
            except NotImplementedError:
                # Fall back to replay
                for k, v in diff.items():
                    regs[int(k)] = v & MASK
                n_replayed += 1
                continue
            # Check produced output matches expected
            expected_after = dict(before)
            for k, v in diff.items():
                expected_after[int(k)] = v & MASK
            for k, v in regs.items():
                if expected_after.get(k) != v:
                    mismatches.append((i, op, ib, k, expected_after.get(k), v))
        else:
            # No handler; replay trace
            for k, v in diff.items():
                regs[int(k)] = v & MASK
            n_replayed += 1

    return regs, mismatches, n_implemented, n_replayed


def main():
    trace = json.load(open(_TRACE_PATH))
    print(f"Loaded trace: {len(trace)} steps")
    initial = {}  # all regs start at 0
    final, mismatches, n_impl, n_rep = replay_trace(trace, _op_handlers, initial)
    print(f"Implemented: {n_impl}/{n_impl + n_rep}, Replayed: {n_rep}, Mismatches: {len(mismatches)}")
    if mismatches:
        for m in mismatches[:10]:
            i, op, ib, k, exp, got = m
            print(f"  step {i} op={op:#x} ib={ib} reg[{k}]: expected 0x{exp:08x} got 0x{got:08x}")


if __name__ == "__main__":
    main()
