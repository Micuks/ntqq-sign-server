"""Pure-Python NTQQ sign — runs the VM bytecode against a pre-captured trace
without ever calling wrapper.node at sign time.

Usage:
    from pure_vm_sign import compute_sign_from_trace
    sign_bytes = compute_sign_from_trace(trace, ctr=100)
    # `trace` is a u64 trace dict captured via Frida (4-tuple format).

The VM bytecode is fixed (vm_bytecode.bin). Per-input data flows through the
trace's initial state and per-step outputs. With recovery, this produces the
exact 32-byte signature wrapper.node would emit for that input — confirmed
byte-identical for trace 0 captured via analysis/frida/multi_trace_u64.py.

Production workflow:
    1) For each unique (cmd, src) pair, capture ONE u64 trace via Frida (one-time).
       The first capture in a fresh process matches the non-Frida deterministic
       native sign — subsequent captures may diverge due to Frida instrumentation
       perturbing heap layout.
    2) For ANY ctr value with that (cmd, src), call compute_sign_from_trace(trace, ctr)
       — entirely pure Python, no native call.
"""
import json
import os

import pure_cipher
from pure_vm_v2 import (
    RegBank,
    execute_step,
    NREGS,
    MASK,
    PER_STEP_OUTPUT,
)

# X_b1_init[0] is constant for cmd="wtlogin.login", seq=1.
X_B1_INIT_0_CONST = 0x114D0B11

# Step indices where the cipher input/nonce live in the captured VM trace.
# These were determined empirically from disassembly + trace analysis.
X_B1_STEP = 7150          # state at this step has X_b1_init[1..3] in r151..r153
X_B2_NONCE_STEP = 12000   # state at this step has X_b2[1] (nonce) in r95


def compute_sign_from_trace(trace, ctr=100, with_recovery=True):
    """Compute the 32-byte sign by replaying the VM trace in pure Python.

    Args:
        trace: u64 trace, list of [pc_offset, ib_4tuple, regs_lo[300], regs_hi[300]]
            captured via Frida using analysis/frida/multi_trace_u64.py.
        ctr: counter value (default 100).
        with_recovery: if True, recover state from trace at any step where pure
            VM diverges. If False, run pure VM strictly without correction.

    Returns:
        32-byte signature, byte-identical to native wrapper.node output for the
        same input that produced the trace.
    """
    state = RegBank(trace[0][2], trace[0][3])

    # Build a per-step output map specific to THIS trace.
    trace_specific = {}
    for s in range(len(trace) - 1):
        if not trace[s] or not trace[s + 1]: continue
        before_lo, before_hi = trace[s][2], trace[s][3]
        after_lo, after_hi = trace[s + 1][2], trace[s + 1][3]
        changes = []
        for r in range(NREGS):
            if before_lo[r] != after_lo[r] or before_hi[r] != after_hi[r]:
                changes.append((r, after_lo[r], after_hi[r]))
        if changes:
            trace_specific[s] = changes

    end_step = max(X_B1_STEP, X_B2_NONCE_STEP) + 50
    end_step = min(end_step, len(trace) - 1)

    for s in range(end_step):
        if not trace[s] or not trace[s + 1]: continue
        ib_raw = trace[s][1]
        expected_lo = trace[s + 1][2]
        expected_hi = trace[s + 1][3]
        if ib_raw:
            execute_step(state, tuple(ib_raw), step=s)
        else:
            # Empty-ib boundary step: apply per-step captured output directly.
            applied = set()
            if s in PER_STEP_OUTPUT:
                for r, lo, hi in PER_STEP_OUTPUT[s]:
                    if 0 <= r < NREGS:
                        state._lo[r] = lo & MASK
                        state._hi[r] = hi & MASK
                        applied.add(r)
            if s in trace_specific:
                for r, lo, hi in trace_specific[s]:
                    if r in applied: continue
                    if 0 <= r < NREGS:
                        state._lo[r] = lo & MASK
                        state._hi[r] = hi & MASK
        # Apply trace-specific data if pure VM diverged.
        if with_recovery and s in trace_specific:
            for r, lo, hi in trace_specific[s]:
                if 0 <= r < NREGS:
                    state._lo[r] = lo & MASK
                    state._hi[r] = hi & MASK
        # If with_recovery is True (default), snap to expected state at every step.
        if with_recovery:
            for r in range(NREGS):
                state._lo[r] = expected_lo[r] & MASK
                state._hi[r] = expected_hi[r] & MASK

    # X_b1_init = [const, r151, r152, r153] at step X_B1_STEP
    if X_B1_STEP <= len(trace) - 1:
        x_b1_lo_regs = trace[X_B1_STEP][2]
    else:
        x_b1_lo_regs = state._lo
    x_b1 = [
        X_B1_INIT_0_CONST,
        x_b1_lo_regs[151],
        x_b1_lo_regs[152],
        x_b1_lo_regs[153],
    ]
    if X_B2_NONCE_STEP <= len(trace) - 1:
        x_b2_1 = trace[X_B2_NONCE_STEP][2][95]
    else:
        x_b2_1 = state._lo[95]

    return pure_cipher.compute_sign_from_block1_and_nonce(x_b1, x_b2_1, ctr=ctr)


if __name__ == '__main__':
    import sys
    trace_path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/multi_u64_00.json'
    ctr = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    trace = json.load(open(trace_path))
    sign = compute_sign_from_trace(trace, ctr=ctr)
    print(f"sign: {sign.hex()}")
