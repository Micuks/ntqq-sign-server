"""Test: run pure_vm_v2 from a HARDCODED initial state (captured from trace 0
for cmd='wtlogin.login') WITHOUT using PER_STEP_OUTPUT_TRACE0.

If this produces the correct sign for the captured src=0x00, we're 95% there.
The src-dependent gap must be filled by injecting src bytes into the right regs.
"""
import json, sys, os
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')

from pure_vm_v2 import RegBank, execute_step, NREGS, MASK, PER_STEP_OUTPUT
import pure_cipher

X_B1_INIT_0_CONST = 0x114D0B11
X_B1_STEP = 7150
X_B2_NONCE_STEP = 12000

def run_for_trace(trace_path, expected_sig_hex):
    trace = json.load(open(trace_path))
    # Use trace[0][2] as initial state. That's cmd='wtlogin.login' src=0x00 fresh-process state.
    initial_lo = list(trace[0][2])
    initial_hi = list(trace[0][3]) if trace[0][3] else [0] * NREGS

    state = RegBank(initial_lo, initial_hi)

    # Run pure_vm_v2 WITHOUT applying PER_STEP_OUTPUT_TRACE0.
    # Apply only PER_STEP_OUTPUT (cross-trace, src-independent).
    end_step = X_B2_NONCE_STEP + 50
    end_step = min(end_step, len(trace) - 1)

    div_steps = []
    for s in range(end_step):
        if not trace[s] or not trace[s + 1]: continue
        ib_raw = trace[s][1]
        expected_lo = trace[s + 1][2]
        if not expected_lo: continue
        if ib_raw:
            execute_step(state, tuple(ib_raw), step=s)
        else:
            # Boundary step — apply PER_STEP_OUTPUT only
            if s in PER_STEP_OUTPUT:
                for r, lo, hi in PER_STEP_OUTPUT[s]:
                    state._lo[r] = lo & MASK
                    state._hi[r] = hi & MASK

        # Count divergence WITHOUT correcting (so it compounds)
        if state._lo[151] != expected_lo[151] or state._lo[152] != expected_lo[152] or state._lo[153] != expected_lo[153]:
            if not div_steps:
                div_steps.append(('FIRST_X_B1_DIVERGE', s, ib_raw))
            elif len(div_steps) < 5:
                div_steps.append((s, ib_raw))

    # Read X_b1_init and X_b2[1]
    x_b1 = [X_B1_INIT_0_CONST, state._lo[151], state._lo[152], state._lo[153]]
    x_b2_1 = state._lo[95]

    # Compare with expected (from trace itself)
    exp_x_b1 = [X_B1_INIT_0_CONST, trace[X_B1_STEP][2][151], trace[X_B1_STEP][2][152], trace[X_B1_STEP][2][153]]
    exp_x_b2_1 = trace[X_B2_NONCE_STEP][2][95]

    print(f"After running pure VM (no TRACE0 snapping):")
    print(f"  X_b1[1..3] computed:    {[hex(v) for v in x_b1[1:]]}")
    print(f"  X_b1[1..3] expected:    {[hex(v) for v in exp_x_b1[1:]]}")
    print(f"  X_b2[1] computed: 0x{x_b2_1:x}, expected: 0x{exp_x_b2_1:x}")
    print(f"  Divergence first observed: {div_steps[:3] if div_steps else 'NONE'}")

    sig = pure_cipher.compute_sign_from_block1_and_nonce(x_b1, x_b2_1, ctr=100)
    expected_sig = bytes.fromhex(expected_sig_hex)
    print(f"\n  Trace: {trace_path}")
    print(f"  Computed sign: {sig.hex()}")
    print(f"  Expected sign: {expected_sig.hex()}")
    ok = sig == expected_sig
    print(f"  {'PASS' if ok else 'FAIL'}")
    return ok

if __name__ == '__main__':
    # Run for all 4 captured traces
    expected = {
        '/tmp/multi_u64_00.json': 'e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f',
    }
    # multi_ext also has src 0..15 traces — verify pure VM on those too
    # Note: multi_ext format is different (per-VM-step samples, not full trace)
    pass_ct = 0; fail_ct = 0
    for path, exp_hex in expected.items():
        if run_for_trace(path, exp_hex): pass_ct += 1
        else: fail_ct += 1
    print(f"\nResults: {pass_ct} PASS, {fail_ct} FAIL")
