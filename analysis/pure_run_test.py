"""Run VM purely, checkpoint at step 7148 to verify X_b1_init values reach r151..r153."""
import json
import sys
NREGS = 300
MASK = 0xFFFFFFFF

sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_vm_v2

trace = json.load(open('/tmp/multi_ext_00.json'))
initial_state = list(trace[0][2])

state = list(initial_state)
n = len(trace)

# Pure execution; record state at key checkpoints
checkpoints = {44, 109, 110, 2236, 2516, 7148, 7150}
recorded = {}

n_miss = 0
n_wrong = 0
first_critical_diverge = None

# What regs are CRITICAL (must match)? Skip pointer-bearing regs.
# Let's track only data regs we care about: r0..r10, r150-r299
data_regs = list(range(11)) + list(range(150, 300))

def critical_diff(state, expected):
    return [r for r in data_regs if state[r] != expected[r]]

for s in range(n - 1):
    if not trace[s] or not trace[s][1]: continue
    ib = tuple(trace[s][1])
    expected_after = trace[s+1][2]

    success = pure_vm_v2.execute_step(state, ib, step=s)
    if not success:
        n_miss += 1
    else:
        diff = [r for r in range(NREGS) if state[r] != expected_after[r]]
        if diff:
            n_wrong += 1
            cdiff = critical_diff(state, expected_after)
            if cdiff and first_critical_diverge is None:
                first_critical_diverge = (s, ib, cdiff[:5])

    if (s+1) in checkpoints:
        recorded[s+1] = list(state)

# Print results
print(f"miss={n_miss}, wrong={n_wrong}")
print(f"first critical diverge: {first_critical_diverge}")

# Compare key checkpoints
for cp in sorted(checkpoints):
    if cp in recorded:
        actual = recorded[cp]
        expected = trace[cp][2]
        # Check critical regs only
        cdiff = [r for r in data_regs if actual[r] != expected[r]]
        print(f"\n=== Checkpoint step {cp} ===")
        print(f"  critical diff regs: {len(cdiff)}")
        for r in cdiff[:5]:
            print(f"    r{r}: actual=0x{actual[r]:08x}, expected=0x{expected[r]:08x}")

# Final check: r151..r153 at step 7148
if 7148 in recorded:
    state_7148 = recorded[7148]
    print(f"\n=== r151..r153 at step 7148 (X_b1_init[1..3] check) ===")
    expected_xb1 = [trace[7148][2][r] for r in [151, 152, 153]]
    actual_xb1 = [state_7148[r] for r in [151, 152, 153]]
    print(f"  expected: {[hex(v) for v in expected_xb1]}")
    print(f"  actual:   {[hex(v) for v in actual_xb1]}")
    print(f"  match: {actual_xb1 == expected_xb1}")
