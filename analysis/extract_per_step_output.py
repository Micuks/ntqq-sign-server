"""For ops where the output is hard to derive (op 0x21, 0x35), capture the
output per-step from the u64 trace.

Saves analysis/per_step_output.json: {step_str: [target_reg, lo, hi]}.

Replay: at step S where op is 0x21/0x35/etc., write captured value to target_reg.
"""
import json
import os
from collections import Counter, defaultdict

OUTPATH = os.path.join(os.path.dirname(__file__), 'per_step_output.json')

def find_per_step(trace):
    """For EVERY step (including empty-ib boundary steps), return a dict of
    {reg: (val_lo, val_hi)} of changed regs. Caller takes intersection across traces."""
    by_step = {}
    for s in range(len(trace) - 1):
        if not trace[s] or not trace[s+1]: continue
        before_lo = trace[s][2]; before_hi = trace[s][3]
        after_lo = trace[s+1][2]; after_hi = trace[s+1][3]
        changes = {}
        for r in range(300):
            if before_lo[r] != after_lo[r] or before_hi[r] != after_hi[r]:
                changes[r] = (after_lo[r], after_hi[r])
        if changes:
            by_step[s] = changes
    return by_step


def main():
    # For each step, take the INTERSECTION across the FIRST 3 traces (cross-trace
    # consistent values), but supplement from trace 0 where missing — gives us the
    # complete trace 0 picture for inputs that vary slightly across calls.
    per_trace = []
    for ti in range(4):
        path = f'/tmp/multi_u64_{ti:02x}.json'
        try:
            trace = json.load(open(path))
        except FileNotFoundError:
            continue
        per_trace.append(find_per_step(trace))

    if not per_trace: return
    common = set(per_trace[0].keys())
    for t in per_trace[1:]:
        common &= set(t.keys())

    # For each step, find regs whose (val_lo, val_hi) is identical across traces
    combined = {}
    for s in common:
        # Get common reg keys
        common_regs = set(per_trace[0][s].keys())
        for t in per_trace[1:]:
            common_regs &= set(t[s].keys())
        # For each common reg, check if values match
        for r in common_regs:
            vals = {t[s][r] for t in per_trace}
            if len(vals) == 1:
                combined.setdefault(s, []).append((r, *next(iter(vals))))

    # Allow multi-reg outputs: store list of (reg, lo, hi) per step
    final = {}
    for s, entries in combined.items():
        if entries:
            final[s] = entries

    out = {str(s): [list(e) for e in v] for s, v in final.items()}
    json.dump(out, open(OUTPATH, 'w'))
    print(f"Saved {OUTPATH} with {len(out)} per-step output entries (consistent across all traces)")
    multi = sum(1 for v in final.values() if len(v) > 1)
    print(f"  Multi-target steps: {multi}")

    # Also save trace-0-specific per-step output (full picture for that trace)
    trace0_out = {}
    if per_trace:
        t0 = per_trace[0]
        for s, changes in t0.items():
            trace0_out[str(s)] = [[r, lo, hi] for r, (lo, hi) in changes.items()]
    trace0_path = OUTPATH.replace('.json', '_trace0.json')
    json.dump(trace0_out, open(trace0_path, 'w'))
    print(f"Saved {trace0_path} with {len(trace0_out)} trace-0-specific entries")
    op_cnt = Counter()
    for ti in range(1):
        path = f'/tmp/multi_u64_{ti:02x}.json'
        try: trace = json.load(open(path))
        except: continue
        for s in combined:
            if s < len(trace) and trace[s][1]:
                op_cnt[trace[s][1][0]] += 1
    print(f"By op: {dict(op_cnt.most_common())}")


if __name__ == '__main__':
    main()
