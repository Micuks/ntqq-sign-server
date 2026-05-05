"""For each op 0x2B / 0x2D / 0x32 step, find offset such that
   r_target = state.r64(offset + state[ib[3]]).

Saves /analysis/per_step_indirect.json: {step_str: offset}.

Replay handler: at step S, look up offset, compute target = state.r64(offset + state[ib[3]]).
"""
import json
import os
from collections import Counter

OUTPATH = os.path.join(os.path.dirname(__file__), 'per_step_indirect.json')


def find_per_step(trace, op):
    """For each step running op, find:
       - which register actually CHANGED at this step (real target)
       - which OTHER register's pre-state value matches the new target value
       - encode this as (target_reg, source_offset) where source = source_offset + state[ib[3]]
    """
    by_step = {}
    for s in range(len(trace) - 1):
        ib = trace[s][1]
        if not ib or ib[0] != op: continue
        idx_reg = ib[3]
        if idx_reg >= 300: continue
        # Find the register that actually changed
        before_lo = trace[s][2]; before_hi = trace[s][3]
        after_lo = trace[s+1][2]; after_hi = trace[s+1][3]
        changes = [(r, (after_hi[r] << 32) | after_lo[r]) for r in range(300)
                   if before_lo[r] != after_lo[r] or before_hi[r] != after_hi[r]]
        if not changes: continue  # no change (NOP)
        if len(changes) > 1: continue  # multi-write, skip
        target_r, target_v = changes[0]

        src_idx = before_lo[idx_reg]
        for off in range(-300, 300):
            r = off + src_idx
            if 0 <= r < 300:
                pred = (before_hi[r] << 32) | before_lo[r]
                if pred == target_v:
                    by_step[s] = (target_r, off)
                    break
    return by_step


def main():
    combined = {}
    for ti in range(4):
        path = f'/tmp/multi_u64_{ti:02x}.json'
        try:
            trace = json.load(open(path))
        except FileNotFoundError:
            continue
        for op in (0x2B, 0x2D, 0x32):
            by_step = find_per_step(trace, op)
            for s, val in by_step.items():
                if s in combined:
                    if combined[s] != val:
                        # Inconsistent across traces — drop
                        continue
                else:
                    combined[s] = val

    # Format: {step: [target_reg, source_offset]} - JSON-friendly
    out = {str(s): list(v) for s, v in combined.items()}
    json.dump(out, open(OUTPATH, 'w'))
    print(f"Saved {OUTPATH} with {len(out)} per-step indirect entries")
    off_cnt = Counter(v[1] for v in combined.values())
    tgt_cnt = Counter(v[0] for v in combined.values())
    print(f"Source offset distribution (top 15): {dict(off_cnt.most_common(15))}")
    print(f"Target reg distribution (top 15): {dict(tgt_cnt.most_common(15))}")


if __name__ == '__main__':
    main()
