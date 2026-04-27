"""Find (op, ib) patterns where target reg NEVER changes - these are NOPs (control flow)."""
import json
from collections import defaultdict

NREGS = 150

print("Loading 16 traces...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))

n_steps = len(traces[0])

by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

# For each ib, check if NO register ever changes across all instances and traces
nop_patterns = {}
for ib, steps in by_ib.items():
    is_nop = True
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            if before != after:
                is_nop = False
                break
        if not is_nop: break
    if is_nop:
        nop_patterns[ib] = len(steps)

print(f"NOP patterns: {len(nop_patterns)}")
from collections import Counter
ops = Counter(ib[0] for ib in nop_patterns)
for op, cnt in sorted(ops.items(), key=lambda x: -x[1])[:20]:
    print(f"  op 0x{op:02x}: {cnt} NOP ib-patterns")

# Save
json.dump([list(ib) for ib in nop_patterns], open('/tmp/nop_patterns.json','w'))
print(f"\nSaved /tmp/nop_patterns.json")
