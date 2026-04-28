"""More aggressive per-step search: half-word combos, complex shifts."""
import json
import sys
NREGS = 300
MASK = 0xFFFFFFFF

print("Loading 16 multi_ext...", flush=True)
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_ext_{sb:02x}.json'))
n_steps = len(traces[0])

sbox = open('/mnt/data1/wuql/services/ntqq-sign-server/custom_sbox.bin','rb').read()

def rotl(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & MASK

sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_vm_v2

trace = json.load(open('/tmp/multi_ext_00.json'))
results = pure_vm_v2.replay_trace(trace)
miss_steps = [r[0] for r in results if r[1] == 'MISS']

from collections import defaultdict
step_by_ib = defaultdict(list)
for s in miss_steps:
    if not traces[0][s] or not traces[0][s][1]: continue
    step_by_ib[tuple(traces[0][s][1])].append(s)

print(f"MISS ibs: {len(step_by_ib)}", flush=True)

new_solutions = {}

def find_advanced(s):
    states = [traces[sb][s][2] for sb in range(16)]
    target_changes = defaultdict(int)
    for sb in range(16):
        before = traces[sb][s][2]
        after = traces[sb][s+1][2]
        for r in range(NREGS):
            if before[r] != after[r]:
                target_changes[r] += 1
    if not target_changes:
        return None
    target = max(target_changes, key=lambda r: target_changes[r])
    afters = [traces[sb][s+1][2][target] for sb in range(16)]

    # 1. target = (state[X] >> sh) | (state[Y] << (32-sh))
    for x in range(NREGS):
        for y in range(NREGS):
            if x == y: continue
            for sh in [8, 16, 24]:
                hi = 32 - sh
                if all((((states[sb][x] >> sh) & ((1 << hi) - 1)) | ((states[sb][y] << hi) & MASK)) & MASK == afters[sb] for sb in range(16)):
                    return ('SHIFT_OR', target, x, sh, y, hi)

    # 2. target = (state[X] & 0xFFFF0000) | (state[Y] & 0xFFFF)
    for x in range(NREGS):
        for y in range(NREGS):
            if x == y: continue
            if all(((states[sb][x] & 0xFFFF0000) | (states[sb][y] & 0xFFFF)) & MASK == afters[sb] for sb in range(16)):
                return ('HW_MERGE_HI_LO', target, x, y)

    # 3. target = (state[X] & 0xFFFF) | (state[Y] & 0xFFFF0000)
    for x in range(NREGS):
        for y in range(NREGS):
            if x == y: continue
            if all(((states[sb][x] & 0xFFFF) | (states[sb][y] & 0xFFFF0000)) & MASK == afters[sb] for sb in range(16)):
                return ('HW_MERGE_LO_HI', target, x, y)

    # 4. target = state[X] >> sh
    for x in range(NREGS):
        for sh in range(1, 32):
            if all((states[sb][x] >> sh) & MASK == afters[sb] for sb in range(16)):
                return ('SHIFT_R', target, x, sh)

    # 5. target = state[X] << sh
    for x in range(NREGS):
        for sh in range(1, 32):
            if all((states[sb][x] << sh) & MASK == afters[sb] for sb in range(16)):
                return ('SHIFT_L', target, x, sh)

    # 6. target = state[X] ^ const for some constant
    for x in range(NREGS):
        c = states[0][x] ^ afters[0]
        if all((states[sb][x] ^ c) & MASK == afters[sb] for sb in range(16)):
            return ('XOR_CONST', target, x, c)

    # 7. target = state[X] + const
    for x in range(NREGS):
        c = (afters[0] - states[0][x]) & MASK
        if all((states[sb][x] + c) & MASK == afters[sb] for sb in range(16)):
            return ('ADD_CONST', target, x, c)

    # 8. target = sbox[(state[X] >> sh_in) & 0xFF] | (sbox[(state[Y] >> sh_in2) & 0xFF] << sh_out2)
    # This is byte assembly from 2 sbox lookups
    # Skip - too expensive

    return None

total = 0
for ib, steps in step_by_ib.items():
    sols = {}
    for s in steps:
        sol = find_advanced(s)
        if sol:
            sols[s] = list(sol)
    if sols:
        new_solutions[ib] = sols
        total += len(sols)
        print(f"  {ib}: {len(sols)}/{len(steps)}", flush=True)

print(f"\nTotal new: {total}", flush=True)

existing = json.load(open('/tmp/per_step_ext2.json'))
saved = dict(existing)
for ib, sols in new_solutions.items():
    ib_str = str(ib)
    if ib_str not in saved:
        saved[ib_str] = {}
    for s, sol in sols.items():
        saved[ib_str][str(s)] = sol
json.dump(saved, open('/tmp/per_step_ext3.json','w'))
print("Saved /tmp/per_step_ext3.json", flush=True)
