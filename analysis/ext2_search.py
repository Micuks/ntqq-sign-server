"""For each unsolved miss step, find target = state[X] in 300-reg space — extended search."""
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

# Use VM
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

print(f"MISS ibs: {len(step_by_ib)}, steps: {len(miss_steps)}", flush=True)

new_solutions = {}

def find_xor_in_ext(s):
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

    # 1. target = state[X]
    for x in range(NREGS):
        if x == target: continue
        if all(states[sb][x] == afters[sb] for sb in range(16)):
            return ('R', target, x)
    # 2. target = state[X] ^ state[Y]
    for x in range(NREGS):
        for y in range(x+1, NREGS):
            if all((states[sb][x] ^ states[sb][y]) & MASK == afters[sb] for sb in range(16)):
                return ('XOR2', target, x, y)
    # 3. target ^= state[X]
    for x in range(NREGS):
        if x == target: continue
        if all((states[sb][target] ^ states[sb][x]) & MASK == afters[sb] for sb in range(16)):
            return ('XOR_ACC', target, x)
    # 4. SBOX_SHIFT
    for x in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            for sh_out in [0, 8, 16, 24]:
                ok = all((sbox[(states[sb][x] >> sh_in) & 0xFF] << sh_out) & MASK == afters[sb] for sb in range(16))
                if ok:
                    return ('SBOX_SHIFT', target, x, sh_in, sh_out)
    # 5. SBOX_BYTE_INSERT
    for x in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            for sh_out in [0, 8, 16, 24]:
                bm = ~(0xFF << sh_out) & MASK
                if all(((states[sb][target] & bm) | ((sbox[(states[sb][x] >> sh_in) & 0xFF] & 0xFF) << sh_out)) & MASK == afters[sb] for sb in range(16)):
                    return ('SBOX_BYTE_INSERT', target, x, sh_in, sh_out)
    # 6. SBOX_XOR_INTO
    for x in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            for sh_out in [0, 8, 16, 24]:
                if all((states[sb][target] ^ ((sbox[(states[sb][x] >> sh_in) & 0xFF] & 0xFF) << sh_out)) & MASK == afters[sb] for sb in range(16)):
                    return ('SBOX_XOR_INTO', target, x, sh_in, sh_out)
    # 7. byte_merge
    for x in range(NREGS):
        for y in range(NREGS):
            if x == y: continue
            for sh in [0, 8, 16, 24]:
                m = 0xFF << sh
                if all(((states[sb][x] & ~m) | (states[sb][y] & m)) & MASK == afters[sb] for sb in range(16)):
                    return ('BYTE_MERGE', target, x, y, sh)
    return None

total = 0
for ib, steps in step_by_ib.items():
    sols = {}
    for s in steps:
        sol = find_xor_in_ext(s)
        if sol:
            sols[s] = list(sol)
    if sols:
        new_solutions[ib] = sols
        total += len(sols)
        print(f"  {ib}: {len(sols)}/{len(steps)}", flush=True)

print(f"\nTotal: {total}", flush=True)

existing = json.load(open('/tmp/per_step_ext.json'))
saved = dict(existing)
for ib, sols in new_solutions.items():
    ib_str = str(ib)
    if ib_str not in saved:
        saved[ib_str] = {}
    for s, sol in sols.items():
        saved[ib_str][str(s)] = sol
json.dump(saved, open('/tmp/per_step_ext2.json','w'))
print("Saved /tmp/per_step_ext2.json", flush=True)
