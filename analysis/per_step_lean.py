"""Lean per-step formula learner — faster, no XOR3 (which is too expensive)."""
import json
import sys
NREGS = 150
MASK = 0xFFFFFFFF

print("Loading...", flush=True)
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))
n_steps = len(traces[0])

sbox = open('/mnt/data1/wuql/services/ntqq-sign-server/custom_sbox.bin','rb').read()

def rotl(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & MASK

# Use the VM to identify which steps MISS or are WRONG
sys.path.insert(0, '/mnt/data1/wuql/services/ntqq-sign-server')
import pure_vm_v2

trace = json.load(open('/tmp/multi_trace_00.json'))
results = pure_vm_v2.replay_trace(trace)
miss_or_wrong_steps = [r[0] for r in results if r[1] in ('MISS', 'WRONG')]
print(f"MISS/WRONG steps: {len(miss_or_wrong_steps)}", flush=True)

from collections import defaultdict
step_by_ib = defaultdict(list)
for s in miss_or_wrong_steps:
    if not traces[0][s] or not traces[0][s][1]: continue
    step_by_ib[tuple(traces[0][s][1])].append(s)

print(f"Distinct ibs: {len(step_by_ib)}", flush=True)

new_per_step = {}

def find_solution(s, target):
    states = [traces[sb][s][2] for sb in range(16)]
    afters = [traces[sb][s+1][2][target] for sb in range(16)]
    
    # 1. target = state[X]
    for x in range(NREGS):
        if all(states[sb][x] == afters[sb] for sb in range(16)):
            return ('R', x)
    
    # 2. target = sbox[(state[X] >> sh_in) & 0xFF] << sh_out
    for x in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            xs = [(states[sb][x] >> sh_in) & 0xFF for sb in range(16)]
            sboxed = [sbox[i] for i in xs]
            for sh_out in [0, 8, 16, 24]:
                if all((sboxed[sb] << sh_out) & MASK == afters[sb] for sb in range(16)):
                    return ('SBOX_SHIFT', x, sh_in, sh_out)
    
    # 3. target = state[X] ^ state[Y]
    for x in range(NREGS):
        for y in range(x, NREGS):
            if all((states[sb][x] ^ states[sb][y]) & MASK == afters[sb] for sb in range(16)):
                return ('XOR2', x, y)
    
    # 4. target ^= state[X]
    for x in range(NREGS):
        if x == target: continue
        if all((states[sb][target] ^ states[sb][x]) & MASK == afters[sb] for sb in range(16)):
            return ('XOR_ACC', x)
    
    # 5. target = sbox-byte-insert into target
    for x in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            for sh_out in [0, 8, 16, 24]:
                bm = ~(0xFF << sh_out) & MASK
                ok = all(((states[sb][target] & bm) | ((sbox[(states[sb][x] >> sh_in) & 0xFF] & 0xFF) << sh_out)) & MASK == afters[sb] for sb in range(16))
                if ok:
                    return ('SBOX_BYTE_INSERT', x, sh_in, sh_out)
    
    # 6. target = sbox xor into
    for x in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            for sh_out in [0, 8, 16, 24]:
                ok = all((states[sb][target] ^ ((sbox[(states[sb][x] >> sh_in) & 0xFF] & 0xFF) << sh_out)) & MASK == afters[sb] for sb in range(16))
                if ok:
                    return ('SBOX_XOR_INTO', x, sh_in, sh_out)
    
    # 7. target = state[X] | (state[Y] << shift)
    for x in range(NREGS):
        for y in range(NREGS):
            if x == y: continue
            for sh in [8, 16, 24]:
                if all((states[sb][x] | ((states[sb][y] << sh) & MASK)) & MASK == afters[sb] for sb in range(16)):
                    return ('OR_SHIFT', x, y, sh)
    
    # 8. target = (state[X] & ~mask) | (state[Y] & mask)  
    for x in range(NREGS):
        for y in range(NREGS):
            if x == y: continue
            for sh in [0, 8, 16, 24]:
                m = 0xFF << sh
                if all(((states[sb][x] & ~m) | (states[sb][y] & m)) & MASK == afters[sb] for sb in range(16)):
                    return ('BYTE_MERGE', x, y, sh)
    
    # 9. target = rotl(state[X], n)
    for x in range(NREGS):
        for n in range(1, 32):
            if all(rotl(states[sb][x], n) == afters[sb] for sb in range(16)):
                return ('ROTL', x, n)
    
    return None

total_solved = 0
for ib, steps in step_by_ib.items():
    target_changes = defaultdict(int)
    for s in steps[:20]:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    target_changes[r] += 1
    if not target_changes: continue
    target = max(target_changes, key=lambda r: target_changes[r])
    
    solutions = {}
    for s in steps:
        sol = find_solution(s, target)
        if sol:
            solutions[s] = sol
    
    if solutions:
        new_per_step[ib] = solutions
        total_solved += len(solutions)
        print(f"  {ib}: {len(solutions)}/{len(steps)} (target={target})", flush=True)

print(f"\nTotal: {total_solved} solved", flush=True)

# Merge with existing
saved = {}
existing = json.load(open('/tmp/per_step_sbox.json'))
for ib_str, step_map in existing.items():
    saved[ib_str] = step_map
for ib, step_map in new_per_step.items():
    ib_str = str(ib)
    if ib_str not in saved:
        saved[ib_str] = {}
    for s, sol in step_map.items():
        saved[ib_str][str(s)] = list(sol)
json.dump(saved, open('/tmp/per_step_all.json','w'))
print("Saved", flush=True)
