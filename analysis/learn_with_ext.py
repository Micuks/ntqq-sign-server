"""Re-run per-step learner with NREGS=300 using 16 multi_ext traces."""
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

# Use VM to find MISS/WRONG steps
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
    
    # 1. target = state[X] in 300-reg space
    for x in range(NREGS):
        if all(states[sb][x] == afters[sb] for sb in range(16)):
            return ('R', x)
    
    # 2. target = sbox[(state[X] >> sh_in) & 0xFF] << sh_out
    for x in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            for sh_out in [0, 8, 16, 24]:
                ok = all((sbox[(states[sb][x] >> sh_in) & 0xFF] << sh_out) & MASK == afters[sb] for sb in range(16))
                if ok:
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
    
    # 8. byte merge
    for x in range(NREGS):
        for y in range(NREGS):
            if x == y: continue
            for sh in [0, 8, 16, 24]:
                m = 0xFF << sh
                if all(((states[sb][x] & ~m) | (states[sb][y] & m)) & MASK == afters[sb] for sb in range(16)):
                    return ('BYTE_MERGE', x, y, sh)
    
    # 9. ROTL
    for x in range(NREGS):
        for n in range(1, 32):
            if all(rotl(states[sb][x], n) == afters[sb] for sb in range(16)):
                return ('ROTL', x, n)
    
    return None

# For ops where target might be in extended range, find target dynamically
total_solved = 0
for ib, steps in step_by_ib.items():
    target_changes = defaultdict(int)
    for s in steps[:5]:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    target_changes[r] += 1
    if not target_changes: continue
    target = max(target_changes, key=lambda r: target_changes[r])
    
    solutions = {}
    # For per-step ops where target changes per call (like op 0x2d), find target per step
    for s in steps:
        # Find target for THIS step
        step_target_changes = defaultdict(int)
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    step_target_changes[r] += 1
        if not step_target_changes:
            continue
        step_target = max(step_target_changes, key=lambda r: step_target_changes[r])
        
        sol = find_solution(s, step_target)
        if sol:
            # Save as (kind, target, *args)
            full_sol = list(sol)
            full_sol.insert(1, step_target)
            solutions[s] = full_sol
    
    if solutions:
        new_per_step[ib] = solutions
        total_solved += len(solutions)
        print(f"  {ib}: {len(solutions)}/{len(steps)} (default_target={target})", flush=True)

print(f"\nTotal: {total_solved} solved", flush=True)

# Save
saved = {}
existing = json.load(open('/tmp/per_step_all.json'))
for ib_str, step_map in existing.items():
    saved[ib_str] = step_map
for ib, step_map in new_per_step.items():
    ib_str = str(ib)
    if ib_str not in saved:
        saved[ib_str] = {}
    for s, sol in step_map.items():
        saved[ib_str][str(s)] = list(sol)
json.dump(saved, open('/tmp/per_step_ext.json','w'))
print("Saved /tmp/per_step_ext.json", flush=True)
