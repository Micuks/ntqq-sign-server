"""For op 0x29 ib=(41,29,85,212), find which formula applies at each STEP.
Save the per-step formula so we can look up at replay time.
"""
import json
NREGS = 150
MASK = 0xFFFFFFFF

print("Loading...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))
n_steps = len(traces[0])
sbox = open('/mnt/data1/wuql/services/ntqq-sign-server/custom_sbox.bin','rb').read()

# Find ALL unsolved op 0x29 + op 0x1a + op 0x2b patterns
# General per-step solver: for each step, find what formula matches

# For each step, find: target = SBOX[(reg[X] >> sh_in) & 0xFF] << sh_out
# OR similar. Group steps by (op, ib).

# Load existing solved
solved = set()
for fn in ['/tmp/learned_v5.json']:
    d = json.load(open(fn))
    if 'solved' in d: d = d['solved']
    solved.update(eval(k) for k in d)
for fn in ['/tmp/more_solved.json', '/tmp/v6_solved.json', '/tmp/byte_solved.json',
           '/tmp/tables_v3.json', '/tmp/sbox_shift.json']:
    try:
        d = json.load(open(fn))
        solved.update(eval(k) for k in d)
    except: pass
nops = json.load(open('/tmp/nop_patterns.json'))
solved.update(tuple(ib) for ib in nops)

from collections import defaultdict
by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

# Per-step solutions for unsolved (op 0x29, op 0x1a, op 0x2b, op 0x55)
TARGET_OPS = [0x29, 0x1a, 0x2b, 0x55, 0x32, 0x09, 0x0d]

per_step_solutions = {}  # (ib_tuple, step) -> (kind, target, idx_reg, sh_in, sh_out)
ib_step_map = defaultdict(dict)  # ib -> {step: solution}

for ib, steps in by_ib.items():
    if ib in solved: continue
    if ib[0] not in TARGET_OPS: continue
    
    # Find target reg for this ib (max changed)
    target_changes = defaultdict(int)
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    target_changes[r] += 1
    if not target_changes: continue
    target = max(target_changes, key=lambda r: target_changes[r])
    
    n_solved = 0
    for s in steps:
        # Try SBOX_SHIFT
        for idx_reg in range(NREGS):
            for sh_in in [0, 8, 16, 24]:
                for sh_out in [0, 8, 16, 24]:
                    ok = True
                    for sb in range(16):
                        before = traces[sb][s][2]
                        after = traces[sb][s+1][2]
                        idx = (before[idx_reg] >> sh_in) & 0xFF
                        expected = (sbox[idx] << sh_out) & MASK
                        if expected != after[target]:
                            ok = False
                            break
                    if ok:
                        ib_step_map[ib][s] = ('SBOX_SHIFT', target, idx_reg, sh_in, sh_out)
                        n_solved += 1
                        break
                if s in ib_step_map[ib]: break
            if s in ib_step_map[ib]: break
        if s in ib_step_map[ib]: continue
        
        # Try SBOX_BYTE_INSERT
        for idx_reg in range(NREGS):
            for sh_in in [0, 8, 16, 24]:
                for sh_out in [0, 8, 16, 24]:
                    bm = ~(0xFF << sh_out) & MASK
                    ok = True
                    for sb in range(16):
                        before = traces[sb][s][2]
                        after = traces[sb][s+1][2]
                        idx = (before[idx_reg] >> sh_in) & 0xFF
                        expected = ((before[target] & bm) | ((sbox[idx] & 0xFF) << sh_out)) & MASK
                        if expected != after[target]:
                            ok = False
                            break
                    if ok:
                        ib_step_map[ib][s] = ('SBOX_BYTE_INSERT', target, idx_reg, sh_in, sh_out)
                        n_solved += 1
                        break
                if s in ib_step_map[ib]: break
            if s in ib_step_map[ib]: break
        if s in ib_step_map[ib]: continue
        
        # Try SBOX_XOR_INTO
        for idx_reg in range(NREGS):
            for sh_in in [0, 8, 16, 24]:
                for sh_out in [0, 8, 16, 24]:
                    ok = True
                    for sb in range(16):
                        before = traces[sb][s][2]
                        after = traces[sb][s+1][2]
                        idx = (before[idx_reg] >> sh_in) & 0xFF
                        expected = (before[target] ^ ((sbox[idx] & 0xFF) << sh_out)) & MASK
                        if expected != after[target]:
                            ok = False
                            break
                    if ok:
                        ib_step_map[ib][s] = ('SBOX_XOR_INTO', target, idx_reg, sh_in, sh_out)
                        n_solved += 1
                        break
                if s in ib_step_map[ib]: break
            if s in ib_step_map[ib]: break

# Print per-ib summary
total_steps_solved = 0
total_steps = 0
for ib, step_map in ib_step_map.items():
    total = len(by_ib[ib])
    solved_count = len(step_map)
    total_steps += total
    total_steps_solved += solved_count
    print(f"  {ib}: {solved_count}/{total} steps solved")

print(f"\nTotal: {total_steps_solved}/{total_steps} steps")

# Save per-step solutions
saved = {}
for ib, step_map in ib_step_map.items():
    saved[str(ib)] = {str(s): list(sol) for s, sol in step_map.items()}
json.dump(saved, open('/tmp/per_step_sbox.json','w'))
print(f"Saved /tmp/per_step_sbox.json")
