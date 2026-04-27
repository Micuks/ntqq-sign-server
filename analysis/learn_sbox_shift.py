"""Try: target = SBOX[(reg[X] >> sh_in) & 0xFF] << sh_out (with possible OR to existing target)."""
import json
from collections import defaultdict
NREGS = 150
MASK = 0xFFFFFFFF

print("Loading...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_trace_{sb:02x}.json'))
n_steps = len(traces[0])

sbox = open('/mnt/data1/wuql/services/ntqq-sign-server/custom_sbox.bin','rb').read()

by_ib = defaultdict(list)
for s in range(n_steps - 1):
    if not traces[0][s] or not traces[0][s][1]: continue
    ib = traces[0][s][1]
    if not ib or len(ib) != 4: continue
    if not all(traces[sb][s] and traces[sb][s+1] and traces[sb][s][2] and traces[sb][s+1][2] for sb in range(16)): continue
    by_ib[tuple(ib)].append(s)

solved = set()
for fn in ['/tmp/learned_v5.json']:
    d = json.load(open(fn))
    if 'solved' in d: d = d['solved']
    solved.update(eval(k) for k in d)
for fn in ['/tmp/more_solved.json', '/tmp/v6_solved.json', '/tmp/byte_solved.json', '/tmp/tables_v3.json']:
    try:
        d = json.load(open(fn))
        solved.update(eval(k) for k in d)
    except: pass
nops = json.load(open('/tmp/nop_patterns.json'))
solved.update(tuple(ib) for ib in nops)

new_solved = {}
for ib, steps in by_ib.items():
    if ib in solved: continue
    
    target_changes = defaultdict(list)
    for s in steps:
        for sb in range(16):
            before = traces[sb][s][2]
            after = traces[sb][s+1][2]
            for r in range(NREGS):
                if before[r] != after[r]:
                    target_changes[r].append((before, after))
    if not target_changes: continue
    target = max(target_changes, key=lambda r: len(target_changes[r]))
    
    obs = []
    for s in steps:
        for sb in range(16):
            obs.append((traces[sb][s][2], traces[sb][s+1][2][target]))
    
    found = None
    # Try: target = SBOX[(reg[X] >> sh_in) & 0xFF] << sh_out
    for idx_reg in range(NREGS):
        for sh_in in [0, 8, 16, 24]:
            for sh_out in [0, 8, 16, 24]:
                ok = True
                for state, val in obs:
                    idx = (state[idx_reg] >> sh_in) & 0xFF
                    expected = (sbox[idx] << sh_out) & MASK
                    if expected != val:
                        ok = False
                        break
                if ok:
                    found = ('SBOX_SHIFT', target, idx_reg, sh_in, sh_out)
                    break
            if found: break
        if found: break
    
    # Try: target = (target & ~MASK_AT_SH_OUT) | (SBOX[(reg[X] >> sh_in) & 0xFF] << sh_out)
    if not found:
        for idx_reg in range(NREGS):
            if idx_reg == target: continue
            for sh_in in [0, 8, 16, 24]:
                for sh_out in [0, 8, 16, 24]:
                    bm = ~(0xFF << sh_out) & MASK
                    ok = True
                    for state, val in obs:
                        idx = (state[idx_reg] >> sh_in) & 0xFF
                        expected = (state[target] & bm) | ((sbox[idx] & 0xFF) << sh_out)
                        expected &= MASK
                        if expected != val:
                            ok = False
                            break
                    if ok:
                        found = ('SBOX_BYTE_INSERT', target, idx_reg, sh_in, sh_out)
                        break
                if found: break
            if found: break
    
    # Try: target = target ^ (SBOX[(reg[X] >> sh_in) & 0xFF] << sh_out)
    if not found:
        for idx_reg in range(NREGS):
            for sh_in in [0, 8, 16, 24]:
                for sh_out in [0, 8, 16, 24]:
                    ok = True
                    for state, val in obs:
                        idx = (state[idx_reg] >> sh_in) & 0xFF
                        expected = (state[target] ^ ((sbox[idx] & 0xFF) << sh_out)) & MASK
                        if expected != val:
                            ok = False
                            break
                    if ok:
                        found = ('SBOX_XOR_INTO', target, idx_reg, sh_in, sh_out)
                        break
                if found: break
            if found: break
    
    if found:
        new_solved[ib] = found

print(f"New SBOX patterns: {len(new_solved)}")
from collections import Counter
op_solve = Counter(ib[0] for ib in new_solved)
for op, cnt in sorted(op_solve.items(), key=lambda x: -x[1])[:10]:
    print(f"  op 0x{op:02x}: {cnt}")
print()
for ib, info in list(new_solved.items())[:10]:
    print(f"  {ib} -> {info}")

saved = {}
for ib, info in new_solved.items():
    saved[str(ib)] = list(info)
json.dump(saved, open('/tmp/sbox_shift.json','w'))
print("Saved")
