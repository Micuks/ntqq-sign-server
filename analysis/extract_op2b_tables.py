"""Extract op 0x2B/0x2D tables from u64 trace.

Op 0x2B: r_ib1 = TABLE_for_ib2[state[ib[3]]]   — qword
Op 0x2D: similar but writes lower-32 with sign-extend (need to verify)

For each ib pattern, build {idx -> u64_value}.
"""
import json
from collections import defaultdict


def extract_for_op(trace, op):
    """Returns {ib_tuple: {idx_value: u64_target}} — only CONSISTENT patterns
    where state[ib[3]] alone determines the output across all invocations."""
    tables = defaultdict(dict)
    inconsistent = set()
    for s in range(len(trace) - 1):
        ib = trace[s][1]
        if not ib or ib[0] != op: continue
        ib_t = tuple(ib)
        target = ib[1]
        idx_reg = ib[3]
        if target >= 300 or idx_reg >= 300: continue
        idx = trace[s][2][idx_reg]
        target_lo = trace[s+1][2][target]
        target_hi = trace[s+1][3][target]
        target_u64 = (target_hi << 32) | target_lo
        if idx in tables[ib_t]:
            if tables[ib_t][idx] != target_u64:
                inconsistent.add(ib_t)
                continue
        tables[ib_t][idx] = target_u64
    return {k: v for k, v in tables.items() if k not in inconsistent}


def main():
    # Load multiple traces to get more coverage
    all_tables = {0x2B: defaultdict(dict), 0x2D: defaultdict(dict), 0x32: defaultdict(dict)}
    for ti in range(4):
        path = f'/tmp/multi_u64_{ti:02x}.json'
        try:
            trace = json.load(open(path))
        except FileNotFoundError:
            continue
        for op in (0x2B, 0x2D, 0x32):
            tab = extract_for_op(trace, op)
            for k, v in tab.items():
                all_tables[op][k].update(v)

    # Save each
    name_map = {0x2B: 'op2b_qword_tables.json', 0x2D: 'op2d_qword_tables.json',
                0x32: 'op32_qword_tables.json'}
    for op, tabs in all_tables.items():
        out = {str(k): {str(idx): val for idx, val in tab.items()} for k, tab in tabs.items()}
        print(f"\nOp 0x{op:02x}: {len(out)} ib patterns")
        for ib, tab in out.items():
            print(f"  {ib}: {len(tab)} entries")
        path = f'/mnt/data1/wuql/services/ntqq-sign-server/analysis/{name_map[op]}'
        json.dump(out, open(path, 'w'))
        print(f"Saved {name_map[op]}")


if __name__ == '__main__':
    main()
