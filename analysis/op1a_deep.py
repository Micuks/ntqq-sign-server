"""Deep look at op 0x1a ib=(26, 46, 13, 0). Find the formula."""
import json
NREGS = 300
MASK = 0xFFFFFFFF

print("Loading 16 multi_ext...")
traces = {}
for sb in range(16):
    traces[sb] = json.load(open(f'/tmp/multi_ext_{sb:02x}.json'))
n_steps = len(traces[0])

target_ib = (26, 46, 13, 0)
target = 46
steps = [s for s in range(n_steps - 1)
         if traces[0][s] and traces[0][s][1] and tuple(traces[0][s][1]) == target_ib]
print(f"steps: {len(steps)}")

# Approach: find what reg holds the result XOR'd. For op 0x1a, maybe target ^= ?
# Look at 0xnnXX bytes per source to find pattern.
# Specifically check first 4 steps:
for s in steps[:4]:
    print(f"\nstep {s}:")
    afters = [traces[sb][s+1][2][target] for sb in range(16)]
    # Find which register at step s holds the result for ALL 16 srcs
    # Wait we already tried that. Let me try complex byte-rearrangement.

    # Maybe target = rotr(some_reg, 16)?
    for x in range(NREGS):
        states = [traces[sb][s][2][x] for sb in range(16)]
        rotated = [(v >> 16) | ((v & 0xFFFF) << 16) for v in states]
        if rotated == afters:
            print(f"  target = rotr16(state[{x}])")
            break

    # Maybe target = byteswap(some reg)?
    for x in range(NREGS):
        states = [traces[sb][s][2][x] for sb in range(16)]
        rev = [((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v & 0xFF0000) >> 8) | ((v >> 24) & 0xFF) for v in states]
        if rev == afters:
            print(f"  target = bswap(state[{x}])")
            break

    # Maybe target = state[X] | mask_const for various X
    for x in range(NREGS):
        states = [traces[sb][s][2][x] for sb in range(16)]
        # delta from each
        deltas = [afters[i] ^ states[i] for i in range(16)]
        if all(d == deltas[0] for d in deltas):
            print(f"  target = state[{x}] ^ 0x{deltas[0]:08x}")
            break
        if all(afters[i] == ((states[i] | deltas[0]) & MASK) for i in range(16)):
            print(f"  target = state[{x}] | 0x{deltas[0]:08x}")
            break

    # Maybe target = state[X] & state[Y]
    found = False
    for x in range(NREGS):
        for y in range(x+1, NREGS):
            sx = [traces[sb][s][2][x] for sb in range(16)]
            sy = [traces[sb][s][2][y] for sb in range(16)]
            if all((sx[i] & sy[i]) & MASK == afters[i] for i in range(16)):
                print(f"  target = state[{x}] & state[{y}]")
                found = True
                break
            if all((sx[i] | sy[i]) & MASK == afters[i] for i in range(16)):
                print(f"  target = state[{x}] | state[{y}]")
                found = True
                break
        if found: break

    # Show afters and r13 details for context
    print(f"  r13_before across srcs: {[hex(traces[sb][s][2][13]) for sb in range(0,4)]}")
    print(f"  afters[0..3]: {[hex(a) for a in afters[:4]]}")

# Maybe target = state[X] ^ rotl(state[Y], n)
print("\n=== Try target = state[X] ^ rotl(state[Y], n) ===")
for s in steps[:4]:
    states = [traces[sb][s][2] for sb in range(16)]
    afters = [traces[sb][s+1][2][target] for sb in range(16)]

    def rotl(x, n):
        n = n & 31
        return ((x << n) | (x >> (32 - n))) & MASK

    found = None
    for x in range(NREGS):
        sx = [states[sb][x] for sb in range(16)]
        for y in range(NREGS):
            if x == y: continue
            sy = [states[sb][y] for sb in range(16)]
            for n in [8, 16, 24]:
                if all((sx[i] ^ rotl(sy[i], n)) & MASK == afters[i] for i in range(16)):
                    found = (x, y, n)
                    break
            if found: break
        if found: break
    print(f"  step {s}: {found}")
