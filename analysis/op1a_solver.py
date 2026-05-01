"""Try to find op 0x1a HI16 formula using 16K mappings."""
import json
sbox = open('/mnt/data1/wuql/services/ntqq-sign-server/custom_sbox.bin','rb').read()

def sar(x, n):
    if x >> 31:
        return ((x >> n) | ((0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return x >> n

def rotl(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

print("Loading 16K mappings...")
data = json.load(open('/tmp/op1a_mass.json'))

# Build deduplicated mappings
mappings = {}
for r13, after in data:
    delta = after ^ sar(r13, 16)
    hi16 = (delta >> 16) & 0xFFFF
    mappings[r13] = hi16

mappings_list = list(mappings.items())
print(f"Unique mappings: {len(mappings_list)}")

# Test: HI16 = sbox[byte_a(g(r13))] | (sbox[byte_b(g(r13))] << 8)
# where g is some transform
def test_formula(name, fn):
    matches = sum(1 for r, hi in mappings_list if fn(r) == hi)
    if matches > 100:
        print(f"  {name}: {matches}/{len(mappings_list)}")
    return matches

# Try a wide variety
tested = []

# 1. SBOX of byte pairs of r13 (already tested but with 16K we may discover)
for X in range(4):
    for Y in range(4):
        n = test_formula(f'sbox[b{X}(r13)] | sbox[b{Y}(r13)]<<8',
                         lambda r, X=X, Y=Y: sbox[(r >> (X*8)) & 0xFF] | (sbox[(r >> (Y*8)) & 0xFF] << 8))

# 2. SBOX of byte pairs of L(r13)
def L(x):
    return x ^ rotl(x,2) ^ rotl(x,10) ^ rotl(x,18) ^ rotl(x,24)
def Lp(x):
    return x ^ rotl(x,13) ^ rotl(x,23)
def sbox_4(w):
    return sbox[w & 0xFF] | (sbox[(w >> 8) & 0xFF] << 8) | (sbox[(w >> 16) & 0xFF] << 16) | (sbox[(w >> 24) & 0xFF] << 24)

# T(x) = L(sbox_4(x))
def T(x):
    return L(sbox_4(x))

# Try HI16 = some bytes of T(r13)
print("\n=== T(r13) = L(sbox_4(r13)) byte slice tests ===")
for shift in [0, 8, 16, 24]:
    n = test_formula(f'(T(r13) >> {shift}) & 0xFFFF',
                     lambda r, sh=shift: (T(r) >> sh) & 0xFFFF)

# Maybe HI16 = T(r13) XOR'd with itself rotated
print("\n=== T(r13) variants ===")
for sh in [0, 8, 16, 24]:
    n = test_formula(f'(T(r13) ^ rotl(T(r13), 16)) >> {sh}',
                     lambda r, sh=sh: ((T(r) ^ rotl(T(r), 16)) >> sh) & 0xFFFF)

# Maybe it's the L' from key schedule: T'(x) = L'(sbox_4(x))
def Tp(x):
    return Lp(sbox_4(x))
print("\n=== T'(r13) = L'(sbox_4(r13)) byte slice ===")
for shift in [0, 8, 16, 24]:
    n = test_formula(f'(Tp(r13) >> {shift}) & 0xFFFF',
                     lambda r, sh=shift: (Tp(r) >> sh) & 0xFFFF)

# Maybe HI16 from L(r13) directly
print("\n=== L(r13) byte slices ===")
for shift in [0, 8, 16, 24]:
    n = test_formula(f'(L(r13) >> {shift}) & 0xFFFF',
                     lambda r, sh=shift: (L(r) >> sh) & 0xFFFF)

# Maybe HI16 = ((r13 XOR rotl(r13, 8)) >> 16) & 0xFFFF
print("\n=== Mixed XOR/rotation ===")
for shift in [0, 8, 16, 24]:
    n = test_formula(f'((r13 ^ rotl(r13, 8)) >> {shift}) & 0xFFFF',
                     lambda r, sh=shift: ((r ^ rotl(r, 8)) >> sh) & 0xFFFF)

# Print sample mappings
print("\n=== Sample (r13 → HI16) ===")
for r, h in list(mappings.items())[:10]:
    print(f"  r13=0x{r:08x} → HI16=0x{h:04x}")
