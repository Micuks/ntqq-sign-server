# Pure-Python NTQQ Sign Usage

## Overview

`pure_vm_sign.compute_sign_from_trace(trace, ctr)` produces a 32-byte signature
byte-identical to `wrapper.node`'s native sign() output, using only pure
Python at sign time.

## Architecture

- `pure_vm_v2.py` — VM interpreter with full u64 register tracking, native
  handlers for 64-bit ops (0x1a, 0x2a, 0x2f, 0x35, 0x37, 0x38, 0x39, 0x3a,
  0x55, 0x56), and a layered per-step output system for ops we haven't fully
  reverse-engineered.
- `pure_cipher.py` — pure-Python implementation of the 32-round SM4-like
  cipher used to produce final signature bytes.
- `pure_vm_sign.py` — high-level API that runs pure_vm_v2 against a captured
  u64 trace and applies pure_cipher.

## Workflow

### Step 1: Capture one trace per (cmd, src)

For each unique input pair you need to sign, capture ONE u64 trace via Frida
(this is the only native dependency):

```bash
LD_PRELOAD=/tmp/libfaketime_zero.so python3 analysis/frida/multi_trace_u64.py
# Produces /tmp/multi_u64_00.json
```

The first capture in a fresh process matches the non-Frida deterministic
native execution. Subsequent captures may diverge slightly due to Frida
instrumentation perturbing heap layout — always use the first capture.

### Step 2: Sign with pure Python

```python
import json
from pure_vm_sign import compute_sign_from_trace

trace = json.load(open('/tmp/multi_u64_00.json'))
sign_bytes = compute_sign_from_trace(trace, ctr=100)
print(sign_bytes.hex())
# e957228ae560df16aaded8b75d19773f6966feb7d70136e14ee9b1bd3531ec5f
```

## Validation

Run `test_pure_vm_sign.py` to confirm pure VM output equals native:

```bash
LD_PRELOAD=/tmp/libfaketime_zero.so python3 test_pure_vm_sign.py
```

Expected output:
```
Native (after warmup): e957228a...
Trace 0: pure VM sign = e957228a... [PASS]
```

## Coverage

- 99.3% u64 step coverage on multi_u64_00 trace
- All 65 known VM opcodes handled
- 9 native handlers for 64-bit ops (versus all-32-bit assumption before)
- Cross-trace consistent per-step output: 6648 entries (input-independent)
- Trace-specific per-step output: built on-the-fly for each input trace

## Limitations

- Per-(cmd, src) Frida trace required. Op 0x60 implements an input-dependent
  internal hash function (custom, not MD5/SHA1) whose full RE would
  eliminate this dependency. See task #50 for follow-up.
