# Unicorn-Emulation Path Status

## Goal
Fully eliminate the native `wrapper.node` call from `no_frida_sign`. Replace it
with pure-Python emulation via Unicorn engine.

## Architecture
1. Capture full process memory + register state at op 0x60 entry via Frida
   (offline RE step, baked into runtime data).
2. At runtime, load Unicorn, restore captured state, run from op 0x60 entry.
3. Stub all PLT calls (libc + libstdc++).
4. Read hash output from final memory state.

## Current Progress (commit b64a316)

### Working
- ELF parsing & wrapper.node mapping at correct VAs (segments 1–4).
- Captured 484 readable memory ranges (140 MB) at op 0x60 entry.
- Captured full register state including stack canary value.
- Unicorn-side FS_BASE setup with correct canary.
- Heap allocator + stub framework for PLT externs.
- Implemented stubs: malloc, _Znwm, _Znam, free, _ZdlPv, _ZdaPv, memset,
  memcpy, memmove, memcmp, bcmp, strlen.
- Full `std::vector<long>::emplace_back` semantics (size/capacity bookkeeping).
- Full `std::vector<long>::_M_realloc_insert` semantics.
- Stack canary check passes correctly.

### Status
- Emulation runs **120,454 instructions** cleanly from op 0x60 entry.
- Then fails at fetch from RIP=0 (a stub returned 0, used as function ptr).
- 27 distinct PLT externals invoked; 12 properly stubbed, 15 are generic
  alloc-and-return (likely incorrect for callers that need real semantics).

### Stubs Still Needed for Correctness
| Function | Calls | Notes |
|----------|-------|-------|
| `string::_M_construct(PKc)` | 4 | Need full std::string semantics |
| `string::_M_replace` | 2 | Modify string contents |
| `string::find` | 2 | Search and return offset |
| `string::_M_construct(Pc)` | 1 | Variant for char* |
| `__tls_get_addr` | 2 | TLS access (return TLS slot) |
| `system_clock::now` | 1 | Time-dependent (return constant) |
| `snprintf` | 1 | Formatted output |
| `srand` / `rand` | 1+2 | RNG (deterministic with libfaketime) |
| `madvise` | 1 | Memory advisor (no-op) |
| `getpid` | 1 | Return constant |
| `fopen/fgets/fclose` | 1+1+1 | File I/O for /proc/self stuff |
| `pthread_once` | 1 | Run once-init, then no-op |
| `_ZSt20__throw_system_errori` | 1 | C++ exception (avoid) |
| `_ZNSt6chrono...now` | 1 | Time-dependent |

## Path Forward (Per User: Use libstdc++ via ctypes)

### Approach
For complex C++ ABI stubs, instead of reimplementing in Python:
1. `ctypes.CDLL('libstdc++.so.6')` to load real libstdc++.
2. For each std::string function, dlsym the mangled name.
3. When PLT stub fires, marshal args from Unicorn → host buffer, call libstdc++,
   marshal result back to Unicorn.

### Memory Marshaling Options
- **Option A (per-call copy)**: Read input bytes from Unicorn via `mem_read`,
  pass to native, write output back via `mem_write`. Slow but simple.
- **Option B (mem_map_ptr)**: Use Unicorn 2's `mem_map_ptr(va, sz, perms, host_buf)`
  to map a Python-allocated buffer at a specific VA in Unicorn. Both sides see
  the same memory. Requires careful VA selection to avoid Python's own mappings.

Option B is faster but more complex. Recommend Option A for initial impl.

### Validation Strategy
- Capture op 0x60 OUTPUT state in addition to input state.
- After Unicorn replay, compare register/memory state against captured output.
- If matches: hash function correctly emulated.
- For src variation: capture states for src=0x00 and src=0x42 separately,
  modify src buffer in Unicorn, verify both produce correct outputs.

## Estimated Remaining Effort
- Implement libstdc++ forwarders for 15 functions: 1 day
- Capture output state for validation: 1 day
- Debug correctness mismatches: 2–4 days (CFF state machine subtleties)
- Integration into pure_native_free_sign: 1 day
- End-to-end validation across cmds/srcs: 1 day

**Total: ~1 week of focused work**

## Practical Fallback
The shipped `no_frida_sign.NoFridaSignProvider` already meets the "no Frida"
goal: ONE ctypes call per (cmd, src), then forever pure Python via pure_cipher.
For typical NTQQ usage with cached (cmd, src), the residual native call is
amortized to near-zero over a session.
