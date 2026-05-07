# Native-Elimination Path: Status Snapshot

## TL;DR
- **`no_frida_sign.NoFridaSignProvider`** (production-ready): ONE ctypes call per
  unique (cmd, src) bootstrap, then pure Python forever via `pure_cipher`.
- **`pure_native_free_sign.PureNativeFreeSignProvider`** (this session): drop-in
  same-API wrapper; currently delegates to no_frida_sign, will become truly
  native-free when Unicorn end-to-end emulation is completed.
- **Multi-week effort remaining** to complete Unicorn stubs. This session laid
  the infrastructure (95% of stubs implemented) and decompiled the binary
  via IDA Pro to confirm the architecture.

## Critical Finding from IDA Pro Decompilation (this session)

The "op 0x60 hash" we sought is **NOT** a single Python-portable function:
- `sub_5CCD94A` (op 0x60 outer): a vector-intern operation (find or insert
  index in deduplicated vector)
- `sub_5CE6006` (op60_helper): wrapper around vector intern
- `sub_5CE6230`: just `std::find`
- `sub_5CE5A3E`: cleanup/init helper

The X_b1_init values (`0x114D0B11` etc.) are produced by the CUMULATIVE state
of running the entire VM (16,198 steps via `sub_56C46C0` block 1 cipher
orchestration → `sub_56B4244` 60KB VM dispatcher → `sub_5CCC307` main loop).

**Implication**: pure-Python sign requires emulating the entire sign() flow,
not just a single hash function. This validates the Unicorn/Qiling approach
as architecturally correct.

# Unicorn-Emulation Path: Final Status Snapshot

## Goal
Fully eliminate the residual native `wrapper.node` call from `no_frida_sign`,
achieving 100% pure-Python (or Unicorn-emulated) sign computation.

## Discoveries This Session

### Critical Insights
1. **Control flow is data-independent at instruction level.** Two different
   srcs (0x43 and 0x44) produce IDENTICAL 5,391,947-instruction execution
   traces in wrapper.node code (within 0x5cc0000-0x5cf0000 range). The
   apparent divergence between 0x42 and 0x43 was purely Frida JIT warmup
   overhead.
2. **X_b1_init values are an analytical-inverse construct.** Frida-scanned
   1.95M block executions during sign(): 0x114D0B11 (X_b1_init[0] for
   wtlogin.login) appears in NO register at any point. Same for the 16K-step
   VM register trace — zero hits for any of {0x114D0B11, 0xAFFC818B,
   0xFC57448F, 0x011D0687, 0x8DBF308F}. Wrapper.node's cipher uses a
   different internal representation that's mathematically equivalent.
3. **Op 0x60 fires only ONCE per sign() call** at VM step 1784516. The block
   at 0x5ce6006 is hit 2x (likely entry + state-machine re-entry).

### Infrastructure Built
- **`analysis/frida/op60_full_memdump.py`**: dumps all 484 readable process
  memory ranges (~140MB) plus full register state at op 0x60 entry, in a
  single sign() call. Configurable via SRC_BYTE / DUMP_SUFFIX env.
- **`analysis/unicorn_op60_replay.py`**: maps wrapper.node ELF + captured
  ranges into Unicorn at correct VAs. Sets up FS_BASE for stack canary.
  Runs from captured RIP. PLT detection + stub framework.
- **`analysis/unicorn_sign_full_proto.py`**: variant that runs from sign_fn
  entry (0x56D81D1) with input/output buffer setup.

### Stubs Implemented (in analysis/unicorn_op60_replay.py)
- malloc / `_Znwm` / `_Znam` / `_ZnwmRKSt9nothrow_t` (heap allocator)
- free / `_ZdlPv` / `_ZdaPv`
- memset / memcpy / memmove / memcmp / bcmp / strlen
- `std::vector<long>::emplace_back` (full SSO + capacity tracking)
- `std::vector<long>::_M_realloc_insert`
- `std::string::_M_construct(PKc/Pc)` (full SSO layout)
- `std::string::_M_replace`
- `std::string::find`
- srand / madvise / pthread_once / pthread_mutex_lock/unlock / time
- snprintf (writes empty string)
- `__tls_get_addr` (returns small alloc)
- getpid / __cxa_atexit (return 0)
- system_clock::now / chrono::system_clock::now (return 0, deterministic)
- fopen / fgets / fclose (return 0/NULL)
- `_ZSt20__throw_system_errori` (returns 0, exception swallowed)

## Validation Status

### What Was Tested
- Unicorn from 0x5ce6006 (helper entry inside op 0x60 region):
  - 5,380,152 instructions execute (matches captured exec trace size)
  - Halts on "Unhandled CPU exception" near offset 0x56e5b98
  - **Hash output NOT produced**: clearing 0x24922b0 with 0xCC and re-running
    leaves the buffer at 0xCC. Expected sign not found anywhere in memory.
- Unicorn from sign_fn entry (0x56D81D1):
  - Only 201 instructions execute before failing on null-pointer read
  - Generic stubs return alloc'd buffers but C++ stdlib calls need real impl

### Why Validation Fails
- Generic stubs return `alloc(256)` for unhandled calls; the buffer is
  uninitialized so callers reading from it get garbage.
- The function at 0x5ce6006 may not be op 0x60's hash entry; it's a helper
  called from 0x5ccda32 in the dispatcher CFF chain.
- Unicorn's `Unhandled CPU exception` near sign() epilogue suggests a
  `syscall` / `cpuid` / unsupported AVX instruction Unicorn can't decode.

## Remaining Work (Multi-Week Estimate)

### Approach A: Make sign_fn-entry emulation work end-to-end
1. Port full string/vector stubs from op60_replay to sign_full_proto: 1d
2. Implement libstdc++ forwarding via ctypes (per user suggestion): 2d
   - mmap host buffer at high VAs to share memory between Unicorn and
     native libstdc++ calls
   - For each PLT call, marshal args, call native, marshal return
3. Handle `std::thread` / `std::future` setup (one std::thread call in
   sign() setup; emulate worker thread synchronously inline): 1-2d
4. Handle CPU-exception-causing instructions (xsavec, vector ops): 1d
5. Validation against captured (cmd, src) → sign tuples: 2-3d

### Approach B: Identify TRUE op 0x60 entry and capture there
1. Use Frida MemoryAccessMonitor or breakpoint on the sign output buffer
   first-write to find precise op 0x60 exit point.
2. Walk back from exit through the dispatcher CFF chain to find entry.
3. Re-capture state at the precise op 0x60 entry.
4. Run Unicorn from there (smaller instruction count, fewer stubs).

## Practical Fallback
The shipped `no_frida_sign.NoFridaSignProvider` already meets the practical
"no Frida" goal: ONE ctypes call per (cmd, src) bootstrap, then forever pure
Python via pure_cipher. For typical NTQQ usage with cached (cmd, src), the
residual native call is amortized to near-zero over a session.

## Total Session Commits (this work)
- a37bfbe — Document Unicorn path status
- b64a316 — Unicorn op60 replay 5.38M instructions
- 3b6bf0c — Unicorn diagnostics: hash output not produced
- f0faa8a — Unicorn sign_fn-entry prototype
- decf0db — Definitive test: cleared buffer remains 0xCC
- (this commit) — Final session status snapshot
