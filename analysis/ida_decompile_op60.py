"""IDA Pro headless decompilation of op 0x60's hash function region.

Strategy:
1. Open wrapper.node (auto-analysis OFF for speed; ~30s instead of ~30min)
2. Force-create function at sign_fn entry (0x56D81D1) and op 0x60 helper (0x5ce6006)
3. Run focused autoanalysis on these functions
4. Apply gooMBA OLLVM-deobfuscator plugin on op 0x60
5. Use ida_hexrays.decompile() to get C-like pseudocode
6. Save to analysis/op60_pseudo.c
"""
import idapro
import os, sys, time

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
SIGN_FN_OFFSET = 0x56D81D1
OP60_HELPER_OFFSET = 0x5ce6006
OUT_PSEUDO = '/mnt/data1/wuql/services/ntqq-sign-server/analysis/op60_pseudo.c'


def main():
    os.chdir('/tmp')
    print(f"[+] Opening {WRAPPER}...")
    t0 = time.time()
    # WITH autoanalysis to get xrefs
    ret = idapro.open_database(WRAPPER, run_auto_analysis=True)
    if ret != 0:
        print(f"[!] open_database failed: {ret}")
        return 1
    print(f"[+] Open with autoanalysis took {time.time()-t0:.1f}s")

    import ida_funcs, ida_segment, ida_bytes, ida_kernwin, ida_hexrays, ida_loader

    # Initialize hex-rays decompiler
    if not ida_hexrays.init_hexrays_plugin():
        print("[!] hex-rays plugin failed to init")
        idapro.close_database(save=False)
        return 1
    print(f"[+] Hex-Rays initialized: {ida_hexrays.get_hexrays_version()}")

    # Force-create function at sign_fn entry
    if not ida_funcs.get_func(SIGN_FN_OFFSET):
        print(f"[+] Adding function at sign_fn 0x{SIGN_FN_OFFSET:x}")
        ida_funcs.add_func(SIGN_FN_OFFSET)
    if not ida_funcs.get_func(OP60_HELPER_OFFSET):
        print(f"[+] Adding function at op 0x60 helper 0x{OP60_HELPER_OFFSET:x}")
        ida_funcs.add_func(OP60_HELPER_OFFSET)

    # Decompile sign_fn
    out = []
    for label, ea in [('sign_fn', SIGN_FN_OFFSET), ('op60_helper', OP60_HELPER_OFFSET)]:
        f = ida_funcs.get_func(ea)
        if not f:
            print(f"[!] No function at 0x{ea:x}")
            continue
        print(f"[+] Decompiling {label} at 0x{ea:x} (size 0x{f.end_ea - f.start_ea:x})...")
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                out.append(f"// ===== {label} @ 0x{ea:x} =====\n{cfunc}")
                print(f"  decompiled OK")
            else:
                print(f"  decompile returned None")
        except ida_hexrays.DecompilationFailure as e:
            print(f"  FAILED: {e}")

    # Save output
    with open(OUT_PSEUDO, 'w') as f:
        f.write('\n\n'.join(out))
    print(f"[+] Saved to {OUT_PSEUDO} ({sum(len(s) for s in out)} chars)")

    idapro.close_database(save=True)
    print(f"[+] Total time: {time.time()-t0:.1f}s")
    return 0


if __name__ == '__main__':
    sys.exit(main())
