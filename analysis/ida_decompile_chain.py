"""Follow-up: decompile the actual crypto functions called from sign_fn and
op60_helper. Uses the already-analyzed wrapper.node.i64 database (so this
runs in seconds, not 30 minutes).
"""
import idapro
import os, sys, time

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
OUT_PSEUDO = '/mnt/data1/wuql/services/ntqq-sign-server/analysis/op60_chain_pseudo.c'

# Functions called from sign_fn (the main crypto chain) and op60_helper (hash)
TARGETS = {
    'sub_56C46C0': 0x56C46C0,  # sign_fn calls this; processes block 1?
    'sub_56C3008': 0x56C3008,  # sign_fn calls this; processes block 2?
    'sub_56B4244': 0x56B4244,  # sign_fn calls this; finalize?
    'sub_5CE6230': 0x5CE6230,  # op60_helper calls this — the actual hash mix
    'sub_5CE6006': 0x5CE6006,  # op60_helper itself (already known)
}


def main():
    os.chdir('/tmp')
    print(f"[+] Opening {WRAPPER} (using cached .i64)...")
    t0 = time.time()
    ret = idapro.open_database(WRAPPER, run_auto_analysis=False)
    if ret != 0:
        print(f"[!] open_database failed: {ret}")
        return 1
    print(f"[+] Open took {time.time()-t0:.1f}s")

    import ida_funcs, ida_hexrays, ida_xref, idautils

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] hex-rays plugin failed to init")
        idapro.close_database(save=False)
        return 1

    # Decompile each target
    out = []
    for label, ea in TARGETS.items():
        f = ida_funcs.get_func(ea)
        if not f:
            print(f"[+] No function at 0x{ea:x}, force-creating...")
            ida_funcs.add_func(ea)
            f = ida_funcs.get_func(ea)
        if not f:
            print(f"[!] Still no function at 0x{ea:x}")
            continue
        size = f.end_ea - f.start_ea
        print(f"[+] Decompiling {label} at 0x{ea:x} (size 0x{size:x})...")
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                out.append(f"// ===== {label} @ 0x{ea:x} (size 0x{size:x}) =====\n{cfunc}")
                # Also list xrefs to this function (who calls it)
                callers = list(idautils.CodeRefsTo(ea, 0))
                print(f"  decompiled OK; {len(callers)} callers")
            else:
                print(f"  decompile returned None")
        except ida_hexrays.DecompilationFailure as e:
            print(f"  FAILED: {e}")

    with open(OUT_PSEUDO, 'w') as f:
        f.write('\n\n'.join(out))
    print(f"[+] Saved to {OUT_PSEUDO} ({sum(len(s) for s in out)} chars)")

    # Also identify what sub_5CE6230 calls
    print("\n[+] Functions called from sub_5CE6230 (the hash mixer):")
    for ref in idautils.FuncItems(0x5CE6230):
        # This is iterating instructions; check for calls
        pass

    idapro.close_database(save=False)  # don't re-save db
    print(f"[+] Total time: {time.time()-t0:.1f}s")
    return 0


if __name__ == '__main__':
    sys.exit(main())
