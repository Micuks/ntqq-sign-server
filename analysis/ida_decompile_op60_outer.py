"""Decompile sub_5CCD94A (op 0x60 outer dispatcher) and sub_5CCC307 (VM main loop)
plus walk callers/callees to find the actual hash function."""
import idapro, os, sys, time

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
OUT = '/mnt/data1/wuql/services/ntqq-sign-server/analysis/op60_outer_pseudo.c'

# The chain we discovered: sign_fn → 56C46C0 → 56B4244 → 5CCC307 → 5CCD94A → 5CE6006
TARGETS = {
    'sub_5CCC307_vm_dispatcher': 0x5CCC307,
    'sub_5CCD94A_op60_outer': 0x5CCD94A,
    'sub_56B4244_partial': 0x56B4244,  # 60KB — too big to decompile maybe
}


def main():
    os.chdir('/tmp')
    print(f"[+] Opening cached database...")
    t0 = time.time()
    ret = idapro.open_database(WRAPPER, run_auto_analysis=False)
    if ret != 0: return 1
    print(f"[+] Open took {time.time()-t0:.1f}s")

    import ida_funcs, ida_hexrays, idautils

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] hex-rays init failed"); return 1

    out = []
    for label, ea in TARGETS.items():
        f = ida_funcs.get_func(ea)
        if not f: continue
        sz = f.end_ea - f.start_ea
        # Skip the huge sub_56B4244 — too slow
        if sz > 0x4000:
            print(f"[+] Skipping {label} (size 0x{sz:x} too big)")
            # But list its callees
            callees = set()
            for head in idautils.Heads(f.start_ea, f.end_ea):
                for ref in idautils.CodeRefsFrom(head, 0):
                    tf = ida_funcs.get_func(ref)
                    if tf and tf.start_ea != f.start_ea:
                        callees.add(tf.start_ea)
            print(f"  {label} callees: {len(callees)}")
            for c in sorted(callees):
                cf = ida_funcs.get_func(c)
                csz = cf.end_ea - cf.start_ea if cf else 0
                marker = ''
                if 0x5cd0000 <= c < 0x5ce0000: marker = '  <-- 0x5CD region'
                if 0x5ce0000 <= c < 0x5cf0000: marker = '  <-- 0x5CE region (op60!)'
                print(f"    0x{c:x}  size=0x{csz:x}{marker}")
            continue
        print(f"[+] Decompiling {label} at 0x{ea:x} (size 0x{sz:x})...")
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                out.append(f"// ===== {label} @ 0x{ea:x} (size 0x{sz:x}) =====\n{cfunc}")
                # List callees
                callees = set()
                for head in idautils.Heads(f.start_ea, f.end_ea):
                    for ref in idautils.CodeRefsFrom(head, 0):
                        tf = ida_funcs.get_func(ref)
                        if tf and tf.start_ea != f.start_ea:
                            callees.add(tf.start_ea)
                callees_str = '\n'.join(f"//    0x{c:x} (size 0x{ida_funcs.get_func(c).end_ea-ida_funcs.get_func(c).start_ea:x})"
                                       for c in sorted(callees))
                out.append(f"// callees of {label}:\n{callees_str}")
                print(f"  decompiled OK ({len(str(cfunc))} chars, {len(callees)} callees)")
        except Exception as e:
            print(f"  FAILED: {e}")

    with open(OUT, 'w') as f:
        f.write('\n\n'.join(out))
    print(f"[+] Saved to {OUT}")
    idapro.close_database(save=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
