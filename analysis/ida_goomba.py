"""Apply gooMBA OLLVM-deobfuscator on the heavily-CFF-obfuscated functions
in wrapper.node, then re-decompile.
"""
import idapro
import os, sys, time

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'
OUT_PSEUDO = '/mnt/data1/wuql/services/ntqq-sign-server/analysis/op60_deobf_pseudo.c'

TARGETS = {
    'sign_fn': 0x56D81D1,
    'sub_56C46C0': 0x56C46C0,  # block 1 cipher (likely contains hash)
    'sub_56C3008': 0x56C3008,
    'sub_5CE6006': 0x5CE6006,  # op60_helper (intern)
}


def main():
    os.chdir('/tmp')
    print(f"[+] Opening cached database...")
    t0 = time.time()
    ret = idapro.open_database(WRAPPER, run_auto_analysis=False)
    if ret != 0:
        print(f"[!] open failed: {ret}"); return 1
    print(f"[+] Open took {time.time()-t0:.1f}s")

    import ida_funcs, ida_hexrays, ida_loader, ida_kernwin, ida_idaapi

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] hex-rays init failed"); return 1

    # Try to find and load gooMBA plugin
    plugin_path = '/mnt/data1/wuql/idapro/plugins/goomba.so'
    print(f"[+] gooMBA plugin path: {plugin_path}")
    print(f"     exists: {os.path.exists(plugin_path)}")

    # Check if already loaded by listing plugins
    # Try ida_loader.load_plugin
    try:
        plg = ida_loader.load_plugin(plugin_path)
        print(f"[+] load_plugin result: {plg}")
    except Exception as e:
        print(f"[!] load_plugin failed: {e}")

    # Try processing 'process function' (gooMBA's typical command)
    # gooMBA exposes via Hex-Rays microcode_filter API
    # Let's check if there's a registered microcode filter
    print(f"[+] Trying to apply gooMBA...")

    # Decompile each function, with goomba should clean up
    out = []
    for label, ea in TARGETS.items():
        f = ida_funcs.get_func(ea)
        if not f:
            print(f"[!] no func at 0x{ea:x}"); continue
        print(f"[+] Decompiling {label} at 0x{ea:x} (size 0x{f.end_ea-f.start_ea:x})...")
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                out.append(f"// ===== {label} @ 0x{ea:x} =====\n{cfunc}")
                print(f"  decompiled OK, {len(str(cfunc))} chars")
            else:
                print(f"  None")
        except Exception as e:
            print(f"  FAILED: {e}")

    with open(OUT_PSEUDO, 'w') as f:
        f.write('\n\n'.join(out))
    print(f"[+] Saved to {OUT_PSEUDO}")
    idapro.close_database(save=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
