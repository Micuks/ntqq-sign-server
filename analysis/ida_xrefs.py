"""Extract callgraph: what does sub_56C46C0 call? Find xrefs to op60_helper
to identify op 0x60's actual handler."""
import idapro, os, sys, time

WRAPPER = '/mnt/data1/wuql/services/ntqq-sign-server/wrapper.node'

def main():
    os.chdir('/tmp')
    print(f"[+] Opening cached database...")
    t0 = time.time()
    ret = idapro.open_database(WRAPPER, run_auto_analysis=False)
    if ret != 0: return 1
    print(f"[+] Open took {time.time()-t0:.1f}s")

    import ida_funcs, idautils, ida_xref, ida_name, ida_bytes

    # Find all callers of sub_5CE6006 (op60_helper)
    print(f"\n[+] Callers of sub_5CE6006 (op60_helper @ 0x5CE6006):")
    for ref in idautils.CodeRefsTo(0x5CE6006, 0):
        f = ida_funcs.get_func(ref)
        nm = ida_funcs.get_func_name(f.start_ea) if f else '?'
        print(f"    from 0x{ref:x} in {nm} (0x{f.start_ea:x})")

    # All functions called from sub_56C46C0
    print(f"\n[+] Functions called from sub_56C46C0 (block 1 cipher):")
    func = ida_funcs.get_func(0x56C46C0)
    callees = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            target_func = ida_funcs.get_func(ref)
            if target_func and target_func.start_ea != func.start_ea:
                callees.add(target_func.start_ea)
    print(f"    {len(callees)} unique callees")
    for c in sorted(callees):
        nm = ida_funcs.get_func_name(c)
        cf = ida_funcs.get_func(c)
        sz = cf.end_ea - cf.start_ea if cf else 0
        # Mark interesting ones
        marker = ''
        if 0x5cc0000 <= c < 0x5cf0000: marker = '  <-- IN OP60 REGION!'
        if c == 0x5CE6006: marker = '  <-- op60_helper!'
        print(f"    0x{c:x}  {nm}  size=0x{sz:x}{marker}")

    # What functions live in 0x5cc0000-0x5cf0000? These are the VM ops
    print(f"\n[+] Functions in op 0x60 region (0x5cc0000-0x5cf0000):")
    count = 0
    for ea in idautils.Functions(0x5cc0000, 0x5cf0000):
        f = ida_funcs.get_func(ea)
        sz = f.end_ea - f.start_ea
        # Count xrefs to it
        nrefs = sum(1 for _ in idautils.CodeRefsTo(ea, 0))
        if count < 30:
            print(f"    0x{ea:x}  size=0x{sz:x}  nrefs={nrefs}")
        count += 1
    print(f"    Total functions in region: {count}")

    idapro.close_database(save=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
