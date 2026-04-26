#!/usr/bin/env python3
"""Use Frida to disassemble code around the sign function and known hot blocks."""
import frida, subprocess, os, time

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');

function disasmAt(off, count) {
    const addr = WRAPPER_BASE.add(off);
    let cur = addr;
    const out = [];
    for (let i = 0; i < count; i++) {
        try {
            const ins = Instruction.parse(cur);
            const o = cur.sub(WRAPPER_BASE).toInt32();
            out.push(`w+0x${o.toString(16)}: ${ins.mnemonic} ${ins.opStr}`);
            cur = ins.next;
        } catch(e) {
            out.push(`w+0x${cur.sub(WRAPPER_BASE).toInt32().toString(16)}: <invalid>`);
            break;
        }
    }
    return out;
}

const targets = [
    {label: 'around sign entry 0x56D81D1', off: 0x56D81D1, count: 20},
    {label: 'sign+0x87D7 (old dispatch offset)', off: 0x56D81D1+0x87D7, count: 20},
    {label: 'hot block w+0x56b4a8b (peak from stalker)', off: 0x56b4a8b, count: 20},
    {label: 'top byte-load helper w+0x5cccffa', off: 0x5cccffa, count: 30},
    {label: 'around malloc caller w+0x5cd56d0', off: 0x5cd56d0, count: 20},
    // Search for the dispatch in CFF blocks. CFF dispatch typically uses
    // a comparison tree on a single register. Look for cmp eax patterns.
];
for (const t of targets) {
    send({type: 'disasm', label: t.label, lines: disasmAt(t.off, t.count)});
}
send({type: 'done'});
"""


def spawn():
    helper = r"""
import ctypes, os, sys, time
os.chdir('/mnt/data1/wuql/services/ntqq-sign-server')
for lib in ["libgnutls.so.30","libssl.so.3","libcrypto.so.3","libpsl.so.5",
            "libnghttp2.so.14","libbrotlidec.so.1","libzstd.so.1",
            "libldap.so","liblber.so","libcurl.so.4","librtmp.so.1",
            "libssh2.so.1","./libsymbols.so"]:
    try: ctypes.CDLL(lib, mode=ctypes.RTLD_GLOBAL)
    except: pass
ctypes.CDLL("./wrapper.node", mode=1)
libc = ctypes.CDLL(None)
base = ctypes.c_ulong(0)
CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
@CB
def cb(info, sz, data):
    addr = ctypes.c_ulong.from_address(info).value
    nm = ctypes.c_void_p.from_address(info + 8).value
    if nm:
        try:
            if "wrapper.node" in ctypes.string_at(nm).decode():
                base.value = addr; return 1
        except: pass
    return 0
libc.dl_iterate_phdr(cb, None)
print(f'BASE={hex(base.value)}', flush=True)
print('READY', flush=True)
time.sleep(120)
"""
    return subprocess.Popen(['python3','-c',helper],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1)


def main():
    p = spawn()
    base = None
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'READY': break
    assert base is not None

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base))
    script = session.create_script(src)
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'disasm':
                print(f"\n=== {pl['label']} ===")
                for line in pl['lines']:
                    print(f"  {line}")
            elif pl.get('type') == 'done':
                done[0] = True
        elif msg['type'] == 'error':
            print(f"[error] {msg.get('description','')[:300]}")
    script.on('message', on_msg)
    script.load()
    deadline = time.time() + 10
    while not done[0] and time.time() < deadline:
        time.sleep(0.5)

    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
