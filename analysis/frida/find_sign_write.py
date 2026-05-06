#!/usr/bin/env python3
"""Hook the OUT buffer (specifically OUT[0x200] where sign starts) and find
the instruction that writes the first byte of sign output. This gives us
a precise capture point right at the END of the cipher.
"""
import frida, subprocess, os, time, sys

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let writes_to_out = [];
let out_addr = null;

Interceptor.attach(SIGN_FN, {
    onEnter: function(args) {
        // arg0=cmd, arg1=src, arg2=src_len, arg3=seq, arg4=out
        out_addr = args[4];
        const out_sig_start = out_addr.add(0x200);
        const out_sig_end = out_addr.add(0x220);
        send({type:'log', msg: 'sign_fn entry, OUT=' + out_addr + ' sig at ' + out_sig_start});
        // Use MemoryAccessMonitor on this range
        try {
            MemoryAccessMonitor.enable([{base: out_sig_start, size: 0x20}], {
                onAccess: function(details) {
                    if (details.operation === 'write') {
                        const insn = details.from;
                        const insn_off = insn.sub(WRAPPER_BASE).toInt32();
                        const off_in_buf = details.address.sub(out_sig_start).toInt32();
                        writes_to_out.push({insn_off: insn_off, byte_off: off_in_buf});
                    }
                }
            });
        } catch(e) {
            send({type:'log', msg: 'monitor enable err: ' + e});
        }
    },
    onLeave: function() {
        try { MemoryAccessMonitor.disable(); } catch(_) {}
        send({type: 'writes', data: writes_to_out});
    }
});
send({type:'ready'});
"""


def spawn_target():
    helper = r"""
import ctypes, os, sys
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
    name_ptr = ctypes.c_void_p.from_address(info + 8).value
    if name_ptr:
        try:
            if "wrapper.node" in ctypes.string_at(name_ptr).decode():
                base.value = addr; return 1
        except: pass
    return 0
libc.dl_iterate_phdr(cb, None)
print(f'BASE={hex(base.value)}', flush=True)
SIGN_T = ctypes.CFUNCTYPE(ctypes.c_longlong, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte))
sf = SIGN_T(base.value + 0x56D81D1)
COUNTER = base.value + 0x7DD868C
sb = (ctypes.c_ubyte * 1)(0)
out = (ctypes.c_ubyte * 0x300)()
ctypes.c_uint32.from_address(COUNTER).value = 100
sf(b'wtlogin.login', sb, 1, 1, out)
print('WARM_DONE', flush=True)
for line in sys.stdin:
    if line.strip() == 'SIGN':
        ctypes.c_uint32.from_address(COUNTER).value = 100
        sf(b'wtlogin.login', sb, 1, 1, out)
        print('SIGN_RES=' + bytes(out)[0x200:0x220].hex(), flush=True)
    elif line.strip() == 'EXIT': break
"""
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/libfaketime_zero.so'
    return subprocess.Popen(['python3','-c',helper],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, text=True, bufsize=1)


def main():
    p = spawn_target()
    base = None
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE': break

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)

    state = {'writes': []}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'log': print(f"[frida] {pl['msg']}")
            elif pl.get('type') == 'writes':
                state['writes'] = pl['data']
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RES='): break
    time.sleep(2)

    print(f"\n[main] Writes to OUT[0x200:0x220]: {len(state['writes'])}")
    # Show first 30 writes
    for w in state['writes'][:30]:
        print(f"  insn 0x{w['insn_off']:x}  -> byte_off {w['byte_off']}")
    # Group by insn
    from collections import Counter
    by_insn = Counter(w['insn_off'] for w in state['writes'])
    print(f"\nUnique writing instructions: {len(by_insn)}")
    for insn, count in by_insn.most_common(10):
        print(f"  insn 0x{insn:x}: {count} writes")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
