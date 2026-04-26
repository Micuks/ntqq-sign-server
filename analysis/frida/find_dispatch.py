#!/usr/bin/env python3
"""Find the VM dispatch instruction in current wrapper.node.
The dispatch instruction executes ~16,186 times per sign() call (one per VM step).
Use Stalker exec events with sampling to find it.

Key signature: most-executed instruction inside sign() that ALSO has a specific
register-read pattern (rax=opcode, rbp-0x280=pc_ptr, r14+0x10=reg_array_ptr).
"""
import frida, subprocess, os, time
from collections import Counter

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let inside = false;
let tid = null;
let execCounts = {};
let totalEvents = 0;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        execCounts = {};
        totalEvents = 0;
        Stalker.follow(tid, {
            events: { exec: true },
            onReceive: function(events) {
                const parsed = Stalker.parse(events);
                for (const e of parsed) {
                    // exec event: ['exec', address]
                    if (e[0] === 'exec') {
                        const k = e[1].toString();
                        execCounts[k] = (execCounts[k] || 0) + 1;
                        totalEvents++;
                    }
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(e) {}
        inside = false;
        // Find top by count
        const entries = [];
        for (const k in execCounts) entries.push([k, execCounts[k]]);
        entries.sort((a, b) => b[1] - a[1]);
        const top = entries.slice(0, 30).map(([k, c]) => {
            try {
                const off = ptr(k).sub(WRAPPER_BASE);
                const io = off.toInt32();
                if (io >= 0 && io < 0x10000000) return ['w+0x' + off.toString(16), c];
            } catch(e) {}
            return [k, c];
        });
        send({type: 'done', totalEvents: totalEvents, totalUnique: entries.length, top: top});
    }
});

send({type: 'ready'});
"""


def spawn():
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
    nm = ctypes.c_void_p.from_address(info + 8).value
    if nm:
        try:
            if "wrapper.node" in ctypes.string_at(nm).decode():
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
def sign_once(src_byte=0, seq=1, ctr=100, cmd='wtlogin.login'):
    sb = (ctypes.c_ubyte * 1)(src_byte)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = ctr
    sf(cmd.encode(), sb, 1, seq, out)
    raw = bytes(out)
    return raw[0x200:0x200+raw[0x2FF]]
_ = sign_once(0)
print('WARM_DONE', flush=True)
for line in sys.stdin:
    line = line.strip()
    if line == 'SIGN':
        r = sign_once(0)
        print(f'SIGN_RESULT={r.hex()}', flush=True)
    elif line == 'EXIT': break
"""
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/libfaketime_zero.so'
    return subprocess.Popen(['python3','-c',helper],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, text=True, bufsize=1)


def main():
    p = spawn()
    base = None
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE': break
    assert base is not None

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)
    result = {}
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'done':
                result.update(pl)
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)

    print('[main] triggering sign...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line.startswith('SIGN_RESULT='):
            print(f'[helper] {line}')
            break
    time.sleep(8.0)

    print(f"\n[main] total exec events: {result.get('totalEvents', 0)}")
    print(f"[main] unique addresses: {result.get('totalUnique', 0)}")
    print(f"\nTop 30 most-executed instructions:")
    for addr, cnt in result.get('top', []):
        print(f"  {addr:30s}: {cnt}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
