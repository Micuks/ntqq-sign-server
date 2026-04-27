#!/usr/bin/env python3
"""Use Stalker.transform with putCallout on EVERY instruction to count visits.
The dispatcher should be visited exactly 16186 times during sign (one per VM step).

We captured ~16186 by hooking byte-reads earlier; now find the single
instruction that's hit that many times.
"""
import frida, subprocess, os, time


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let inside = false;
let tid = null;
const counts = {};

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        for (const k in counts) delete counts[k];
        Stalker.follow(tid, {
            transform: function(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    const addrStr = ins.address.toString();
                    iter.putCallout(function(ctx) {
                        counts[addrStr] = (counts[addrStr] || 0) + 1;
                    });
                    iter.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(e) {}
        inside = false;
        // Find instructions hit close to 16186 times
        const candidates = [];
        for (const addr in counts) {
            const c = counts[addr];
            if (c >= 15000 && c <= 17000) {
                candidates.push([addr, c]);
            }
        }
        send({type: 'candidates', list: candidates});
        // Also send top 50 most-hit
        const sorted = [];
        for (const addr in counts) sorted.push([addr, counts[addr]]);
        sorted.sort((a, b) => b[1] - a[1]);
        send({type: 'top', list: sorted.slice(0, 50)});
        send({type: 'done'});
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
def sign_once(src_byte=0):
    sb = (ctypes.c_ubyte * 1)(src_byte)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = 100
    sf(b'wtlogin.login', sb, 1, 1, out)
    return bytes(out)[0x200:0x200+bytes(out)[0x2FF]]
_ = sign_once(0)
print('WARM_DONE', flush=True)
for line in sys.stdin:
    if line.strip() == 'SIGN':
        r = sign_once(0)
        print(f'SIGN_RESULT={r.hex()}', flush=True)
    elif line.strip() == 'EXIT': break
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

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)
    candidates = []
    top = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'candidates':
                candidates.extend(pl['list'])
            elif pl.get('type') == 'top':
                top.extend(pl['list'])
            elif pl.get('type') == 'done':
                done[0] = True
        elif msg['type'] == 'error':
            print(f"[error] {msg.get('description','')[:300]}")
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line.startswith('SIGN_RESULT='):
            print(f'[helper] {line}')
            break
    deadline = time.time() + 180
    while not done[0] and time.time() < deadline:
        time.sleep(1)

    print(f'\n=== Instructions hit 15000-17000 times (DISPATCHER candidates) ===')
    for addr, cnt in candidates:
        try:
            offset = int(addr, 16) - base
            print(f"  w+0x{offset:x}: {cnt}")
        except:
            print(f"  {addr}: {cnt}")

    print(f'\n=== Top 30 most-hit instructions ===')
    for addr, cnt in top[:30]:
        try:
            offset = int(addr, 16) - base
            print(f"  w+0x{offset:x}: {cnt}")
        except:
            print(f"  {addr}: {cnt}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
