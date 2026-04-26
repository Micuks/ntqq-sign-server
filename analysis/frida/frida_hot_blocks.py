#!/usr/bin/env python3
"""Stalker with block events — find hot basic blocks (executed ~16,186 times during sign).
The real VM dispatch loop must be among them."""
import frida, subprocess, os, time
from collections import Counter

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let insideSign = false;
let tid = null;
let blockCounts = {};

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        insideSign = true;
        tid = Process.getCurrentThreadId();
        blockCounts = {};
        Stalker.follow(tid, {
            events: { block: true },
            onReceive: function(events) {
                // events is a buffer of block events
                const parsed = Stalker.parse(events);
                for (const e of parsed) {
                    // event: ['block', start, end]
                    if (e[0] === 'block') {
                        const key = e[1].toString();
                        blockCounts[key] = (blockCounts[key] || 0) + 1;
                    }
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(e) {}
        insideSign = false;
        // Top blocks by count
        const sorted = [];
        for (const k in blockCounts) sorted.push([k, blockCounts[k]]);
        sorted.sort((a, b) => b[1] - a[1]);
        // Convert to module-relative offsets
        const top = [];
        for (let i = 0; i < Math.min(40, sorted.length); i++) {
            const p = ptr(sorted[i][0]);
            try {
                const off = p.sub(WRAPPER_BASE);
                const io = off.toInt32();
                if (io >= 0 && io < 0x10000000) {
                    top.push(['w+0x' + off.toString(16), sorted[i][1]]);
                } else {
                    top.push([sorted[i][0], sorted[i][1]]);
                }
            } catch(e) { top.push([sorted[i][0], sorted[i][1]]); }
        }
        send({type: 'done', top: top, totalUnique: sorted.length});
    }
});

send({type: 'ready'});
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
    p = spawn_target()
    assert p.stdout and p.stdin
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
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'done':
                result.update(pl)
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    print('[main] triggering sign (slower due to block tracking)...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break
    time.sleep(5.0)

    top = result.get('top', [])
    print(f'\n[main] {result.get("totalUnique", 0)} unique blocks during sign')
    print(f'Top 40 by count:')
    for addr, cnt in top:
        print(f"  {addr:30s}: {cnt}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
