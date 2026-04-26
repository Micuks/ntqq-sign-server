#!/usr/bin/env python3
"""Dump full 257-byte buffer at multiple points during sign() to understand its purpose."""
import frida, subprocess, os, time

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let insideSign = false;
let targetBuf = null;
let snapshots = [];
let hookCalls = 0;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        insideSign = true;
        targetBuf = null;
        snapshots = [];
        hookCalls = 0;
    },
    onLeave: function() {
        insideSign = false;
        // Final snapshot
        if (targetBuf) {
            try { snapshots.push({phase: 'final', buf: Array.from(new Uint8Array(targetBuf.readByteArray(257)))}); } catch(e) {}
        }
        send({type: 'done', snaps: snapshots});
    }
});

const mallocPlt = WRAPPER_BASE.add(0x7ae63b0);
Interceptor.attach(mallocPlt, {
    onEnter: function(args) {
        if (!insideSign) return;
        this.size = args[0].toInt32();
    },
    onLeave: function(ret) {
        if (!insideSign || this.size !== 257 || targetBuf !== null) return;
        targetBuf = ret;
        try {
            snapshots.push({phase: 'post-malloc', buf: Array.from(new Uint8Array(ret.readByteArray(257)))});
        } catch(e) {}
    }
});

// Periodic snapshots via hook_fn
const hookFn = WRAPPER_BASE.add(0x5cccffa);
Interceptor.attach(hookFn, {
    onEnter: function() {
        if (!insideSign || !targetBuf) return;
        hookCalls++;
        // Snapshot at key points: first 50 calls (catch early writes) + every 100
        if (hookCalls <= 50 || hookCalls % 100 === 0) {
            try {
                const buf = Array.from(new Uint8Array(targetBuf.readByteArray(32)));
                // Only snapshot if content differs from previous
                const last = snapshots.length ? snapshots[snapshots.length-1].buf.slice(0, 32) : null;
                let changed = !last;
                if (last) {
                    for (let i = 0; i < 32; i++) if (buf[i] !== last[i]) { changed = true; break; }
                }
                if (changed) {
                    snapshots.push({phase: 'hook_' + hookCalls, buf: buf});
                }
            } catch(e) {}
        }
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
                result['snaps'] = pl['snaps']
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    print('[main] triggering sign...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break
    time.sleep(2.0)

    snaps = result.get('snaps', [])
    print(f'\n[main] {len(snaps)} unique state snapshots of 257-byte buffer:')
    for i, s in enumerate(snaps):
        b = bytes(s['buf'])
        print(f"  [{i:3}] {s['phase']:15s}: {b[:32].hex()}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
