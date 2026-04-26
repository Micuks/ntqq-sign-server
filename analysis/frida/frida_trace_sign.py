#!/usr/bin/env python3
"""Frida-based memory tracer for wrapper.node sign function.

Captures memcpy/memmove/memset/malloc during sign() call and detects
when the 20-byte XOR stream pattern is seen in memory operations.
When detected, dumps the backtrace to identify the producer.
"""
import frida
import subprocess
import sys
import time
import os
import json

TARGET_XOR = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

def make_script(base_int, offset_int, target_hex):
    return r"""
'use strict';

const WRAPPER_BASE = ptr('""" + hex(base_int) + r"""');
const SIGN_FN = ptr('""" + hex(base_int + offset_int) + r"""');
const TARGET = [""" + ','.join(str(b) for b in bytes.fromhex(target_hex)) + r"""];

let insideSign = false;
let tracker = {memcpy: 0, memset: 0, malloc: 0, free: 0, xor_hits: []};

send({type: 'log', msg: 'script loaded, wrapper base=' + WRAPPER_BASE + ', sign fn=' + SIGN_FN});

Interceptor.attach(SIGN_FN, {
    onEnter: function (args) {
        insideSign = true;
        tracker = {memcpy: 0, memset: 0, malloc: 0, free: 0, xor_hits: []};
        send({type: 'log', msg: 'sign() enter, src_len=' + args[2].toInt32()});
    },
    onLeave: function (retval) {
        insideSign = false;
        send({type: 'sign_done', data: {
            memcpy: tracker.memcpy, memset: tracker.memset,
            malloc: tracker.malloc, free: tracker.free,
            xor_hits_count: tracker.xor_hits.length,
        }});
    }
});

function checkPattern(addr, n) {
    if (n < 20) return false;
    try {
        const b = new Uint8Array(addr.readByteArray(20));
        for (let i = 0; i < 20; i++) if (b[i] !== TARGET[i]) return false;
        return true;
    } catch (e) { return false; }
}

function safeResolve(name) {
    try { return Module.getGlobalExportByName(name); } catch(e) {
        try { return Module.findGlobalExportByName(name); } catch(e2) {
            try { return Module.findExportByName(null, name); } catch(e3) {
                send({type: 'log', msg: 'could not resolve ' + name});
                return null;
            }
        }
    }
}
const memcpy = safeResolve('memcpy');
const memmove = safeResolve('memmove');
const memset = safeResolve('memset');
const malloc = safeResolve('malloc');
const free = safeResolve('free');
send({type: 'log', msg: 'resolved: memcpy=' + (memcpy||'null') + ' memmove=' + (memmove||'null') + ' malloc=' + (malloc||'null')});

function hookCopy(addr, name) {
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            if (!insideSign) return;
            tracker.memcpy++;
            const dst = args[0], src = args[1], n = args[2].toInt32();
            if (n < 20 || n > 2048) return;
            if (!checkPattern(src, n)) return;
            // Hit!
            let bt = [];
            try {
                bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(x => {
                        try {
                            const off = x.sub(WRAPPER_BASE);
                            return 'wrapper+0x' + off.toString(16);
                        } catch(e) { return x.toString(); }
                    });
            } catch(e) {}
            const hit = {event: name, dst: dst.toString(), src: src.toString(), n: n, backtrace: bt.slice(0, 15)};
            tracker.xor_hits.push(hit);
            send({type: 'xor_hit', hit: hit});
        }
    });
}

hookCopy(memcpy, 'memcpy');
hookCopy(memmove, 'memmove');

if (malloc) Interceptor.attach(malloc, {
    onEnter: function(args) { this.sz = args[0].toInt32(); },
    onLeave: function(ret) {
        if (insideSign && this.sz >= 16 && this.sz <= 1024) tracker.malloc++;
    }
});
if (free) Interceptor.attach(free, {
    onEnter: function() { if (insideSign) tracker.free++; }
});

send({type: 'log', msg: 'hooks installed'});
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
def sign_once(src_byte, seq=1, ctr=100, cmd='wtlogin.login'):
    src = bytes([src_byte])
    sb = (ctypes.c_ubyte * 1)(*src)
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
    elif line == 'EXIT':
        break
"""
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/libfaketime_zero.so'
    p = subprocess.Popen(['python3', '-c', helper],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, text=True, bufsize=1)
    return p


def main():
    p = spawn_target()
    base = None
    assert p.stdout is not None
    while True:
        line = p.stdout.readline()
        if not line: break
        line = line.strip()
        print(f'[helper] {line}')
        if line.startswith('BASE='):
            base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE':
            break
    assert base is not None
    print(f'[main] helper warmed up, BASE=0x{base:x}')

    session = frida.attach(p.pid)
    script_src = make_script(base, 0x56D81D1, TARGET_XOR.hex())
    script = session.create_script(script_src)

    messages = []
    def on_message(msg, data):
        if msg['type'] == 'send':
            payload = msg['payload']
            messages.append(payload)
            t = payload.get('type')
            if t == 'log':
                print(f"[frida] {payload['msg']}")
            elif t == 'xor_hit':
                h = payload['hit']
                print(f"\n*** XOR PATTERN MATCH: {h['event']} n={h['n']} src={h['src']} dst={h['dst']} ***")
                for bt in h['backtrace'][:12]:
                    print(f"    {bt}")
            elif t == 'sign_done':
                d = payload['data']
                print(f"[frida] sign done: {d['memcpy']} memcpy, {d['malloc']} malloc, {d['xor_hits_count']} xor hits")
        elif msg['type'] == 'error':
            print(f"[frida error] {msg}")

    script.on('message', on_message)
    script.load()

    time.sleep(0.5)  # let script init + hooks attach

    print('[main] triggering sign...')
    assert p.stdin is not None
    p.stdin.write('SIGN\n')
    p.stdin.flush()

    t = time.time()
    while time.time() - t < 15:
        line = p.stdout.readline()
        if not line: break
        line = line.strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='):
            break
    time.sleep(0.8)  # drain messages

    print("\n=== Final summary ===")
    hits = [m for m in messages if m.get('type') == 'xor_hit']
    print(f"XOR pattern hits: {len(hits)}")
    if hits:
        print("First hit backtrace:")
        for bt in hits[0]['hit']['backtrace']:
            print(f"  {bt}")

    p.stdin.write('EXIT\n')
    p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
