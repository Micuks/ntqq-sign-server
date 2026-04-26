#!/usr/bin/env python3
"""Frida: after sign() completes, scan process heap for the 20-byte XOR stream
to find where it ended up in memory. Then on the next call, use
MemoryAccessMonitor to watch that exact region."""
import frida
import subprocess
import os
import time

TARGET_XOR = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const TARGET = [%TARGET%];
const TARGET_BYTES = new Uint8Array(TARGET);

send({type: 'log', msg: 'script loaded'});

let insideSign = false;
let signCallCount = 0;
let accessLog = [];
let xorRegions = [];

// Hook sign function
Interceptor.attach(SIGN_FN, {
    onEnter: function (args) {
        insideSign = true;
        signCallCount++;
        accessLog = [];
        send({type: 'log', msg: `sign() #${signCallCount} enter`});
    },
    onLeave: function (retval) {
        insideSign = false;
        send({type: 'sign_end', call: signCallCount});
    }
});

rpc.exports = {
    scanHeap: function() {
        // Scan all RW memory for the target pattern
        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: true});
        const hits = [];
        const targetStr = Array.from(TARGET_BYTES).map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
        for (const r of ranges) {
            if (r.size > 0x10000000) continue;  // skip huge ranges (JIT etc.)
            try {
                const found = Memory.scanSync(r.base, r.size, targetStr);
                for (const f of found) hits.push({addr: f.address.toString(), size: f.size});
            } catch(e) {}
        }
        return hits;
    },
    monitorAddr: function(addr_str, range_size) {
        const addr = ptr(addr_str);
        accessLog = [];
        const ranges = [{base: addr, size: range_size}];
        try {
            MemoryAccessMonitor.enable(ranges, {
                onAccess: function(details) {
                    if (!insideSign) return;
                    let bt = [];
                    try {
                        bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .slice(0, 8)
                            .map(x => {
                                try {
                                    const off = x.sub(WRAPPER_BASE);
                                    const io = off.toInt32();
                                    if (io >= 0 && io < 0x10000000) return 'wrapper+0x' + off.toString(16);
                                    return x.toString();
                                } catch(e) { return x.toString(); }
                            });
                    } catch(e) {}
                    accessLog.push({
                        op: details.operation,
                        addr: details.address.toString(),
                        offset: details.address.sub(addr).toInt32(),
                        from: details.from ? details.from.toString() : null,
                        bt: bt
                    });
                }
            });
            send({type: 'log', msg: 'MemoryAccessMonitor enabled on ' + addr + ' + ' + range_size});
            return true;
        } catch(e) {
            send({type: 'log', msg: 'monitor err: ' + e.message});
            return false;
        }
    },
    getAccessLog: function() {
        return accessLog;
    },
    disableMonitor: function() {
        try { MemoryAccessMonitor.disable(); return true; } catch(e) { return false; }
    }
};

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
    targets = ','.join(str(b) for b in TARGET_XOR)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1)).replace('%TARGET%', targets)
    script = session.create_script(src)

    messages = []
    def on_message(msg, data):
        if msg['type'] == 'send':
            messages.append(msg['payload'])
            t = msg['payload'].get('type')
            if t == 'log':
                print(f"[frida] {msg['payload']['msg']}")
            else:
                print(f"[frida] {msg['payload']}")
        elif msg['type'] == 'error':
            print(f"[frida error] {msg}")

    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    # Call sign once to get heap state
    print('[main] sign #1...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break

    time.sleep(0.5)

    # Scan for XOR pattern in heap
    print('[main] scanning heap for XOR pattern...')
    hits = script.exports_sync.scan_heap()
    print(f'[main] {len(hits)} hits for target pattern')
    for h in hits[:5]:
        print(f'  {h}')

    if not hits:
        print('Pattern not found in memory. The 20 bytes may have been freed already.')
        p.terminate(); return

    # Use first hit as target
    target_addr = hits[0]['addr']
    print(f'\n[main] Monitoring memory access at {target_addr}')
    ok = script.exports_sync.monitor_addr(target_addr, 64)
    if not ok:
        print('Monitor setup failed')
        p.terminate(); return

    # Trigger another sign with monitoring active
    print('[main] sign #2 with memory access monitor...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break

    time.sleep(1.0)

    # Get access log
    log = script.exports_sync.get_access_log()
    print(f'\n[main] Memory access events on XOR region: {len(log)}')
    for i, ev in enumerate(log[:30]):
        print(f'  [{i}] {ev["op"]} offset={ev["offset"]} from={ev["from"]}')
        if i < 5:
            for bt in ev['bt']:
                print(f'      {bt}')

    script.exports_sync.disable_monitor()
    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
