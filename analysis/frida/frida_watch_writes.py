#!/usr/bin/env python3
"""Monitor writes to the memory region where the 20-byte XOR stream lives.
Identify which function writes those bytes."""
import frida, subprocess, os, time

TARGET_XOR = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const HOOK_FN = WRAPPER_BASE.add(0x5cccffa);
const TARGET_STR = '%TARGET_HEX_SPACED%';

let insideSign = false;
let callIdx = 0;
let foundAddr = null;
let rwRanges = [];
let writeLog = [];

function addrToModOffset(addr) {
    try {
        const off = addr.sub(WRAPPER_BASE);
        const io = off.toInt32();
        if (io >= 0 && io < 0x10000000) return 'w+0x' + off.toString(16);
    } catch(e) {}
    return addr.toString();
}

Interceptor.attach(SIGN_FN, {
    onEnter: function(args) {
        insideSign = true;
        callIdx = 0;
        writeLog = [];
        rwRanges = Process.enumerateRanges({protection: 'rw-', coalesce: true})
                    .filter(r => r.size < 0x2000000 && r.size > 0x1000)
                    .slice(0, 200);
    },
    onLeave: function() {
        insideSign = false;
        if (foundAddr) {
            try { MemoryAccessMonitor.disable(); } catch(e) {}
        }
        send({type: 'sign_done', writeLogLen: writeLog.length});
        send({type: 'writes', writes: writeLog});
    }
});

Interceptor.attach(HOOK_FN, {
    onEnter: function(args) {
        if (!insideSign) return;
        callIdx++;
        // Scan less frequently, and only until found
        if (foundAddr !== null) return;
        if (callIdx % 20 !== 0) return;
        for (const r of rwRanges) {
            try {
                const hits = Memory.scanSync(r.base, r.size, TARGET_STR);
                if (hits.length > 0) {
                    foundAddr = hits[0].address;
                    // Dump surrounding region
                    try {
                        const ctx = Array.from(new Uint8Array(foundAddr.sub(32).readByteArray(128)));
                        send({type: 'found', callIdx: callIdx, addr: foundAddr.toString(), context: ctx});
                    } catch(e) {
                        send({type: 'found', callIdx: callIdx, addr: foundAddr.toString(), context: null});
                    }
                    return;
                }
            } catch(e) {}
        }
    }
});

send({type: 'ready'});

// Separate call: after finding the address, trigger another sign that uses MAM on that region
rpc.exports = {
    monitor: function(addr_hex, size) {
        try {
            const addr = ptr(addr_hex);
            foundAddr = addr;  // set so we don't rescan
            MemoryAccessMonitor.enable([{base: addr, size: size}], {
                onAccess: function(details) {
                    if (!insideSign) return;
                    let bt = [];
                    try {
                        bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .slice(0, 6).map(addrToModOffset);
                    } catch(e) {}
                    writeLog.push({
                        op: details.operation,
                        offset: details.address.sub(addr).toInt32(),
                        from: details.from ? addrToModOffset(details.from) : null,
                        bt: bt
                    });
                    if (writeLog.length > 500) MemoryAccessMonitor.disable();
                }
            });
            send({type: 'log', msg: 'MAM enabled on ' + addr + ' + ' + size});
            return true;
        } catch(e) {
            send({type: 'log', msg: 'MAM error: ' + e.message});
            return false;
        }
    }
};
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
    tgt_spaced = ' '.join(f'{b:02x}' for b in TARGET_XOR)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1)) \
                .replace('%TARGET_HEX_SPACED%', tgt_spaced)
    script = session.create_script(src)

    result = {}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            t = pl.get('type')
            if t == 'log': print(f"[frida] {pl['msg']}")
            elif t == 'found':
                result['addr'] = pl['addr']
                print(f"[frida] found at call #{pl['callIdx']}, addr={pl['addr']}")
                if pl.get('context'):
                    ctx_bytes = bytes(pl['context'])
                    print(f"  context: {ctx_bytes.hex()}")
            elif t == 'writes':
                result['writes'] = pl['writes']
            elif t == 'sign_done':
                result['done'] = True
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    # First sign: find the address
    print('[main] sign #1 (find address)...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break
    time.sleep(1.0)

    if 'addr' not in result:
        print('Pattern not found.')
        p.terminate(); return

    # Second sign: monitor writes to that address
    print(f'\n[main] Setting up MAM on {result["addr"]}...')
    ok = script.exports_sync.monitor(result['addr'], 64)
    print(f'[main] MAM setup: {ok}')
    result['writes'] = []

    print('[main] sign #2 (monitor)...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break
    time.sleep(2.0)

    writes = result.get('writes', [])
    print(f"\n[main] Access events captured: {len(writes)}")
    # Show first 20 events
    for i, ev in enumerate(writes[:30]):
        print(f"  [{i}] {ev['op']} offset={ev['offset']:3d} from={ev['from']}")
        if ev.get('bt'):
            for b in ev['bt'][:3]:
                print(f"      {b}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
