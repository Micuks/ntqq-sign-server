#!/usr/bin/env python3
"""When we see malloc(size=257) (the buffer that will hold XOR stream),
immediately enable MemoryAccessMonitor on it to catch the writer."""
import frida, subprocess, os, time

TARGET_XOR = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const TARGET = [%XOR_BYTES%];

function rel(addr) {
    try {
        const off = addr.sub(WRAPPER_BASE);
        const io = off.toInt32();
        if (io >= 0 && io < 0x10000000) return 'w+0x' + off.toString(16);
    } catch(e) {}
    return addr.toString();
}

let insideSign = false;
let targetBufAddr = null;
let accessLog = [];
let monitoredSizes = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        insideSign = true;
        targetBufAddr = null;
        accessLog = [];
        monitoredSizes = [];
    },
    onLeave: function() {
        if (targetBufAddr) { try { MemoryAccessMonitor.disable(); } catch(e) {} }
        insideSign = false;
        send({type: 'done', log: accessLog, sizes: monitoredSizes});
    }
});

const mallocPlt = WRAPPER_BASE.add(0x7ae63b0);
Interceptor.attach(mallocPlt, {
    onEnter: function(args) {
        if (!insideSign) return;
        this.size = args[0].toInt32();
    },
    onLeave: function(ret) {
        if (!insideSign) return;
        // Specifically target size=257 buffers — that's the XOR stream buffer
        if (this.size !== 257) return;
        if (targetBufAddr !== null) {
            monitoredSizes.push({size: this.size, addr: ret.toString(), skipped: 'already monitoring'});
            return;
        }
        targetBufAddr = ret;
        monitoredSizes.push({size: this.size, addr: ret.toString()});
        try {
            MemoryAccessMonitor.enable([{base: ret, size: 64}], {
                onAccess: function(details) {
                    if (!insideSign) return;
                    let bt = [];
                    try {
                        bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .slice(0, 10).map(rel);
                    } catch(e) {}
                    // Read buffer state after access
                    let sample = null;
                    try { sample = Array.from(new Uint8Array(targetBufAddr.readByteArray(32))); } catch(e) {}
                    accessLog.push({
                        op: details.operation,
                        offset: details.address.sub(targetBufAddr).toInt32(),
                        from: details.from ? rel(details.from) : null,
                        bt: bt,
                        sample: sample
                    });
                }
            });
        } catch(e) { send({type: 'log', msg: 'MAM err: ' + e.message}); }
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
    xor_ints = ','.join(str(b) for b in TARGET_XOR)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1)) \
                .replace('%XOR_BYTES%', xor_ints)
    script = session.create_script(src)

    result = {}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'done':
                result['log'] = pl['log']; result['sizes'] = pl['sizes']
            elif pl.get('type') == 'log':
                print(f"[frida] {pl['msg']}")
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
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

    sizes = result.get('sizes', [])
    print(f'\n[main] {len(sizes)} size=257 allocs during sign:')
    for s in sizes[:5]: print(f'  {s}')

    log = result.get('log', [])
    print(f'\n[main] {len(log)} memory access events on 257-byte buffer:')
    for i, ev in enumerate(log[:30]):
        samp = bytes(ev.get('sample', [])).hex() if ev.get('sample') else ''
        print(f"  [{i}] {ev['op']} offset={ev['offset']:3d} from={ev['from']} buf={samp[:32]}...")
        if i < 5:
            for b in ev.get('bt', []):
                print(f"      {b}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
