#!/usr/bin/env python3
"""Hook FREQ_FN (wrapper+0x5ccd94a) and dump src buffer content for all calls.
Find the call where rdx (source ptr) contains our 20-byte XOR pattern."""
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
let callIdx = 0;
let calls = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() { insideSign = true; callIdx = 0; calls = []; },
    onLeave: function() {
        insideSign = false;
        send({type: 'done', calls: calls});
    }
});

const FREQ_FN = WRAPPER_BASE.add(0x5ccd94a);
Interceptor.attach(FREQ_FN, {
    onEnter: function(args) {
        if (!insideSign) return;
        callIdx++;
        const rdi = args[0], rsi = args[1], rdx = args[2];
        const rsiVal = rsi.toInt32();
        // Only care about small sizes (1-64 bytes)
        if (rsiVal < 1 || rsiVal > 64) return;
        let srcBytes = null;
        try {
            const rdxVal = parseInt(rdx.toString(), 16);
            if (rdxVal > 0x10000 && rdxVal < 0x800000000000) {
                srcBytes = Array.from(new Uint8Array(rdx.readByteArray(Math.min(rsiVal, 32))));
            }
        } catch(e) {}
        if (!srcBytes) return;
        // Check if starts with XOR pattern
        let matchLen = 0;
        for (let i = 0; i < Math.min(srcBytes.length, TARGET.length); i++) {
            if (srcBytes[i] === TARGET[i]) matchLen++;
            else break;
        }
        const info = {
            idx: callIdx, size: rsiVal,
            rdi: rdi.toString(), rdx: rdx.toString(),
            src: srcBytes, matchLen: matchLen
        };
        if (matchLen >= 4 || callIdx <= 30) {
            calls.push(info);
        }
        if (matchLen >= 10) {
            let bt = [];
            try {
                bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 10).map(rel);
            } catch(e) {}
            info.bt = bt;
            send({type: 'match', call: info});
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
                result['calls'] = pl['calls']
            elif pl.get('type') == 'match':
                print(f"\n*** MATCH at call #{pl['call']['idx']}: size={pl['call']['size']} matchLen={pl['call']['matchLen']} ***")
                print(f"  src bytes: {bytes(pl['call']['src']).hex()}")
                print(f"  rdi={pl['call']['rdi']} rdx={pl['call']['rdx']}")
                if pl['call'].get('bt'):
                    for b in pl['call']['bt']: print(f"    {b}")
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

    calls = result.get('calls', [])
    print(f'\n[main] {len(calls)} FREQ_FN calls with size 1-64')
    # Show all with matchLen > 0 first, then a sample
    matches = [c for c in calls if c.get('matchLen', 0) > 0]
    print(f'Matches (matchLen > 0): {len(matches)}')
    for c in matches[:10]:
        print(f"  #{c['idx']} size={c['size']} matchLen={c['matchLen']} src={bytes(c['src']).hex()}")
    # First 20 calls as reference
    print(f'\nFirst 20 calls (baseline):')
    for c in calls[:20]:
        print(f"  #{c['idx']} size={c['size']} src={bytes(c['src']).hex()}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
