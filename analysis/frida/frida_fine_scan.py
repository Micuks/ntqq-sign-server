#!/usr/bin/env python3
"""Very fine-grained scan: at EVERY hook call, scan heap for emerging 20-byte pattern.
When pattern first appears, we'll know the precise call it was written."""
import frida, subprocess, os, time

TARGET_XOR = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const TARGET_STR = '%TARGET_HEX_SPACED%';

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
let foundAt = null;
let foundAddr = null;
let heapRanges = null;
let callLog = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        insideSign = true;
        callIdx = 0;
        foundAt = null;
        foundAddr = null;
        callLog = [];
        // Pre-enumerate heap ranges ONCE
        heapRanges = Process.enumerateRanges({protection: 'rw-', coalesce: true})
                      .filter(r => r.size < 0x1000000 && r.size > 0x1000)
                      .slice(0, 100);
    },
    onLeave: function() {
        insideSign = false;
        send({type: 'done', foundAt: foundAt, foundAddr: foundAddr, callLog: callLog});
    }
});

// Hook a medium-frequency op to get granularity (~788 calls during sign)
const FREQ_FN = WRAPPER_BASE.add(0x5ccd94a);
Interceptor.attach(FREQ_FN, {
    onEnter: function(args) {
        if (!insideSign) return;
        callIdx++;
        if (foundAt !== null) return;
        // Record recent call arguments
        callLog.push({
            idx: callIdx,
            rdi: args[0].toString(),
            rsi: args[1].toString(),
            rdx: args[2].toString(),
        });
        // Scan heap
        for (const r of heapRanges) {
            try {
                const hits = Memory.scanSync(r.base, r.size, TARGET_STR);
                if (hits.length > 0) {
                    foundAt = callIdx;
                    foundAddr = hits[0].address.toString();
                    send({type: 'found', callIdx: callIdx, addr: foundAddr});
                    return;
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
    tgt_spaced = ' '.join(f'{b:02x}' for b in TARGET_XOR)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1)) \
                .replace('%TARGET_HEX_SPACED%', tgt_spaced)
    script = session.create_script(src)

    result = {}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'done':
                result.update(pl)
            elif pl.get('type') == 'found':
                print(f"[frida] found at FREQ_FN call #{pl['callIdx']}, addr={pl['addr']}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    print('[main] triggering sign (slow due to every-call scan)...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break
    time.sleep(5.0)

    log = result.get('callLog', [])
    print(f'\n[main] Total {len(log)} FREQ_FN calls before pattern found.')
    print(f"Found at call #{result.get('foundAt')}, addr={result.get('foundAddr')}")
    # Show last 5 calls BEFORE pattern appeared
    if len(log) >= 5:
        print(f'\nLast 5 calls BEFORE pattern found:')
        for e in log[-5:]:
            print(f"  #{e['idx']}: rdi={e['rdi']} rsi={e['rsi']} rdx={e['rdx']}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
