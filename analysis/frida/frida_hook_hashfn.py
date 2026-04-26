#!/usr/bin/env python3
"""Hook wrapper+0x5ccd94a (called 788 times during sign) and capture its inputs/outputs.
Goal: determine if it's a hash function and, if so, what inputs produce the 20-byte XOR stream."""
import frida, subprocess, os, time, json

TARGET_XOR = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const TARGET = WRAPPER_BASE.add(0x5ccd94a);
const TARGET_XOR = [%XOR_BYTES%];

let insideSign = false;
let callNum = 0;
let capturedCalls = [];

send({type: 'log', msg: 'hooking: ' + TARGET});

function byteCmp(bytes, target, n) {
    if (bytes.length < n) return false;
    for (let i = 0; i < n; i++) if (bytes[i] !== target[i]) return false;
    return true;
}

Interceptor.attach(SIGN_FN, {
    onEnter: function (args) {
        insideSign = true;
        callNum = 0;
        capturedCalls = [];
    },
    onLeave: function () {
        insideSign = false;
        send({type: 'sign_done', total_calls: callNum, captured: capturedCalls.length});
        send({type: 'calls', data: capturedCalls.slice(0, 50)});
    }
});

Interceptor.attach(TARGET, {
    onEnter: function (args) {
        if (!insideSign) return;
        this._callIdx = callNum++;
        // Record argument register values
        this._ctx = {
            rdi: args[0].toString(),
            rsi: args[1].toString(),
            rdx: args[2].toString(),
            rcx: args[3].toString(),
            r8: args[4].toString(),
            r9: args[5].toString(),
        };
        // Try to read memory at each pointer (first 64 bytes)
        const mem = {};
        for (const reg of ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']) {
            try {
                const p = ptr(this._ctx[reg]);
                // Only try if looks like a valid pointer
                const ival = parseInt(this._ctx[reg], 16);
                if (ival > 0x100000 && ival < 0x800000000000) {
                    mem[reg] = Array.from(new Uint8Array(p.readByteArray(64)));
                }
            } catch (e) {}
        }
        this._inMem = mem;
    },
    onLeave: function (retval) {
        if (!insideSign) return;
        // Capture return value + output memory (via same pointers after call)
        const outMem = {};
        for (const reg of ['rdi', 'rsi', 'rdx']) {
            try {
                const p = ptr(this._ctx[reg]);
                const ival = parseInt(this._ctx[reg], 16);
                if (ival > 0x100000 && ival < 0x800000000000) {
                    outMem[reg] = Array.from(new Uint8Array(p.readByteArray(64)));
                }
            } catch (e) {}
        }
        // Check if any output matches XOR target
        let xorHit = false;
        for (const reg in outMem) {
            if (byteCmp(outMem[reg], TARGET_XOR, 20)) {
                xorHit = true;
                break;
            }
        }
        // Only keep small subset (avoid flooding)
        if (this._callIdx < 30 || xorHit) {
            capturedCalls.push({
                idx: this._callIdx,
                ctx: this._ctx,
                inMem: this._inMem,
                outMem: outMem,
                retval: retval.toString(),
                xorHit: xorHit
            });
        }
        if (xorHit) {
            send({type: 'xor_hit', call: {idx: this._callIdx, ctx: this._ctx, outMem: outMem}});
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
    xor_str = ','.join(str(b) for b in TARGET_XOR)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1)).replace('%XOR_BYTES%', xor_str)
    script = session.create_script(src)

    result = {}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            t = pl.get('type')
            if t == 'log': print(f"[frida] {pl['msg']}")
            elif t == 'sign_done':
                print(f"[frida] sign done: total_calls={pl['total_calls']}, captured={pl['captured']}")
                result['total'] = pl['total_calls']
            elif t == 'calls':
                result['calls'] = pl['data']
            elif t == 'xor_hit':
                print(f"\n*** XOR HIT in hash fn output! call #{pl['call']['idx']} ***")
                result.setdefault('hits', []).append(pl['call'])
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

    # Analyze
    calls = result.get('calls', [])
    print(f"\n[main] {len(calls)} captured calls")
    if calls:
        # Show first 3 calls in detail
        for i, c in enumerate(calls[:3]):
            print(f"\n=== Call #{c['idx']} ===")
            print(f"  rdi={c['ctx']['rdi']} rsi={c['ctx']['rsi']} rdx={c['ctx']['rdx']}")
            for reg in ['rdi', 'rsi', 'rdx']:
                if reg in c['inMem']:
                    print(f"  [{reg}] IN :  {bytes(c['inMem'][reg]).hex()}")
                if reg in c['outMem']:
                    print(f"  [{reg}] OUT:  {bytes(c['outMem'][reg]).hex()}")

    hits = result.get('hits', [])
    if hits:
        print(f"\n=== XOR pattern HITS: {len(hits)} ===")
        for h in hits:
            print(f"  call idx={h['idx']}")
            for reg in ['rdi', 'rsi', 'rdx']:
                if reg in h['outMem']:
                    print(f"    [{reg}] {bytes(h['outMem'][reg]).hex()}")

    # Save full data
    with open('/tmp/hash_fn_calls.json', 'w') as f:
        json.dump(calls, f, indent=2)

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
