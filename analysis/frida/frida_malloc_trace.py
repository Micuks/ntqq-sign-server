#!/usr/bin/env python3
"""Hook malloc in sign(); for each alloc, record (size, addr, caller).
After sign, find the alloc whose buffer contains the 20-byte XOR pattern."""
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
let allocs = [];
let mallocHit = 0;

let freedAddrs = new Set();
let hookCallCounter = 0;
let foundMatch = null;

// The key hook: at each VM byte-op, scan pending allocs for the XOR pattern
const VMDispatchFn = WRAPPER_BASE.add(0x5cccffa);
Interceptor.attach(VMDispatchFn, {
    onEnter: function() {
        if (!insideSign || foundMatch) return;
        hookCallCounter++;
        if (hookCallCounter % 5 !== 0) return;  // scan every 5 calls
        // Scan allocs
        for (const a of allocs) {
            if (freedAddrs.has(a.addr)) continue;
            try {
                const buf = new Uint8Array(ptr(a.addr).readByteArray(Math.min(a.size, 64)));
                for (let off = 0; off <= Math.max(0, buf.length - 20); off++) {
                    let m = true;
                    for (let j = 0; j < 20; j++) {
                        if (buf[off + j] !== TARGET[j]) { m = false; break; }
                    }
                    if (m) {
                        foundMatch = {
                            hookCall: hookCallCounter,
                            allocIdx: allocs.indexOf(a),
                            size: a.size, addr: a.addr, offset: off,
                            bt: a.bt, op: a.op
                        };
                        send({type: 'match', match: foundMatch});
                        return;
                    }
                }
            } catch(e) {}
        }
    }
});

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        insideSign = true;
        allocs = [];
        freedAddrs = new Set();
        hookCallCounter = 0;
        foundMatch = null;
    },
    onLeave: function() {
        insideSign = false;
        send({type: 'done', alloc_count: allocs.length, matched: foundMatch});
    }
});

// Hook malloc@plt in wrapper.node (wrapper+0x7ae63b0) and libc malloc
function hookMalloc(addr, name) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            if (!insideSign) return;
            this.size = args[0].toInt32();
        },
        onLeave: function(ret) {
            if (!insideSign) return;
            if (this.size < 16 || this.size > 4096) return;
            let bt = [];
            try { bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8).map(rel); } catch(e) {}
            allocs.push({op: name, size: this.size, addr: ret.toString(), bt: bt});
        }
    });
}
const mallocPlt = WRAPPER_BASE.add(0x7ae63b0);
hookMalloc(mallocPlt, 'malloc@plt');
try {
    const libcMalloc = Module.getGlobalExportByName('malloc');
    hookMalloc(libcMalloc, 'malloc');
} catch(e) {}

// Also hook _Znwm (C++ new)
const znwm = Module.findGlobalExportByName('_Znwm');
if (znwm) {
    Interceptor.attach(znwm, {
        onEnter: function(args) {
            if (!insideSign) return;
            this.size = args[0].toInt32();
        },
        onLeave: function(ret) {
            if (!insideSign) return;
            if (this.size < 16 || this.size > 4096) return;
            let bt = [];
            try { bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8).map(rel); } catch(e) {}
            allocs.push({size: this.size, addr: ret.toString(), op: 'new', bt: bt});
        }
    });
}

// Hook free to track freed allocs
const freePlt = WRAPPER_BASE.add(0x7ae6320);
Interceptor.attach(freePlt, {
    onEnter: function(args) {
        if (!insideSign) return;
        freedAddrs.add(args[0].toString());
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
                result.update(pl)
            elif pl.get('type') == 'match':
                result['match'] = pl['match']
                print(f"\n*** MATCH: alloc #{pl['match']['allocIdx']} size={pl['match']['size']} at offset={pl['match']['offset']} (at hook #{pl['match']['hookCall']}) ***")
                for bt in pl['match'].get('bt', []):
                    print(f"  {bt}")
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
    time.sleep(1.5)

    allocs = result.get('alloc_count', 0)
    match = result.get('match')
    print(f'\n[main] {allocs} allocs tracked')
    if match:
        print(f'Match: size={match["size"]} addr={match["addr"]} offset={match["offset"]}')
        print(f'  op={match.get("op")}')
        print(f'  caller backtrace:')
        for b in match.get('bt', []):
            print(f'    {b}')
    else:
        print('No match found during sign execution.')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
