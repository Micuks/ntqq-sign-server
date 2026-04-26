#!/usr/bin/env python3
"""Hook malloc and scan EACH alloc at many points during sign.
Record all allocs whose content at any point contains the 20-byte XOR pattern."""
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
let allocs = {};  // addr -> {size, bt, firstMatch}
let sampleCounter = 0;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        insideSign = true;
        allocs = {};
        sampleCounter = 0;
    },
    onLeave: function() {
        insideSign = false;
        const matches = [];
        for (const addr in allocs) {
            if (allocs[addr].firstMatch !== undefined) {
                matches.push({addr: addr, ...allocs[addr]});
            }
        }
        send({type: 'done', totalAllocs: Object.keys(allocs).length, matches: matches});
    }
});

const mallocPlt = WRAPPER_BASE.add(0x7ae63b0);
Interceptor.attach(mallocPlt, {
    onEnter: function(args) {
        if (!insideSign) return;
        this.size = args[0].toInt32();
    },
    onLeave: function(ret) {
        if (!insideSign || this.size < 16 || this.size > 4096) return;
        let bt = [];
        try { bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8).map(rel); } catch(e) {}
        allocs[ret.toString()] = {size: this.size, bt: bt};
    }
});

// Don't delete on free — we want to catch the buffer while it's alive
// The scan will naturally fail when memory is reallocated


// Scan all live allocs periodically
const hookFn = WRAPPER_BASE.add(0x5cccffa);
Interceptor.attach(hookFn, {
    onEnter: function() {
        if (!insideSign) return;
        sampleCounter++;
        // Scan every call (slow but comprehensive)
        for (const addrStr in allocs) {
            const a = allocs[addrStr];
            if (a.firstMatch !== undefined) continue;
            try {
                const buf = new Uint8Array(ptr(addrStr).readByteArray(Math.min(a.size, 64)));
                // Check if target is at any position 0..max
                for (let off = 0; off <= Math.max(0, buf.length - 20); off++) {
                    let match = true;
                    for (let j = 0; j < 20; j++) if (buf[off+j] !== TARGET[j]) { match = false; break; }
                    if (match) {
                        a.firstMatch = sampleCounter;
                        a.matchOffset = off;
                        break;
                    }
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
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    print('[main] triggering sign...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break
    time.sleep(3.0)

    matches = result.get('matches', [])
    print(f'\n[main] {result.get("totalAllocs", 0)} allocs total')
    print(f'{len(matches)} allocs contained the XOR pattern at some point:')
    # Sort by first match time (earliest first)
    matches.sort(key=lambda m: m.get('firstMatch', 0))
    for m in matches:
        print(f"\n  size={m['size']} addr={m['addr']} firstMatchAt=call#{m['firstMatch']} offset={m.get('matchOffset', 0)}")
        print(f"  alloc backtrace:")
        for b in m.get('bt', []):
            print(f"    {b}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
