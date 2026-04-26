#!/usr/bin/env python3
"""Find the VM main bytecode by scanning all reachable memory from VM contexts.

For each pointer in rdi+0..0x100, follow it and dump 512 bytes. Look for the
KNOWN_FIRST_IB = [2, 0, 21, 0] pattern. Also collect memory regions that
match the size profile (~360 bytes of compact opcode-like bytes).
"""
import frida, subprocess, os, time

KNOWN_FIRST_IB = [2, 0, 21, 0]


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const HELPER = WRAPPER_BASE.add(0x5cccffa);

let inside = false;
let scanned = false;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        scanned = false;
    },
    onLeave: function() {
        inside = false;
        send({type: 'done'});
    }
});

let firstRdi = null;
let scanCount = 0;
Interceptor.attach(HELPER, {
    onEnter: function(args) {
        if (!inside) return;
        scanCount++;
        // Wait for ~50 calls so VM is fully set up
        if (scanCount !== 50) return;
        const rdi = this.context.rdi;
        // Dump fields
        const fields = [];
        for (let off = 0; off < 0x100; off += 8) {
            try {
                const val = rdi.add(off).readPointer();
                fields.push([off, val]);
            } catch(e) { break; }
        }

        // For each pointer-looking value, follow and scan 512 bytes
        const results = [];
        for (const [off, val] of fields) {
            try {
                const data = val.readByteArray(512);
                if (!data) continue;
                const arr = new Uint8Array(data);
                // Search for KNOWN_FIRST_IB in arr
                for (let i = 0; i <= arr.length - 4; i++) {
                    if (arr[i] === 2 && arr[i+1] === 0 && arr[i+2] === 21 && arr[i+3] === 0) {
                        results.push({
                            field_off: off,
                            ptr: val.toString(),
                            match_pos: i,
                            sample: Array.from(arr.slice(Math.max(0, i-4), i+32))
                        });
                        break;
                    }
                }
            } catch(e) {}
        }
        send({type: 'scan_results', rdi: rdi.toString(), results: results, fieldCount: fields.length});

        // Also dump first 16 fields raw
        const fieldDump = fields.slice(0, 32).map(([off, val]) => [off, val.toString()]);
        send({type: 'fields', rdi: rdi.toString(), fields: fieldDump});
    }
});

send({type: 'ready'});
"""


def spawn():
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
    nm = ctypes.c_void_p.from_address(info + 8).value
    if nm:
        try:
            if "wrapper.node" in ctypes.string_at(nm).decode():
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
def sign_once(src_byte=0):
    sb = (ctypes.c_ubyte * 1)(src_byte)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = 100
    sf(b'wtlogin.login', sb, 1, 1, out)
    return bytes(out)[0x200:0x200+bytes(out)[0x2FF]]
_ = sign_once(0)
print('WARM_DONE', flush=True)
for line in sys.stdin:
    if line.strip() == 'SIGN':
        r = sign_once(0)
        print(f'SIGN_RESULT={r.hex()}', flush=True)
    elif line.strip() == 'EXIT': break
"""
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/libfaketime_zero.so'
    return subprocess.Popen(['python3','-c',helper],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, text=True, bufsize=1)


def main():
    p = spawn()
    base = None
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE': break

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)
    results = []
    fields = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'scan_results':
                results.append(pl)
            elif pl.get('type') == 'fields':
                fields.append(pl)
            elif pl.get('type') == 'done':
                done[0] = True
        elif msg['type'] == 'error':
            print(f"[error] {msg.get('description','')[:300]}")
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line.startswith('SIGN_RESULT='):
            print(f'[helper] {line}')
            break
    deadline = time.time() + 8
    while not done[0] and time.time() < deadline:
        time.sleep(0.2)

    print(f'\n=== Field dumps ===')
    for f in fields[:1]:
        print(f"rdi={f['rdi']}, {len(f['fields'])} fields")
        for off, val in f['fields']:
            print(f"  +0x{off:02x}: {val}")

    print(f'\n=== Scan results ===')
    for r in results:
        print(f"\nrdi={r['rdi']} (scanned {r['fieldCount']} fields)")
        if not r['results']:
            print('  No matches for KNOWN_FIRST_IB pattern.')
        for hit in r['results']:
            print(f"  HIT field +0x{hit['field_off']:02x} = {hit['ptr']} match_pos={hit['match_pos']}")
            print(f"    bytes around match: {' '.join(f'{b:02x}' for b in hit['sample'])}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
