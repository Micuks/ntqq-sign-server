#!/usr/bin/env python3
"""Find the main VM bytecode region by examining the VM context structure.

Strategy:
  1. Set a hook at sign function entry to grab args (cmd, src, etc.)
  2. Inside sign, the VM context (rdi or similar) is set up. We need to find it.
  3. The byte-load helper at w+0x5cccffa reads from *(rdi+0x18) + rsi.
     But rsi was small (0..52) — too small for main bytecode.
  4. Maybe the main VM bytecode is read via a DIFFERENT loader.

Approach: scan all unique rdi values seen at byte-load helper. For each,
inspect rdi+0x10, rdi+0x18, rdi+0x20 etc. The MAIN VM context will have
a large bytecode buffer (~360 bytes based on OLD trace pc range 0..360).

Also: dump 256 bytes from each candidate buffer and compare against the
known OLD bytecode pattern: first ib at pc=0 was [2, 0, 21, 0].
"""
import frida, subprocess, os, time

KNOWN_FIRST_IB = [2, 0, 21, 0]  # First 4 bytes of bytecode (from old trace)


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const HELPER = WRAPPER_BASE.add(0x5cccffa);

let inside = false;
let context_dumps = {};   // rdi -> first dump
let dump_count = 0;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        context_dumps = {};
        dump_count = 0;
    },
    onLeave: function() {
        inside = false;
        send({type: 'done', contexts: Object.keys(context_dumps).length, dumps: dump_count});
    }
});

Interceptor.attach(HELPER, {
    onEnter: function(args) {
        if (!inside) return;
        const rdi = this.context.rdi;
        const rdiKey = rdi.toString();
        if (context_dumps[rdiKey] !== undefined) return;
        context_dumps[rdiKey] = true;
        dump_count++;
        // Dump struct fields at rdi
        const fields = [];
        for (let off = 0; off < 0x80; off += 8) {
            try {
                const val = rdi.add(off).readPointer();
                fields.push([off, val.toString()]);
            } catch(e) {
                fields.push([off, 'unreadable']);
                break;
            }
        }
        // Try to read bytes at the most likely bytecode pointer (rdi+0x18 or similar)
        // and compare against KNOWN_FIRST_IB
        const candidates = [];
        for (const [off, valStr] of fields) {
            if (valStr === 'unreadable') continue;
            try {
                const ptrVal = ptr(valStr);
                // Try first 32 bytes
                const data = ptrVal.readByteArray(32);
                if (data) {
                    candidates.push({offset: off, ptr: valStr, bytes: Array.from(new Uint8Array(data))});
                }
            } catch(e) {}
        }
        send({type: 'context', rdi: rdiKey, fields: fields, candidates: candidates});
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
def sign_once(src_byte=0, seq=1, ctr=100, cmd='wtlogin.login'):
    sb = (ctypes.c_ubyte * 1)(src_byte)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = ctr
    sf(cmd.encode(), sb, 1, seq, out)
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
    contexts = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'context':
                contexts.append(pl)
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
    deadline = time.time() + 5
    while not done[0] and time.time() < deadline:
        time.sleep(0.2)

    print(f'\n=== Captured {len(contexts)} VM contexts ===')
    for ctx in contexts:
        print(f"\nrdi={ctx['rdi']}")
        print('  Field offsets (rdi+N -> pointer value):')
        for off, val in ctx['fields'][:16]:
            print(f"    +0x{off:02x}: {val}")
        # Print candidates that look like bytecode
        print('  Candidate bytecode pointers (first 32 bytes at each):')
        for cand in ctx['candidates'][:8]:
            data = cand['bytes']
            hexb = ' '.join(f'{b:02x}' for b in data[:16])
            match_known = data[:4] == KNOWN_FIRST_IB
            marker = ' *** MATCHES KNOWN_FIRST_IB ***' if match_known else ''
            print(f"    rdi+0x{cand['offset']:02x} = {cand['ptr']} :: {hexb}{marker}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
