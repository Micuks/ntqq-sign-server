#!/usr/bin/env python3
"""Hook the byte-load helper at w+0x5cccffa. At each call, capture:
  - return address (caller of this helper)
  - rdi (VM context pointer)
  - rsi (PC offset into bytecode)
  - byte value loaded (read from memory after computing rdi+0x18 + rsi)

Goal: identify which caller is the VM dispatch loop, and characterize how
bytecode bytes are consumed (1 per opcode? 1 per operand? mixed?).

This will tell us where to hook to capture per-VM-step state (registers + memory).
"""
import frida, subprocess, os, time, json
from collections import Counter


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const HELPER = WRAPPER_BASE.add(0x5cccffa);

let inside = false;
let calls = [];  // {ret, rdi, rsi, byte, callIdx}
let callIdx = 0;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        calls = [];
        callIdx = 0;
    },
    onLeave: function() {
        inside = false;
        // Send in chunks
        const CHUNK = 500;
        for (let i = 0; i < calls.length; i += CHUNK) {
            send({type: 'chunk', data: calls.slice(i, i+CHUNK)});
        }
        send({type: 'done', total: calls.length});
    }
});

Interceptor.attach(HELPER, {
    onEnter: function(args) {
        if (!inside) return;
        const rdi = this.context.rdi;
        const rsi = this.context.rsi;
        // The function does: rax = *(rdi+0x18); al = *(rax + rsi)
        let byte = -1;
        try {
            const bytecode_ptr = rdi.add(0x18).readPointer();
            byte = bytecode_ptr.add(rsi).readU8();
        } catch(e) {}
        const ret = this.returnAddress;
        let retOff = -1;
        try {
            const off = ret.sub(WRAPPER_BASE).toInt32();
            if (off >= 0 && off < 0x10000000) retOff = off;
        } catch(e) {}
        calls.push({
            ret: retOff,
            rdi: rdi.toString(),
            rsi: rsi.toInt32(),
            byte: byte,
            idx: callIdx++,
        });
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
    p = spawn()
    base = None
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE': break
    assert base is not None

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)
    all_calls = []
    done = [False, 0]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'chunk':
                all_calls.extend(pl['data'])
            elif pl.get('type') == 'done':
                done[1] = pl['total']
                done[0] = True
        elif msg['type'] == 'error':
            print(f"[error] {msg.get('description','')[:300]}")
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)

    print('[main] triggering sign...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line.startswith('SIGN_RESULT='):
            print(f'[helper] {line}')
            break
    deadline = time.time() + 10
    while not done[0] and time.time() < deadline:
        time.sleep(0.2)

    print(f'\n[main] total byte-load calls: {done[1]}, captured: {len(all_calls)}')
    # Top callers
    callers = Counter(c['ret'] for c in all_calls)
    print(f'\nTop 20 callers (return addresses):')
    for addr, cnt in callers.most_common(20):
        if addr >= 0:
            print(f'  w+0x{addr:08x}: {cnt}')
        else:
            print(f'  <unknown>: {cnt}')

    # rdi values (should be small set — VM contexts)
    rdis = Counter(c['rdi'] for c in all_calls)
    print(f'\nDistinct rdi (VM context): {len(rdis)}')
    for r, c in rdis.most_common(5):
        print(f'  rdi={r}: {c} calls')

    # rsi (PC) range
    rsis = [c['rsi'] for c in all_calls]
    print(f'\nrsi (PC) range: min={min(rsis)} max={max(rsis)}')

    # First 30 calls — sequence
    print(f'\nFirst 30 byte-loads:')
    for c in all_calls[:30]:
        print(f"  idx={c['idx']:>4} ret=w+0x{c['ret']:08x} rsi={c['rsi']:>4} byte=0x{c['byte']:02x}")

    # Save all
    with open('/tmp/byteload_calls.json', 'w') as f:
        json.dump(all_calls, f)
    print(f"\nSaved {len(all_calls)} calls to /tmp/byteload_calls.json")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
