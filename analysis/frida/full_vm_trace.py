#!/usr/bin/env python3
"""Capture FULL per-step VM trace at dispatcher w+0x5cd3685.

For each VM step, capture:
  - PC (offset within bytecode buffer)
  - 4 ib bytes
  - All 150 registers (u32 each)

Save as JSON for offline analysis.

Usage: python3 full_vm_trace.py <src_byte_hex>
e.g., python3 full_vm_trace.py 00 → uses src=b"\x00"
"""
import frida, subprocess, os, time, json, sys


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const DISPATCHER_OFF = 0x5cd3685;

let inside = false;
let tid = null;
let bytecodeBase = null;
const samples = [];
const NREGS = 150;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        samples.length = 0;
        bytecodeBase = null;
        Stalker.follow(tid, {
            transform: function(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    if (ins.address.equals(WRAPPER_BASE.add(DISPATCHER_OFF))) {
                        iter.putCallout(function(ctx) {
                            if (samples.length >= 17000) return;
                            const rax = ctx.rax;
                            const r14 = ctx.r14;
                            // ib bytes at rax
                            let ib = null;
                            try {
                                const data = rax.readByteArray(4);
                                ib = Array.from(new Uint8Array(data));
                            } catch(e) {}
                            // Register array via r14+0x10
                            let regArray = null;
                            try {
                                const ra = r14.add(0x10).readPointer();
                                const arr = new Uint32Array(NREGS);
                                for (let i = 0; i < NREGS; i++) {
                                    try { arr[i] = ra.add(i*8).readU32(); }
                                    catch(e) { arr[i] = 0; }
                                }
                                regArray = Array.from(arr);
                            } catch(e) {}
                            // Track bytecode base from first sample
                            if (bytecodeBase === null) {
                                bytecodeBase = rax;
                            }
                            const pc_offset = rax.sub(bytecodeBase).toInt32();
                            samples.push([pc_offset, ib, regArray]);
                        });
                    }
                    iter.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(e) {}
        inside = false;
        send({type: 'count', n: samples.length});
        // Send in chunks; each sample has 150 u32 + ib so ~600 bytes
        const CHUNK = 100;
        for (let i = 0; i < samples.length; i += CHUNK) {
            send({type: 'chunk', data: samples.slice(i, i+CHUNK), start: i});
        }
        send({type: 'done'});
    }
});

send({type: 'ready'});
"""


def spawn(src_byte=0):
    helper = f"""
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
print(f'BASE={{hex(base.value)}}', flush=True)
SIGN_T = ctypes.CFUNCTYPE(ctypes.c_longlong, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte))
sf = SIGN_T(base.value + 0x56D81D1)
COUNTER = base.value + 0x7DD868C
def sign_once(src_byte={src_byte}):
    sb = (ctypes.c_ubyte * 1)(src_byte)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = 100
    sf(b'wtlogin.login', sb, 1, 1, out)
    return bytes(out)[0x200:0x200+bytes(out)[0x2FF]]
_ = sign_once(0)
print('WARM_DONE', flush=True)
for line in sys.stdin:
    if line.strip() == 'SIGN':
        r = sign_once({src_byte})
        print(f'SIGN_RESULT={{r.hex()}}', flush=True)
    elif line.strip() == 'EXIT': break
"""
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/libfaketime_zero.so'
    return subprocess.Popen(['python3','-c',helper],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, text=True, bufsize=1)


def main():
    src_hex = sys.argv[1] if len(sys.argv) > 1 else '00'
    src_byte = int(src_hex, 16) & 0xFF
    out_path = sys.argv[2] if len(sys.argv) > 2 else f'/tmp/full_vm_trace_{src_hex}.json'

    p = spawn(src_byte)
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
    samples = [None] * 17000
    n_received = [0]
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'count':
                print(f"[script] capturing {pl['n']} VM steps")
            elif pl.get('type') == 'chunk':
                start = pl['start']
                for i, s in enumerate(pl['data']):
                    samples[start + i] = s
                n_received[0] += len(pl['data'])
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
    deadline = time.time() + 600
    while not done[0] and time.time() < deadline:
        time.sleep(2)

    samples = [s for s in samples if s is not None]
    print(f'\nReceived {n_received[0]} samples ({len(samples)} non-null).')
    with open(out_path, 'w') as f:
        json.dump(samples, f)
    print(f'Saved to {out_path}')
    print(f'File size: {os.path.getsize(out_path)} bytes')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
