#!/usr/bin/env python3
"""At dispatcher candidate w+0x5cd3685, read bytes at rax (and various offsets)
to verify it's the PC pointer.
"""
import frida, subprocess, os, time, json


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const TARGET_OFF = 0x5cd3685;

let inside = false;
let tid = null;
const samples = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        samples.length = 0;
        Stalker.follow(tid, {
            transform: function(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    if (ins.address.equals(WRAPPER_BASE.add(TARGET_OFF))) {
                        iter.putCallout(function(ctx) {
                            if (samples.length >= 100) return;
                            const sample = {
                                idx: samples.length,
                                rax: ctx.rax.toString(),
                                rcx: ctx.rcx.toString(),
                                rsi: ctx.rsi.toString(),
                                rdi: ctx.rdi.toString(),
                                r14: ctx.r14.toString(),
                                bytes_at_rax: null,
                                bytes_at_rcx: null,
                                bytes_at_rsi: null,
                                bytes_at_rdi: null,
                            };
                            // Try reading bytes at each pointer-like reg
                            for (const r of ['rax', 'rcx', 'rsi', 'rdi']) {
                                try {
                                    const ptr_ = ptr(sample[r]);
                                    const data = ptr_.readByteArray(8);
                                    if (data) sample['bytes_at_' + r] = Array.from(new Uint8Array(data));
                                } catch(e) {}
                            }
                            samples.push(sample);
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
        send({type: 'samples', samples: samples});
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
    samples = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'samples':
                samples.extend(pl['samples'])
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
    deadline = time.time() + 240
    while not done[0] and time.time() < deadline:
        time.sleep(1)

    # Load OLD trace to compare
    trace = json.load(open('/tmp/complete_trace_00.json'))
    print(f'\n=== First 10 samples vs OLD trace ===')
    for i, s in enumerate(samples[:10]):
        if i >= len(trace): break
        step, op, pc, diff, ib = trace[i]
        print(f"\nidx={i} (trace step {step}, op={op:#x}, pc_offset={pc}, ib={ib})")
        for r in ['rax', 'rcx', 'rsi', 'rdi']:
            ptr_v = int(s[r], 16)
            bytes_at = s.get('bytes_at_' + r)
            match = "MATCH" if bytes_at and list(bytes_at[:4]) == ib else ""
            print(f"  {r}=0x{ptr_v:016x} bytes_at={bytes_at} {match}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
