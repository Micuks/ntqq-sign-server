"""Capture multi_u64 traces for SPECIFIC srcs in INDEPENDENT processes,
so the initial state isn't polluted by previous sign() calls.

This gives us clean (cmd, src) → trace mappings for differential analysis."""
import frida, subprocess, os, time, sys, json

SRCS = [int(s, 16) for s in (sys.argv[1] if len(sys.argv) > 1 else '0x00,0x42,0xab').split(',')]

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const DISPATCHER_OFF = 0x5cd3685;
const NREGS = 300;

let inside = false;
let tid = null;
let bytecodeBase = null;
let samples = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        samples = [];
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
                            let ib = null;
                            try {
                                ib = Array.from(new Uint8Array(rax.readByteArray(4)));
                            } catch(e) {}
                            let regsLo = null, regsHi = null;
                            try {
                                const ra = r14.add(0x10).readPointer();
                                regsLo = []; regsHi = [];
                                for (let i = 0; i < NREGS; i++) {
                                    try {
                                        regsLo.push(ra.add(i*8).readU32());
                                        regsHi.push(ra.add(i*8 + 4).readU32());
                                    } catch(e) { regsLo.push(0); regsHi.push(0); }
                                }
                            } catch(e) {}
                            if (bytecodeBase === null) bytecodeBase = rax;
                            const pc = rax.sub(bytecodeBase).toInt32();
                            samples.push([pc, ib, regsLo, regsHi]);
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
    }
});

recv('dump', function() {
    const CHUNK = 50;
    for (let i = 0; i < samples.length; i += CHUNK) {
        send({type: 'chunk', data: samples.slice(i, i+CHUNK), start: i});
    }
    send({type: 'done', total: samples.length});
});

send({type:'ready'});
"""


def capture_for_src(src_byte):
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
print('READY', flush=True)
for line in sys.stdin:
    if line.strip() == 'GO':
        sb = (ctypes.c_ubyte * 1)({src_byte})
        out = (ctypes.c_ubyte * 0x300)()
        ctypes.c_uint32.from_address(COUNTER).value = 100
        sf(b'wtlogin.login', sb, 1, 1, out)
        print('SIGN_DONE='+bytes(out)[0x200:0x220].hex(), flush=True)
    elif line.strip() == 'EXIT': break
"""
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tmp/libfaketime_zero.so'
    p = subprocess.Popen(['python3', '-c', helper],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, text=True, bufsize=1)
    base = None
    while True:
        line = p.stdout.readline().strip()
        if line.startswith('BASE='):
            base = int(line.split('=')[1], 16)
        if line == 'READY': break
    assert base

    session = frida.attach(p.pid)
    s = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(s)

    chunks = []
    state = {'done': False}
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'chunk':
                chunks.append((pl['start'], pl['data']))
            elif pl.get('type') == 'done':
                state['done'] = True
        elif msg['type'] == 'error':
            print(f"[err] {msg.get('description','')[:200]}")
    script.on('message', on_msg)
    script.load()
    time.sleep(0.3)

    p.stdin.write('GO\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line.startswith('SIGN_DONE='):
            print(f"  src=0x{src_byte:02x}: sign={line.split('=', 1)[1]}")
            break

    script.post({'type': 'dump'})
    for _ in range(120):
        if state['done']: break
        time.sleep(0.5)

    chunks.sort()
    samples = [None] * 17000
    for start, data in chunks:
        for i, s in enumerate(data):
            if start + i < 17000: samples[start + i] = s
    samples = [s for s in samples if s is not None]
    out_path = f'/tmp/fresh_u64_{src_byte:02x}.json'
    with open(out_path, 'w') as f: json.dump(samples, f)
    print(f"  Saved {len(samples)} samples to {out_path}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


def main():
    for s in SRCS:
        print(f"\n=== Capturing fresh trace for src=0x{s:02x} ===")
        capture_for_src(s)


if __name__ == '__main__':
    main()
