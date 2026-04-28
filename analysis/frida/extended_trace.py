"""Capture VM trace with EXTENDED registers (300 regs instead of 150).
Maybe the unsolved ops read from regs >= 150."""
import frida, subprocess, os, time, json, sys

NUM_TRACES = 4  # just 4 src values
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
const allSamples = [];

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
                            let regArray = null;
                            try {
                                const ra = r14.add(0x10).readPointer();
                                const arr = new Uint32Array(NREGS);
                                for (let i = 0; i < NREGS; i++) {
                                    try { arr[i] = ra.add(i*8).readU32(); }
                                    catch(e) { arr[i] = 0xDEADBEEF; }
                                }
                                regArray = Array.from(arr);
                            } catch(e) {}
                            if (bytecodeBase === null) bytecodeBase = rax;
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
        allSamples.push(samples);
    }
});

recv('dump', function() {
    send({type: 'count', n_traces: allSamples.length, n_per: allSamples.length ? allSamples[0].length : 0});
    const CHUNK = 50;
    for (let t = 0; t < allSamples.length; t++) {
        const ts = allSamples[t];
        for (let i = 0; i < ts.length; i += CHUNK) {
            send({type: 'chunk', t: t, data: ts.slice(i, i+CHUNK), start: i});
        }
    }
    send({type: 'done'});
});

send({type: 'ready'});
"""

def spawn():
    helper = """
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
def sign_once(src_byte):
    sb = (ctypes.c_ubyte * 1)(src_byte)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = 100
    sf(b'wtlogin.login', sb, 1, 1, out)
    return bytes(out)[0x200:0x200+bytes(out)[0x2FF]]
_ = sign_once(0)
print('WARM_DONE', flush=True)
for line in sys.stdin:
    line = line.strip()
    if line.startswith('SIGN_'):
        sb = int(line.split('_')[1], 16)
        r = sign_once(sb)
        print(f'SIGN_RESULT_{sb:02x}={r.hex()}', flush=True)
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
        print(f'[h] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE': break
    
    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)
    
    all_traces = [None] * NUM_TRACES
    for i in range(NUM_TRACES):
        all_traces[i] = [None] * 17000
    n_recv = [0] * NUM_TRACES
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'count':
                print(f"[s] {pl['n_traces']} traces, {pl['n_per']} samples each")
            elif pl.get('type') == 'chunk':
                t = pl['t']
                start = pl['start']
                for i, s in enumerate(pl['data']):
                    if start + i < 17000:
                        all_traces[t][start + i] = s
                n_recv[t] += len(pl['data'])
            elif pl.get('type') == 'done':
                done[0] = True
        elif msg['type'] == 'error':
            print(f"[err] {msg.get('description','')[:200]}")
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)
    
    for sb in range(NUM_TRACES):
        p.stdin.write(f'SIGN_{sb:02x}\n'); p.stdin.flush()
        while True:
            line = p.stdout.readline().strip()
            if line.startswith(f'SIGN_RESULT_{sb:02x}='):
                print(f'[h] {line[:50]}...')
                break
    
    script.post({'type': 'dump'})
    deadline = time.time() + 1200
    while not done[0] and time.time() < deadline:
        time.sleep(2)
    
    for sb in range(NUM_TRACES):
        samples = [s for s in all_traces[sb] if s is not None]
        out_path = f'/tmp/ext_trace_{sb:02x}.json'
        with open(out_path, 'w') as f:
            json.dump(samples, f)
        print(f'  src=0x{sb:02x}: {len(samples)} samples -> {out_path}')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
