"""Capture the call stack / instruction path when op 0x1a runs.

Use Stalker to log next ~20 instructions executed AFTER the dispatcher fires for op 0x1a.
This tells us the ACTUAL handler address.
"""
import frida, subprocess, os, time, json

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const DISPATCHER_OFF = 0x5cd3685;

let inside = false;
let tid = null;
let firstOp1a = null;  // first time we see op 0x1a, capture path
let trackingCount = 0;

const allEvents = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        firstOp1a = null;
        trackingCount = 0;
        Stalker.follow(tid, {
            transform: function(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    const insAddr = ins.address;
                    const insAddr_offset = insAddr.sub(WRAPPER_BASE).toInt32();

                    if (insAddr.equals(WRAPPER_BASE.add(DISPATCHER_OFF))) {
                        iter.putCallout(function(ctx) {
                            try {
                                const ib = new Uint8Array(ctx.rax.readByteArray(4));
                                if (ib[0] === 26 && ib[1] === 46 && ib[2] === 13 && ib[3] === 0 && firstOp1a === null) {
                                    firstOp1a = true;
                                    trackingCount = 0;
                                    const r14 = ctx.r14;
                                    const ra = r14.add(0x10).readPointer();
                                    const r13_val = ra.add(13*8).readU32();
                                    allEvents.push({type: 'op1a_entry', r13: r13_val});
                                }
                            } catch(e) {}
                        });
                    } else if (firstOp1a) {
                        // Only track first 50 instructions after op 0x1a entry
                        const offCopy = insAddr_offset;
                        iter.putCallout(function(ctx) {
                            if (trackingCount > 100) { firstOp1a = false; return; }
                            trackingCount++;
                            try {
                                allEvents.push({
                                    type: 'instr',
                                    off: offCopy,
                                    rax: ctx.rax.toInt32(),
                                    rbx: ctx.rbx.toInt32(),
                                    rcx: ctx.rcx.toInt32(),
                                    rdx: ctx.rdx.toInt32(),
                                    rsi: ctx.rsi.toInt32(),
                                    rdi: ctx.rdi.toInt32(),
                                    r8: ctx.r8.toInt32(),
                                    r9: ctx.r9.toInt32(),
                                });
                            } catch(e) {}
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
        send({type: 'count', n: allEvents.length});
        const CHUNK = 50;
        for (let i = 0; i < allEvents.length; i += CHUNK) {
            send({type: 'chunk', data: allEvents.slice(i, i+CHUNK)});
        }
        send({type: 'done'});
    }
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
        print('SIGN_DONE', flush=True)
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
        print(f'[h] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE': break

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base + 0x56D81D1))
    script = session.create_script(src)
    samples = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'count':
                print(f"[s] captured {pl['n']} events")
            elif pl.get('type') == 'chunk':
                samples.extend(pl['data'])
            elif pl.get('type') == 'done':
                done[0] = True
        elif msg['type'] == 'error':
            print(f"[err] {msg.get('description','')[:200]}")
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line == 'SIGN_DONE': break
    deadline = time.time() + 60
    while not done[0] and time.time() < deadline:
        time.sleep(2)
    print(f'\nCaptured {len(samples)} events')
    json.dump(samples, open('/tmp/op1a_path.json', 'w'))

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
