#!/usr/bin/env python3
"""Try several candidate dispatch instruction offsets in current wrapper.node.
For each, instrument with a hit counter. The dispatch should hit ~16186 times per sign.

Old dispatch was at base+0x5F56328 (sign at 0x5F4DB51), offset from sign = 0x87D7.
Current sign is at base+0x56D81D1.

Candidates:
  base+0x56D81D1+0x87D7 = base+0x56E09A8 (same offset from sign)
  Various nearby offsets
"""
import frida, subprocess, os, time, json

# Candidate offsets to test
CANDIDATES = [
    0x56E09A8,   # +0x87D7 from sign
    0x56DA000,
    0x56DAFFF,
    0x56E0000,
    0x56E2000,
    0x56E5000,
]

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const CANDS = %CANDS%;

let inside = false;
let tid = null;
let counts = {};
let opSeq = [];   // sequence of (addr, rax_byte, ib[0..3]) for first matching candidate

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        counts = {};
        for (const c of CANDS) counts[c] = 0;
        opSeq = [];
        Stalker.follow(tid, {
            events: { exec: false },
            transform: function(iter) {
                let ins = iter.next();
                do {
                    const insAddrStr = ins.address.toString();
                    // Convert ins.address (ptr) to relative offset for matching
                    let offHex;
                    try {
                        const off = ins.address.sub(WRAPPER_BASE).toInt32();
                        if (off >= 0 && off < 0x10000000) offHex = off;
                        else offHex = -1;
                    } catch(e) { offHex = -1; }
                    if (offHex >= 0 && CANDS.indexOf(offHex) !== -1) {
                        iter.putCallout(function(ctx) {
                            counts[offHex] = (counts[offHex] || 0) + 1;
                        });
                    }
                    iter.keep();
                } while ((ins = iter.next()) !== null);
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(e) {}
        inside = false;
        send({type: 'done', counts: counts});
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
    raw = bytes(out)
    return raw[0x200:0x200+raw[0x2FF]]
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
    assert base is not None

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1)) \
                .replace('%CANDS%', json.dumps(CANDIDATES))
    script = session.create_script(src)
    result = {}
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'done':
                result.update(pl)
        elif msg['type'] == 'error':
            print(f'[error] {msg.get("description", "")[:300]}')
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
    time.sleep(15.0)

    counts = result.get('counts', {})
    print('\nDispatch candidate hit counts (should be ~16186 for the real one):')
    for c in CANDIDATES:
        cnt = counts.get(str(c), counts.get(c, 0))
        marker = ' ← MATCH!' if 15500 < cnt < 17000 else ''
        print(f"  base+0x{c:08x}: {cnt}{marker}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
