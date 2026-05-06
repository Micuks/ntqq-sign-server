#!/usr/bin/env python3
"""
Stalker-based capture of op 0x60's inner basic-block execution path.

Per the captured u64 trace, op 0x60 fires exactly once per sign() call
(at VM step 1784516, trace index 2788, with ib=[96, 0, 2, 0]).

Strategy:
- Hook sign() entry; start Stalker with both 'block' and 'compile' events on
- During sign(), record (block_start, block_end, basic_block_count) for ALL blocks
- Compare counts across many srcs to find blocks that only execute during op 0x60
  (since op 0x60 fires once per sign, those blocks have count==1 per sign call)

Output: /tmp/op60_blocks_<src>.json — list of basic blocks executed during sign(),
with execution counts. Use diff across srcs to isolate hash-mixing blocks.
"""
import frida, subprocess, os, time, sys, json

NUM_SRCS = int(os.environ.get('NUM_SRCS', '8'))

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let tid = null;
let blockSeq = [];   // ordered list of [block_start_offset, block_end_offset]
let blockSet = {};

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        tid = Process.getCurrentThreadId();
        blockSeq = [];
        blockSet = {};
        Stalker.follow(tid, {
            events: { block: true },
            onReceive: function(events) {
                const parsed = Stalker.parse(events);
                for (const e of parsed) {
                    if (e[0] === 'block') {
                        const s = e[1], en = e[2];
                        try {
                            const so = s.sub(WRAPPER_BASE).toInt32();
                            const eo = en.sub(WRAPPER_BASE).toInt32();
                            if (so >= 0 && so < 0x8000000) {
                                blockSeq.push([so, eo]);
                                const key = so.toString(16);
                                blockSet[key] = (blockSet[key] || 0) + 1;
                            }
                        } catch(_) {}
                    }
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(_) {}
        send({type: 'done', seq: blockSeq, set: blockSet});
    }
});
send({type: 'ready'});
"""


def spawn_target():
    helper = r"""
import ctypes, os, sys, json
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
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)

    pending = {}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'done':
                pending['done'] = pl
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    # Capture for 8 different srcs
    for src_byte in range(NUM_SRCS):
        pending.clear()
        print(f'[main] Triggering sign for src=0x{src_byte:02x}...')
        p.stdin.write(f'SIGN_{src_byte:02x}\n'); p.stdin.flush()
        # Wait for sign result
        while True:
            line = p.stdout.readline().strip()
            print(f'[helper] {line}')
            if line.startswith(f'SIGN_RESULT_{src_byte:02x}='): break
        # Wait for stalker done
        for _ in range(60):
            if 'done' in pending: break
            time.sleep(0.2)
        if 'done' not in pending:
            print(f'[!] No stalker done for src=0x{src_byte:02x}')
            continue
        out_path = f'/tmp/op60_blocks_{src_byte:02x}.json'
        with open(out_path, 'w') as f:
            json.dump({'seq': pending['done']['seq'], 'set': pending['done']['set']}, f)
        print(f'[main] Saved {len(pending["done"]["seq"])} block events for src=0x{src_byte:02x} -> {out_path}')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
