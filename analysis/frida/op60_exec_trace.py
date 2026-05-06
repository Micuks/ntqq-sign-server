#!/usr/bin/env python3
"""
Capture instruction-level exec trace within op 0x60 region (0x5ce0000-0x5cf0000)
plus 0x5ccdxxxx prelude. Log each instruction's address + register state via
Stalker.transform with callout instrumentation.

Output: /tmp/op60_exec_<src>.json — list of [insn_offset, reg_dump_dict]
"""
import frida, subprocess, os, time, sys, json

NUM_SRCS = int(os.environ.get('NUM_SRCS', '2'))
SRC_LIST = os.environ.get('SRC_LIST', '0x42,0x43').split(',')

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const RANGE_LO = WRAPPER_BASE.add(0x5cc0000);
const RANGE_HI = WRAPPER_BASE.add(0x5cf0000);

let tid = null;
let log = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        tid = Process.getCurrentThreadId();
        log = [];
        Stalker.follow(tid, {
            transform: function(iterator) {
                let instr;
                while ((instr = iterator.next()) !== null) {
                    const a = instr.address;
                    if (a.compare(RANGE_LO) >= 0 && a.compare(RANGE_HI) < 0) {
                        const off = a.sub(WRAPPER_BASE).toInt32();
                        iterator.putCallout(function(context) {
                            log.push(off);
                        });
                    }
                    iterator.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(_) {}
        // Send in chunks to avoid IPC overflow
        const CHUNK = 50000;
        for (let i = 0; i < log.length; i += CHUNK) {
            send({type:'chunk', data: log.slice(i, i+CHUNK)});
        }
        send({type:'done', total: log.length});
    }
});
send({type: 'ready'});
"""


def spawn_target():
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

    chunks = []
    state = {'done': False, 'total': 0}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'chunk':
                chunks.append(pl['data'])
            elif pl.get('type') == 'done':
                state['done'] = True
                state['total'] = pl['total']
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    for src_byte_str in SRC_LIST[:NUM_SRCS]:
        sb = int(src_byte_str, 16)
        chunks.clear(); state['done'] = False
        print(f'[main] Triggering sign for src=0x{sb:02x}...')
        p.stdin.write(f'SIGN_{sb:02x}\n'); p.stdin.flush()
        while True:
            line = p.stdout.readline().strip()
            print(f'[helper] {line}')
            if line.startswith(f'SIGN_RESULT_{sb:02x}='): break
        for _ in range(120):
            if state['done']: break
            time.sleep(0.5)
        all_offsets = []
        for c in chunks: all_offsets.extend(c)
        out_path = f'/tmp/op60_exec_{sb:02x}.json'
        with open(out_path, 'w') as f:
            json.dump(all_offsets, f)
        print(f'[main] Saved {len(all_offsets)} executed instructions for src=0x{sb:02x} -> {out_path}')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
