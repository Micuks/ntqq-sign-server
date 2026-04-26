#!/usr/bin/env python3
"""Dump a large context around the 20-byte XOR region to identify the buffer structure."""
import frida, subprocess, os, time

TARGET_XOR = bytes.fromhex('550504a20fd4f219c36087685573c224881743b7')

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const HOOK_FN = WRAPPER_BASE.add(0x5cccffa);
const TARGET_STR = '%TARGET_HEX_SPACED%';

let insideSign = false;
let callIdx = 0;
let hits = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function(args) {
        insideSign = true;
        callIdx = 0;
        hits = [];
    },
    onLeave: function() {
        insideSign = false;
        send({type: 'sign_done', hits: hits});
    }
});

Interceptor.attach(HOOK_FN, {
    onEnter: function(args) {
        if (!insideSign) return;
        callIdx++;
        // Scan less frequently, capture multiple snapshots
        if (callIdx % 10 !== 0) return;
        const rwRanges = Process.enumerateRanges({protection: 'rw-', coalesce: true})
                    .filter(r => r.size < 0x2000000 && r.size > 0x1000).slice(0, 200);
        for (const r of rwRanges) {
            try {
                const found = Memory.scanSync(r.base, r.size, TARGET_STR);
                if (found.length > 0) {
                    const addr = found[0].address;
                    // Dump 512 bytes around it
                    try {
                        const before = Array.from(new Uint8Array(addr.sub(256).readByteArray(256)));
                        const after = Array.from(new Uint8Array(addr.add(20).readByteArray(256)));
                        hits.push({
                            callIdx: callIdx, addr: addr.toString(),
                            before: before, after: after
                        });
                    } catch(e) {}
                    return;  // only record first hit per snapshot
                }
            } catch(e) {}
        }
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
    tgt_spaced = ' '.join(f'{b:02x}' for b in TARGET_XOR)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)) \
                .replace('%SIGN_FN%', hex(base+0x56D81D1)) \
                .replace('%TARGET_HEX_SPACED%', tgt_spaced)
    script = session.create_script(src)

    result = {}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'sign_done':
                result['hits'] = pl['hits']
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    print('[main] triggering sign...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break
    time.sleep(2.0)

    hits = result.get('hits', [])
    print(f'\n[main] {len(hits)} hits recorded')
    if hits:
        # First hit: show full context
        h = hits[0]
        print(f'\nFirst hit at call #{h["callIdx"]}, addr={h["addr"]}')
        before = bytes(h['before'])
        after = bytes(h['after'])
        full = before + TARGET_XOR + after
        print(f'Full 532-byte dump centered on XOR bytes:')
        for off in range(0, len(full), 32):
            chunk = full[off:off+32]
            # Mark the 20-byte target
            rel_off = off - 256  # offset relative to target start
            marker = ' <-- XOR HERE' if -10 <= rel_off <= 0 else ''
            print(f'  +{rel_off:+5d}: {chunk.hex()} {marker}')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
