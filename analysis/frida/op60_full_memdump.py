#!/usr/bin/env python3
"""Dump ALL readable process memory ranges at op 0x60 entry, plus full register state.
Output saved as compact binary blobs + JSON manifest."""
import frida, subprocess, os, time, sys, json

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const OP60_ENTRY = WRAPPER_BASE.add(0x5ce6006);

let dumped = false;
let stalker_tid = null;

function dumpMemory(cpu) {
    if (dumped) return;
    dumped = true;
    // Capture full register state
    const regs = {};
    ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
     'r8','r9','r10','r11','r12','r13','r14','r15','rip','rflags'].forEach(r => {
        try { regs[r] = cpu[r] ? cpu[r].toString() : '0'; } catch(_) {regs[r] = '?';}
    });
    send({type: 'regs', regs: regs});
    // Enumerate all readable ranges
    const ranges = Process.enumerateRanges('r--');
    send({type: 'range_count', count: ranges.length});
    let idx = 0;
    for (const r of ranges) {
        try {
            // Skip very large ranges to avoid OOM
            if (r.size > 0x1000000) {
                send({type: 'range_skip', addr: r.base.toString(), size: r.size, reason: 'too_large'});
                continue;
            }
            const data = r.base.readByteArray(r.size);
            send({type: 'range', idx: idx, addr: r.base.toString(), size: r.size, prot: r.protection}, data);
            idx++;
        } catch(e) {
            send({type: 'range_skip', addr: r.base.toString(), size: r.size, reason: 'read_failed'});
        }
    }
    send({type: 'done', total: idx});
}

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        if (dumped) return;
        stalker_tid = Process.getCurrentThreadId();
        Stalker.follow(stalker_tid, {
            transform: function(iterator) {
                let instr;
                while ((instr = iterator.next()) !== null) {
                    if (instr.address.equals(OP60_ENTRY) && !dumped) {
                        iterator.putCallout(function(context) {
                            dumpMemory(context);
                        });
                    }
                    iterator.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(stalker_tid); Stalker.flush(); } catch(_) {}
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
SRC_BYTE = int(os.environ.get('SRC_BYTE', '0x00'), 16)
sb = (ctypes.c_ubyte * 1)(SRC_BYTE)
out = (ctypes.c_ubyte * 0x300)()
ctypes.c_uint32.from_address(COUNTER).value = 100
sf(b'wtlogin.login', sb, 1, 1, out)
print('WARM_DONE', flush=True)
import time
for line in sys.stdin:
    if line.strip() == 'SIGN':
        ctypes.c_uint32.from_address(COUNTER).value = 100
        sf(b'wtlogin.login', sb, 1, 1, out)
        print('SIGN_DONE', flush=True)
    elif line.strip() == 'EXIT': break
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

    state = {'regs': None, 'ranges': [], 'done': False}
    suffix = os.environ.get('DUMP_SUFFIX', '')
    range_data_dir = f'/tmp/op60_memdump{suffix}'
    os.makedirs(range_data_dir, exist_ok=True)
    range_data = {}  # idx -> bytes

    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            t = pl.get('type')
            if t == 'regs':
                state['regs'] = pl['regs']
            elif t == 'range_count':
                print(f'[main] {pl["count"]} ranges to dump')
            elif t == 'range':
                idx = pl['idx']
                state['ranges'].append({'idx': idx, 'addr': pl['addr'], 'size': pl['size'], 'prot': pl['prot']})
                if data: range_data[idx] = data
            elif t == 'range_skip':
                print(f'[main] skipped 0x{pl["addr"]} size={pl["size"]}: {pl["reason"]}')
            elif t == 'done':
                state['done'] = True
                print(f'[main] dump done, {pl["total"]} ranges')
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    print('[main] Triggering sign...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line == 'SIGN_DONE': break
        print(f'[helper] {line}')

    for _ in range(120):
        if state['done']: break
        time.sleep(0.5)

    if not state['regs']:
        print('[!] No state captured')
        sys.exit(1)

    # Save metadata + per-range files
    print(f'[main] Saving {len(state["ranges"])} ranges...')
    regs_int = {k: int(v, 16) if isinstance(v, str) and v.startswith('0x') else int(v) for k, v in state['regs'].items()}
    out_meta = {'wrapper_base': base, 'regs': regs_int, 'ranges': []}
    for r in state['ranges']:
        addr = int(r['addr'], 16)
        idx = r['idx']
        if idx in range_data:
            fname = f'/tmp/op60_memdump{suffix}/range_{idx:04d}.bin'
            with open(fname, 'wb') as f:
                f.write(range_data[idx])
            out_meta['ranges'].append({'addr': addr, 'size': r['size'], 'prot': r['prot'], 'file': fname})
    json_path = f'/tmp/op60_memdump{suffix}.json'
    with open(json_path, 'w') as f:
        json.dump(out_meta, f, indent=2)
    print(f'[main] Saved {json_path} with {len(out_meta["ranges"])} ranges')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
