#!/usr/bin/env python3
"""Capture every memory READ that happens during sign() execution.

Uses Frida Stalker with transform mode + a memory-write callback at
each memory-load instruction. Records (instruction_addr, target_addr, value).

Combined with the existing register diff trace, this provides everything
needed to model the VM's memory in pure Python.

Memory accesses needed for sign:
  - Bytecode reads (PC-driven; into bytecode buffer)
  - Register array reads (rdi+0x10 indexed by ops)
  - Constant table reads (SBOX, round keys, etc.)
  - Heap scratch buffer reads (intermediate cipher state)
"""
import frida, subprocess, os, time, json


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let inside = false;
let tid = null;
let reads = [];
let MAX_READS = 100000;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        reads = [];
        Stalker.follow(tid, {
            transform: function(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    // Only instrument memory loads
                    let isLoad = false;
                    try {
                        const m = ins.mnemonic;
                        if (m === 'mov' || m === 'movzx' || m === 'movsx' ||
                            m === 'movd' || m === 'movq') {
                            // Check if source operand is memory
                            const opStr = ins.opStr;
                            const parts = opStr.split(',');
                            if (parts.length === 2 && parts[1].includes('[')) {
                                isLoad = true;
                            }
                        }
                    } catch(e) {}
                    if (isLoad && reads.length < MAX_READS) {
                        const insAddr = ins.address;
                        const opStr = ins.opStr;
                        iter.putCallout(function(ctx) {
                            if (reads.length >= MAX_READS) return;
                            // Best-effort: parse the memory operand to get target addr
                            // For now, just record the instruction address
                            reads.push({
                                ins: insAddr.sub(WRAPPER_BASE).toInt32(),
                                op: opStr,
                            });
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
        // Send in chunks
        for (let i = 0; i < reads.length; i += 1000) {
            send({type: 'chunk', reads: reads.slice(i, i+1000)});
        }
        send({type: 'done', total: reads.length});
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
    all_reads = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'chunk':
                all_reads.extend(pl['reads'])
            elif pl.get('type') == 'done':
                done[0] = True
                print(f"[script] Total mem-load instructions seen: {pl['total']}")
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
    deadline = time.time() + 60
    while not done[0] and time.time() < deadline:
        time.sleep(0.5)

    print(f'\n=== Captured {len(all_reads)} memory load instructions ===')
    # Most-frequent load addresses
    from collections import Counter
    counter = Counter(r['ins'] for r in all_reads)
    print('\nTop 20 most-frequent load instructions:')
    for ins_off, cnt in counter.most_common(20):
        print(f"  w+0x{ins_off:08x}: {cnt}")

    with open('/tmp/mem_loads.json', 'w') as f:
        json.dump(all_reads, f)
    print(f"\nSaved to /tmp/mem_loads.json")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
