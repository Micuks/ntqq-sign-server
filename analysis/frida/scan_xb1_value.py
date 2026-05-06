#!/usr/bin/env python3
"""Hook every basic block during sign() and check if any register contains
0x114D0B11 (X_b1_init[0]). This finds where in the execution flow the hash
constant first appears — that's the END of op 0x60's hash computation.
"""
import frida, subprocess, os, time, sys, json

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const TARGET = 0x114D0B11;

let hits = [];
let tid = null;
let blockCount = 0;

function checkRegs(context) {
    blockCount++;
    const candidates = [
        Number(context.rax & 0xffffffff), Number(context.rbx & 0xffffffff),
        Number(context.rcx & 0xffffffff), Number(context.rdx & 0xffffffff),
        Number(context.rsi & 0xffffffff), Number(context.rdi & 0xffffffff),
        Number(context.r8 & 0xffffffff), Number(context.r9 & 0xffffffff),
        Number(context.r10 & 0xffffffff), Number(context.r11 & 0xffffffff),
        Number(context.r12 & 0xffffffff), Number(context.r13 & 0xffffffff),
        Number(context.r14 & 0xffffffff), Number(context.r15 & 0xffffffff),
    ];
    const reg_names = ['rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'];
    for (let i = 0; i < candidates.length; i++) {
        if (candidates[i] === TARGET) {
            const rip = context.rip.sub(WRAPPER_BASE).toInt32();
            hits.push({block: blockCount, rip: rip, reg: reg_names[i]});
            return;
        }
    }
}

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        tid = Process.getCurrentThreadId();
        hits = [];
        blockCount = 0;
        Stalker.follow(tid, {
            transform: function(iterator) {
                let instr;
                let firstInBlock = true;
                while ((instr = iterator.next()) !== null) {
                    const insn_off = instr.address.sub(WRAPPER_BASE).toInt32();
                    if (firstInBlock && insn_off > 0 && insn_off < 0x8000000) {
                        iterator.putCallout(checkRegs);
                        firstInBlock = false;
                    }
                    iterator.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(_) {}
        send({type: 'total_blocks', count: blockCount});
        const CHUNK = 1000;
        for (let i = 0; i < hits.length; i += CHUNK) {
            send({type:'chunk', data: hits.slice(i, i+CHUNK)});
        }
        send({type:'done', total: hits.length});
    }
});
send({type:'ready'});
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
sb = (ctypes.c_ubyte * 1)(0)
out = (ctypes.c_ubyte * 0x300)()
ctypes.c_uint32.from_address(COUNTER).value = 100
sf(b'wtlogin.login', sb, 1, 1, out)
print('WARM_DONE', flush=True)
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
    base = None
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('BASE='): base = int(line.split('=')[1], 16)
        if line == 'WARM_DONE': break

    session = frida.attach(p.pid)
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)

    chunks = []
    state = {'done': False, 'total_blocks': 0}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'chunk':
                chunks.append(pl['data'])
            elif pl.get('type') == 'total_blocks':
                state['total_blocks'] = pl['count']
            elif pl.get('type') == 'done':
                state['done'] = True
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line == 'SIGN_DONE': break

    for _ in range(180):
        if state['done']: break
        time.sleep(0.5)

    all_hits = []
    for c in chunks: all_hits.extend(c)
    print(f"\n[main] Total blocks executed: {state['total_blocks']}")
    print(f"[main] Hits where 0x114D0B11 in registers: {len(all_hits)}")
    if all_hits:
        # First hit = where the value first appears
        print(f"\nFirst 20 hits:")
        for h in all_hits[:20]:
            print(f"  block {h['block']:>5d}  RIP=0x{h['rip']:x}  reg={h['reg']}")
        # Last hit
        print(f"\nLast 5 hits:")
        for h in all_hits[-5:]:
            print(f"  block {h['block']:>5d}  RIP=0x{h['rip']:x}  reg={h['reg']}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
