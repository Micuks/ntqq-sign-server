#!/usr/bin/env python3
"""Hook every memory write during sign() and find writes whose VALUES match
the expected X_b1_init pattern (0x114D0B11 etc.). The instruction performing
that write IS the end of op 0x60's hash function — we can capture state RIGHT
THERE and run Unicorn from a known-good point.
"""
import frida, subprocess, os, time, sys, json

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

const TARGET_VAL_LO = 0x114D0B11;  // X_b1_init[0] = 0x114D0B11 for cmd=wtlogin.login
const TARGET_VAL_2  = 0xFC57448F;  // X_b1_init[2] for src=0x00

let hits = [];
let tid = null;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        tid = Process.getCurrentThreadId();
        hits = [];
        Stalker.follow(tid, {
            transform: function(iterator) {
                let instr;
                while ((instr = iterator.next()) !== null) {
                    // Look for instructions that write 32-bit values to memory.
                    // Most x86 stores are 'mov [mem], reg' or 'mov [mem], imm'
                    // Or 'mov dword ptr [...], reg32' — capstone mnemonic 'mov'
                    if (instr.mnemonic === 'mov' && instr.operands.length === 2 &&
                        instr.operands[0].type === 'mem' &&
                        (instr.operands[1].type === 'reg' || instr.operands[1].type === 'imm')) {
                        // Add a callout that checks the value being written
                        const insn_addr = instr.address;
                        const insn_off = insn_addr.sub(WRAPPER_BASE).toInt32();
                        // Only watch wrapper.node code
                        if (insn_off > 0 && insn_off < 0x8000000) {
                            iterator.putCallout(function(context) {
                                // For mov [mem], reg/imm: check value about to be written
                                // We can read the value FROM the source operand
                                // but simpler: after the mov, read [mem]. Need post-execution callout.
                                // Approximate: check if RAX/RBX/etc. low 32 bits == target
                                const candidates = [
                                    context.rax & 0xffffffff, context.rbx & 0xffffffff,
                                    context.rcx & 0xffffffff, context.rdx & 0xffffffff,
                                    context.rsi & 0xffffffff, context.rdi & 0xffffffff,
                                    context.r8 & 0xffffffff, context.r9 & 0xffffffff,
                                    context.r10 & 0xffffffff, context.r11 & 0xffffffff,
                                    context.r12 & 0xffffffff, context.r13 & 0xffffffff,
                                    context.r14 & 0xffffffff, context.r15 & 0xffffffff,
                                ];
                                const lo32 = TARGET_VAL_LO & 0xffffffff;
                                for (let i = 0; i < candidates.length; i++) {
                                    if (Number(candidates[i]) === lo32) {
                                        hits.push({insn_off: insn_off, target: 'X_b1[0]'});
                                        break;
                                    }
                                    if (Number(candidates[i]) === (TARGET_VAL_2 & 0xffffffff)) {
                                        hits.push({insn_off: insn_off, target: 'X_b1[2]'});
                                        break;
                                    }
                                }
                            });
                        }
                    }
                    iterator.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(_) {}
        // Send hits in chunks
        const CHUNK = 5000;
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
    state = {'done': False, 'total': 0}
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'chunk':
                chunks.append(pl['data'])
            elif pl.get('type') == 'done':
                state['done'] = True; state['total'] = pl['total']
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        if line == 'SIGN_DONE': break
    for _ in range(120):
        if state['done']: break
        time.sleep(0.5)

    all_hits = []
    for c in chunks: all_hits.extend(c)
    print(f"\n[main] Total hits: {len(all_hits)}")
    # Group by insn_off and target
    from collections import Counter
    counter = Counter()
    for h in all_hits: counter[(h['insn_off'], h['target'])] += 1
    print("Top offsets where target value appeared in registers:")
    for (off, tgt), c in counter.most_common(50):
        print(f"  offset 0x{off:x} target={tgt}  count={c}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
