#!/usr/bin/env python3
"""Capture full register state and key memory regions at the entry to op 0x60's
inner CFF block (0x5ce6006).

Output:
  /tmp/op60_state.bin  - binary blob: regs + stack region + heap candidates
  /tmp/op60_state.json - metadata: register values, memory region addresses
"""
import frida, subprocess, os, time, sys, json, struct

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const OP60_ENTRY = WRAPPER_BASE.add(0x5ce6006);

let captured = false;
let stalker_tid = null;
let result = null;

function captureState(cpu) {
    // Read all GPRs
    const regs = {};
    ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
     'r8','r9','r10','r11','r12','r13','r14','r15','rip','rflags'].forEach(r => {
        try { regs[r] = cpu[r] ? cpu[r].toString() : '0'; } catch(_) {regs[r] = '?';}
    });
    // Capture stack [rsp - 0x100, rsp + 0x4000]
    const rsp = ptr(cpu.rsp);
    const stack_start = rsp.sub(0x100);
    const stack_end = rsp.add(0x4000);
    const stack_data = stack_start.readByteArray(stack_end.sub(stack_start).toInt32());
    // VM context is pointed to by some register — the trace shows
    // r12=0x9f2a41e0, r14=0x1bbf870 as candidates (VA from snapshot).
    // Capture data at these addresses too.
    const ctx_dumps = {};
    ['r12','r13','r14','r15','rbx','rbp'].forEach(r => {
        const v = ptr(cpu[r]);
        if (v.isNull()) return;
        try {
            const data = v.readByteArray(0x400);
            ctx_dumps[r] = {addr: v.toString(), len: 0x400};
        } catch(e) {}
    });
    return {regs, stack_addr: stack_start.toString(), stack_len: 0x4100, ctx_dumps};
}

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        if (captured) return;
        stalker_tid = Process.getCurrentThreadId();
        const me = this;
        Stalker.follow(stalker_tid, {
            transform: function(iterator) {
                let instr;
                while ((instr = iterator.next()) !== null) {
                    if (instr.address.equals(OP60_ENTRY) && !captured) {
                        captured = true;
                        iterator.putCallout(function(context) {
                            const state = captureState(context);
                            const stack_data = ptr(state.stack_addr).readByteArray(state.stack_len);
                            // Send ctx dumps as separate messages
                            send({type: 'state', regs: state.regs, stack_addr: state.stack_addr,
                                  stack_len: state.stack_len, ctx_dumps: state.ctx_dumps}, stack_data);
                            for (const r in state.ctx_dumps) {
                                const dump = state.ctx_dumps[r];
                                try {
                                    const d = ptr(dump.addr).readByteArray(dump.len);
                                    send({type: 'ctx', reg: r, addr: dump.addr, len: dump.len}, d);
                                } catch(e) {}
                            }
                            send({type: 'state_done'});
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
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)

    state = {}
    ctx_dumps = []
    state_done = [False]
    def on_message(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'state':
                state.update(pl)
                state['stack_data'] = data
            elif pl.get('type') == 'ctx':
                ctx_dumps.append({'reg': pl['reg'], 'addr': pl['addr'], 'len': pl['len'], 'data': data})
            elif pl.get('type') == 'state_done':
                state_done[0] = True
        elif msg['type'] == 'error':
            print(f"[frida err] {msg}")
    script.on('message', on_message)
    script.load()
    time.sleep(0.5)

    print('[main] Triggering sign...')
    p.stdin.write('SIGN\n'); p.stdin.flush()
    while True:
        line = p.stdout.readline().strip()
        print(f'[helper] {line}')
        if line.startswith('SIGN_RESULT='): break

    for _ in range(60):
        if state_done[0]: break
        time.sleep(0.5)

    if not state:
        print('[!] No state captured')
        sys.exit(1)

    # Save
    print(f'[main] Captured state: {list(state.get("regs",{}).keys())[:5]}...')
    print(f'[main] Stack data: {len(state.get("stack_data", b""))} bytes')
    print(f'[main] Context dumps: {len(ctx_dumps)}')
    # Convert reg values to int (hex strings -> int)
    regs_int = {}
    for k, v in state.get('regs', {}).items():
        try:
            if isinstance(v, str) and v.startswith('0x'): regs_int[k] = int(v, 16)
            else: regs_int[k] = int(v)
        except: regs_int[k] = 0

    out_meta = {
        'wrapper_base': base,
        'regs': regs_int,
        'stack_addr': int(state['stack_addr'], 16),
        'stack_len': state['stack_len'],
        'ctx_dumps': [{'reg': c['reg'], 'addr': int(c['addr'], 16), 'len': c['len']} for c in ctx_dumps],
    }
    with open('/tmp/op60_state.json', 'w') as f:
        json.dump(out_meta, f, indent=2)
    with open('/tmp/op60_state_stack.bin', 'wb') as f:
        f.write(state['stack_data'])
    for c in ctx_dumps:
        with open(f'/tmp/op60_state_ctx_{c["reg"]}.bin', 'wb') as f:
            f.write(c['data'])
    print(f'[main] Saved /tmp/op60_state.json and stack/ctx blobs')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
