"""Capture memory reads during op 0x1a execution via Frida.

Approach: when the dispatcher runs ib=(26, 46, 13, 0), follow next ~50 instructions
and capture (instruction_addr, memory_read_addr, value).
"""
import frida, subprocess, os, time, json, sys


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const DISPATCHER_OFF = 0x5cd3685;

let inside = false;
let tid = null;
let trackingOp1a = false;
let trackInstrCount = 0;
const memReads = [];

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        memReads.length = 0;
        trackingOp1a = false;
        trackInstrCount = 0;
        Stalker.follow(tid, {
            transform: function(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    if (ins.address.equals(WRAPPER_BASE.add(DISPATCHER_OFF))) {
                        // At dispatcher: check if this is op 0x1a ib=(26,46,13,0)
                        iter.putCallout(function(ctx) {
                            if (memReads.length >= 5000) return;
                            try {
                                const ib = new Uint8Array(ctx.rax.readByteArray(4));
                                if (ib[0] === 26 && ib[1] === 46 && ib[2] === 13 && ib[3] === 0) {
                                    trackingOp1a = true;
                                    trackInstrCount = 0;
                                    // Save r13 value at this point
                                    const r14 = ctx.r14;
                                    const ra = r14.add(0x10).readPointer();
                                    const r13_val = ra.add(13*8).readU32();
                                    memReads.push({type:'op1a_start', r13: r13_val, ts: memReads.length});
                                } else {
                                    trackingOp1a = false;
                                }
                            } catch(e) {}
                        });
                    } else if (trackingOp1a) {
                        // Try to detect MOV/LOAD instructions
                        // For simplicity, just trace a few following instructions
                        const insAddr = ins.address;
                        const insStr = ins.toString();
                        // Capture address & memory read value for instructions that look like loads
                        if (insStr.indexOf('mov ') === 0 || insStr.indexOf('movzx ') === 0 || insStr.indexOf('movsx ') === 0) {
                            iter.putCallout(function(ctx) {
                                if (!trackingOp1a || trackInstrCount > 30) {
                                    trackingOp1a = false;
                                    return;
                                }
                                trackInstrCount++;
                                // Just log addresses being touched
                                try {
                                    memReads.push({
                                        type: 'instr',
                                        addr: insAddr.toString(),
                                        ins: insStr,
                                        ts: memReads.length,
                                        rax: ctx.rax.toString(),
                                        rbx: ctx.rbx.toString(),
                                        rcx: ctx.rcx.toString(),
                                        rdx: ctx.rdx.toString(),
                                        rsi: ctx.rsi.toString(),
                                        rdi: ctx.rdi.toString(),
                                        r8: ctx.r8.toString(),
                                        r9: ctx.r9.toString(),
                                        r10: ctx.r10.toString(),
                                        r11: ctx.r11.toString(),
                                        r12: ctx.r12.toString(),
                                        r13: ctx.r13.toString(),
                                        r14: ctx.r14.toString(),
                                    });
                                } catch(e) {}
                            });
                        }
                    }
                    iter.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(e) {}
        inside = false;
        send({type: 'count', n: memReads.length});
        const CHUNK = 100;
        for (let i = 0; i < memReads.length; i += CHUNK) {
            send({type: 'chunk', data: memReads.slice(i, i+CHUNK), start: i});
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
        print(f'SIGN_RESULT={r.hex()[:30]}', flush=True)
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
                .replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)
    samples = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'count':
                print(f"[s] capturing {pl['n']} events")
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
        if line.startswith('SIGN_RESULT='):
            print(f'[h] {line[:50]}')
            break
    deadline = time.time() + 600
    while not done[0] and time.time() < deadline:
        time.sleep(2)

    print(f'\nCaptured {len(samples)} events')
    with open('/tmp/op1a_mem_capture.json','w') as f:
        json.dump(samples, f)
    print('Saved /tmp/op1a_mem_capture.json')

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
