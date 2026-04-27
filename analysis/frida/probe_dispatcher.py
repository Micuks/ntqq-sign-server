#!/usr/bin/env python3
"""For each dispatcher candidate (w+0x5cd024c, w+0x5cd3685, etc.), hook it
and capture (rax, rbp, r14, register dump) at each hit. Compare against the
known opcode sequence from the OLD trace.
"""
import frida, subprocess, os, time, json


CANDIDATES = [
    0x5cd024c, 0x5cd0252, 0x5cd3685, 0x5cd368c, 0x5cd3693, 0x5cd369a,
    0x5cd369f, 0x5cd36a4, 0x5cd36a7, 0x5cd36ae, 0x5cd36b5, 0x5cd36bc, 0x5cd36c3,
    0x5ccf553, 0x5cd0234, 0x5cd023a, 0x5cd0240, 0x5cd0246,
]
TARGET_OFF = 0x5cd3685  # primary candidate to inspect deeply


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const TARGETS = %TARGETS%;
const TARGET_OFF = %TARGET_OFF%;

let inside = false;
let tid = null;
const counts = {};
const samples = {};  // first 100 hits per target

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        tid = Process.getCurrentThreadId();
        for (const k in counts) delete counts[k];
        for (const k in samples) delete samples[k];
        Stalker.follow(tid, {
            transform: function(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    const off = ins.address.sub(WRAPPER_BASE).toInt32();
                    if (TARGETS.indexOf(off) !== -1) {
                        const offCopy = off;
                        iter.putCallout(function(ctx) {
                            counts[offCopy] = (counts[offCopy] || 0) + 1;
                            // Capture deep state for the primary target
                            if (offCopy === TARGET_OFF) {
                                if (!samples[offCopy]) samples[offCopy] = [];
                                if (samples[offCopy].length < 50) {
                                    // rax (opcode candidate), rbp, r14, rsi, rdi
                                    let regArrayDump = null;
                                    try {
                                        const r14 = ctx.r14;
                                        // Try r14+0x10 = register array pointer
                                        const ra = r14.add(0x10).readPointer();
                                        // Read 16 u64 from there
                                        const dump = [];
                                        for (let i = 0; i < 32; i++) {
                                            try {
                                                dump.push(ra.add(i*8).readU32());
                                            } catch(e) { dump.push(0); }
                                        }
                                        regArrayDump = dump;
                                    } catch(e) {}
                                    samples[offCopy].push({
                                        idx: counts[offCopy] - 1,
                                        rax: ctx.rax.toString(),
                                        rcx: ctx.rcx.toString(),
                                        rsi: ctx.rsi.toString(),
                                        rdi: ctx.rdi.toString(),
                                        rbp: ctx.rbp.toString(),
                                        r14: ctx.r14.toString(),
                                        r15: ctx.r15.toString(),
                                        regArray: regArrayDump,
                                    });
                                }
                            }
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
        send({type: 'counts', counts: counts});
        send({type: 'samples', samples: samples});
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
                .replace('%SIGN_FN%', hex(base+0x56D81D1)) \
                .replace('%TARGETS%', json.dumps(CANDIDATES)) \
                .replace('%TARGET_OFF%', str(TARGET_OFF))
    script = session.create_script(src)
    counts = {}
    samples = {}
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'counts':
                counts.update(pl['counts'])
            elif pl.get('type') == 'samples':
                samples.update(pl['samples'])
                done[0] = True
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
    deadline = time.time() + 240
    while not done[0] and time.time() < deadline:
        time.sleep(1)

    print(f'\n=== Counts ===')
    for off, cnt in sorted(counts.items()):
        print(f"  w+0x{int(off):x}: {cnt}")

    # Compare samples to OLD trace
    if str(TARGET_OFF) in samples:
        sps = samples[str(TARGET_OFF)]
    elif TARGET_OFF in samples:
        sps = samples[TARGET_OFF]
    else:
        sps = []
    print(f'\n=== First 5 samples at w+0x{TARGET_OFF:x} ===')
    for s in sps[:5]:
        rax = int(s['rax'], 16)
        print(f"  idx={s['idx']} rax=0x{rax:016x}  (low 8 = 0x{rax & 0xff:02x})")
        if s.get('regArray'):
            print(f"      regArray[0..15] = {[hex(x) for x in s['regArray'][:16]]}")
    # Compare rax low byte to opcode sequence from trace
    trace = json.load(open('/tmp/complete_trace_00.json'))
    print(f'\n=== Comparing rax low byte to trace opcode sequence ===')
    matches = 0
    mismatches = []
    for i, s in enumerate(sps[:30]):
        if i >= len(trace): break
        trace_op = trace[i][1]
        rax = int(s['rax'], 16)
        if (rax & 0xff) == trace_op:
            matches += 1
        else:
            mismatches.append((i, trace_op, rax & 0xff))
    print(f"  {matches}/{min(30, len(sps))} matches in first 30")
    if mismatches[:5]:
        print(f"  First mismatches (i, expected_op, rax_low):")
        for m in mismatches[:5]:
            print(f"    {m}")

    # If no match for low byte, try other regs
    if matches < 5:
        for reg_name in ['rcx', 'rsi', 'rdi', 'rbp', 'r14', 'r15']:
            tries = 0
            for i, s in enumerate(sps[:30]):
                if i >= len(trace): break
                trace_op = trace[i][1]
                v = int(s.get(reg_name, '0'), 16) & 0xff
                if v == trace_op: tries += 1
            print(f"  {reg_name} low byte matches op: {tries}/30")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
