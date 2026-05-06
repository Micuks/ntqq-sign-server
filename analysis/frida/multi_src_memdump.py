#!/usr/bin/env python3
"""Capture memory at op 0x60 entry for MULTIPLE srcs in the SAME process.
Same ASLR / heap layout — diffing memory dumps directly isolates src-dependent
bytes (i.e. src buffer location + cipher state derived from src).
"""
import frida, subprocess, os, time, sys, json

SRCS = [0x00, 0x42, 0xab]  # 3 different srcs

SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const OP60_ENTRY = WRAPPER_BASE.add(0x5ce6006);

let captures = [];
let curr_capture = null;
let tid = null;
let dumped_this_call = false;

function dumpMemoryFor(cpu, label) {
    const regs = {};
    ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
     'r8','r9','r10','r11','r12','r13','r14','r15','rip'].forEach(r => {
        try { regs[r] = cpu[r] ? cpu[r].toString() : '0'; } catch(_) {regs[r] = '?';}
    });
    const ranges = Process.enumerateRanges('rw-');  // only RW (where heap and stack are)
    const range_data = [];
    for (const r of ranges) {
        if (r.size > 0x200000) continue;  // skip very large
        try {
            const data = r.base.readByteArray(r.size);
            range_data.push({addr: r.base.toString(), size: r.size, data: data});
        } catch(_) {}
    }
    return {label: label, regs: regs, ranges: range_data};
}

Interceptor.attach(SIGN_FN, {
    onEnter: function(args) {
        if (curr_capture === null) return;  // not collecting
        dumped_this_call = false;
        tid = Process.getCurrentThreadId();
        Stalker.follow(tid, {
            transform: function(iterator) {
                let instr;
                while ((instr = iterator.next()) !== null) {
                    if (instr.address.equals(OP60_ENTRY) && !dumped_this_call) {
                        iterator.putCallout(function(context) {
                            if (dumped_this_call) return;
                            dumped_this_call = true;
                            const cap = dumpMemoryFor(context, curr_capture);
                            send({type:'capture', label: cap.label, regs: cap.regs});
                            for (let i = 0; i < cap.ranges.length; i++) {
                                send({type:'range', label: cap.label, idx: i,
                                      addr: cap.ranges[i].addr, size: cap.ranges[i].size},
                                     cap.ranges[i].data);
                            }
                            send({type:'capture_done', label: cap.label, n_ranges: cap.ranges.length});
                        });
                    }
                    iterator.keep();
                }
            }
        });
    },
    onLeave: function() {
        try { Stalker.unfollow(tid); Stalker.flush(); } catch(_) {}
    }
});

function rearmRecv() {
    recv('start_capture', function(msg) {
        curr_capture = msg.label;
        send({type:'log', msg: 'Now capturing for: ' + msg.label});
        rearmRecv();  // re-arm
    });
}
rearmRecv();

send({type:'ready'});
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
def sign_once(src_byte):
    sb = (ctypes.c_ubyte * 1)(src_byte)
    out = (ctypes.c_ubyte * 0x300)()
    ctypes.c_uint32.from_address(COUNTER).value = 100
    sf(b'wtlogin.login', sb, 1, 1, out)
    return bytes(out)[0x200:0x200+bytes(out)[0x2FF]]
_ = sign_once(0)
print('WARM_DONE', flush=True)
for line in sys.stdin:
    line = line.strip()
    if line.startswith('SIGN_'):
        sb = int(line.split('_')[1], 16)
        r = sign_once(sb)
        print(f'SIGN_RES_{sb:02x}={r.hex()}', flush=True)
    elif line == 'EXIT': break
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
    src = SCRIPT.replace('%WRAPPER_BASE%', hex(base)).replace('%SIGN_FN%', hex(base+0x56D81D1))
    script = session.create_script(src)

    captures = {}  # label -> {'regs': ..., 'ranges': {idx: {addr, size, data}}}
    done_labels = set()

    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'log': print(f"[s] {pl['msg']}")
            elif pl.get('type') == 'capture':
                captures[pl['label']] = {'regs': pl['regs'], 'ranges': {}}
            elif pl.get('type') == 'range':
                lbl = pl['label']
                captures[lbl]['ranges'][pl['idx']] = {
                    'addr': int(pl['addr'], 16), 'size': pl['size'], 'data': data}
            elif pl.get('type') == 'capture_done':
                done_labels.add(pl['label'])
                print(f"[s] {pl['label']} done: {pl['n_ranges']} ranges")
        elif msg['type'] == 'error':
            print(f"[err] {msg.get('description','')[:300]}")
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)

    for src_byte in SRCS:
        label = f'src_{src_byte:02x}'
        # Tell Frida to capture next call
        script.post({'type': 'start_capture', 'label': label})
        time.sleep(0.3)
        # Trigger sign
        p.stdin.write(f'SIGN_{src_byte:02x}\n'); p.stdin.flush()
        while True:
            line = p.stdout.readline().strip()
            if line.startswith(f'SIGN_RES_{src_byte:02x}='):
                print(f'[h] {line[:80]}...')
                break
        # Wait for capture
        for _ in range(60):
            if label in done_labels: break
            time.sleep(0.5)

    # Save captures
    for label, cap in captures.items():
        regs_int = {k: int(v, 16) for k, v in cap['regs'].items() if isinstance(v, str) and v.startswith('0x')}
        out_dir = f'/tmp/multi_src_{label}'
        os.makedirs(out_dir, exist_ok=True)
        meta = {'regs': regs_int, 'ranges': []}
        for idx, r in cap['ranges'].items():
            fname = f'{out_dir}/range_{idx:04d}.bin'
            with open(fname, 'wb') as f: f.write(r['data'])
            meta['ranges'].append({'addr': r['addr'], 'size': r['size'], 'file': fname})
        with open(f'/tmp/multi_src_{label}.json', 'w') as f:
            json.dump(meta, f, indent=2)
        print(f"  Saved {label}: {len(meta['ranges'])} ranges")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
