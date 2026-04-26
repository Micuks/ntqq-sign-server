#!/usr/bin/env python3
"""Dump the VM bytecode buffer (found at 0x14c0c30 in test process).
We need to find this address dynamically each run, then dump 7-8KB.
"""
import frida, subprocess, os, time

PATTERN = "02 00 15 00 75 01 12 00"
DUMP_SIZE = 8192  # ~7KB bytecode + a bit


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');
const PATTERN = "%PATTERN%";

let inside = false;
let scanned = false;
let scanCount = 0;

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        scanned = false;
        scanCount = 0;
    },
    onLeave: function() {
        inside = false;
        send({type: 'done'});
    }
});

const HELPER = WRAPPER_BASE.add(0x5cccffa);
Interceptor.attach(HELPER, {
    onEnter: function(args) {
        if (!inside || scanned) return;
        scanCount++;
        if (scanCount < 100) return;
        scanned = true;

        const ranges = Process.enumerateRanges('r--');
        for (const r of ranges) {
            if (r.base.compare(WRAPPER_BASE) >= 0 && r.base.compare(WRAPPER_BASE.add(0x10000000)) < 0) continue;
            if (r.size > 0x10000000) continue;
            try {
                const found = Memory.scanSync(r.base, r.size, PATTERN);
                for (const m of found) {
                    const data = m.address.readByteArray(%DUMP_SIZE%);
                    send({type: 'bytecode', addr: m.address.toString(), bytes: Array.from(new Uint8Array(data))});
                }
            } catch(e) {}
        }
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
                .replace('%PATTERN%', PATTERN) \
                .replace('%DUMP_SIZE%', str(DUMP_SIZE))
    script = session.create_script(src)
    bytecodes = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'bytecode':
                bytecodes.append(pl)
                print(f"[script] Got bytecode at {pl['addr']}, {len(pl['bytes'])} bytes")
            elif pl.get('type') == 'done':
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
    deadline = time.time() + 60
    while not done[0] and time.time() < deadline:
        time.sleep(0.5)

    if bytecodes:
        bc = bytecodes[0]
        out_path = '/tmp/vm_bytecode.bin'
        with open(out_path, 'wb') as f:
            f.write(bytes(bc['bytes']))
        print(f"\nSaved bytecode to {out_path}: {len(bc['bytes'])} bytes from addr {bc['addr']}")

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
