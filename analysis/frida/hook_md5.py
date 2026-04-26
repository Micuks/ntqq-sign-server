#!/usr/bin/env python3
"""Hook XP_MD5_Update and XP_MD5_Final inside wrapper.node to capture every
piece of data that gets hashed during a single sign() call.

This will reveal all the MD5 inputs the sign algorithm uses, including any
nested or derived hashes that produce X_b1_init / X_b2[1].
"""
import frida, subprocess, os, time, json


SCRIPT = r"""
'use strict';
const WRAPPER_BASE = ptr('%WRAPPER_BASE%');
const SIGN_FN = ptr('%SIGN_FN%');

let inside = false;
const events = [];
const md5Updates = {};  // ctx -> list of byte arrays appended

const md5Update = Module.getGlobalExportByName( 'XP_MD5_Update');
const md5Final = Module.getGlobalExportByName( 'XP_MD5_Final');
const md5Init = Module.getGlobalExportByName( 'XP_MD5_Init');
const md5HashBuffer = Module.getGlobalExportByName( 'XP_Md5HashBuffer');
const teaEnc = Module.getGlobalExportByName( 'TeaEncryptECB');
const teaDec = Module.getGlobalExportByName( 'TeaDecryptECB');
const oiEnc = Module.getGlobalExportByName( 'oi_symmetry_encrypt');
const oiEnc2 = Module.getGlobalExportByName( 'oi_symmetry_encrypt2');

send({type: 'init', exports: {
    md5Update: md5Update ? md5Update.toString() : null,
    md5Final: md5Final ? md5Final.toString() : null,
    md5Init: md5Init ? md5Init.toString() : null,
    md5HashBuffer: md5HashBuffer ? md5HashBuffer.toString() : null,
    teaEnc: teaEnc ? teaEnc.toString() : null,
    teaDec: teaDec ? teaDec.toString() : null,
    oiEnc: oiEnc ? oiEnc.toString() : null,
    oiEnc2: oiEnc2 ? oiEnc2.toString() : null,
}});

Interceptor.attach(SIGN_FN, {
    onEnter: function() {
        inside = true;
        events.length = 0;
        for (const k in md5Updates) delete md5Updates[k];
    },
    onLeave: function() {
        inside = false;
        send({type: 'done', events: events.length, contexts: Object.keys(md5Updates).length});
        // Send each context's accumulated bytes
        for (const ctx in md5Updates) {
            const updates = md5Updates[ctx];
            send({type: 'md5_input', ctx: ctx, updates: updates});
        }
    }
});

if (md5Init) {
    Interceptor.attach(md5Init, {
        onEnter: function(args) {
            if (!inside) return;
            const ctx = args[0].toString();
            md5Updates[ctx] = [];
            events.push({fn: 'init', ctx: ctx});
        }
    });
}

if (md5Update) {
    Interceptor.attach(md5Update, {
        onEnter: function(args) {
            if (!inside) return;
            const ctx = args[0].toString();
            const data = args[1];
            const len = args[2].toInt32();
            try {
                const bytes = data.readByteArray(Math.min(len, 256));
                if (!md5Updates[ctx]) md5Updates[ctx] = [];
                md5Updates[ctx].push({len: len, bytes: Array.from(new Uint8Array(bytes))});
                events.push({fn: 'update', ctx: ctx, len: len});
            } catch(e) {}
        }
    });
}

if (md5Final) {
    Interceptor.attach(md5Final, {
        onEnter: function(args) {
            if (!inside) return;
            const ctx = args[0].toString();
            this.outPtr = args[1];
            this.ctx = ctx;
        },
        onLeave: function(retval) {
            if (!inside) return;
            try {
                const digest = Array.from(new Uint8Array(this.outPtr.readByteArray(16)));
                events.push({fn: 'final', ctx: this.ctx, digest: digest});
                send({type: 'md5_final', ctx: this.ctx, digest: digest, updates: md5Updates[this.ctx] || []});
            } catch(e) {}
        }
    });
}

if (md5HashBuffer) {
    Interceptor.attach(md5HashBuffer, {
        onEnter: function(args) {
            if (!inside) return;
            const data = args[0];
            const len = args[1].toInt32();
            this.outPtr = args[2];
            try {
                const bytes = data.readByteArray(Math.min(len, 256));
                this.input = Array.from(new Uint8Array(bytes));
                this.len = len;
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (!inside) return;
            try {
                const digest = Array.from(new Uint8Array(this.outPtr.readByteArray(16)));
                send({type: 'md5_buffer', input: this.input, len: this.len, digest: digest});
            } catch(e) {}
        }
    });
}

if (teaEnc) {
    Interceptor.attach(teaEnc, {
        onEnter: function(args) {
            if (!inside) return;
            // TeaEncryptECB(const void* input, void* output, const void* key)
            try {
                const input = Array.from(new Uint8Array(args[0].readByteArray(8)));
                const key = Array.from(new Uint8Array(args[2].readByteArray(16)));
                this.input = input;
                this.key = key;
                this.outPtr = args[1];
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (!inside) return;
            try {
                const out = Array.from(new Uint8Array(this.outPtr.readByteArray(8)));
                send({type: 'tea_enc', input: this.input, key: this.key, output: out});
            } catch(e) {}
        }
    });
}

if (oiEnc) {
    Interceptor.attach(oiEnc, {
        onEnter: function(args) {
            if (!inside) return;
            try {
                const inputLen = args[1].toInt32();
                const input = Array.from(new Uint8Array(args[0].readByteArray(Math.min(inputLen, 256))));
                const key = Array.from(new Uint8Array(args[2].readByteArray(16)));
                this.input = input; this.key = key; this.inputLen = inputLen;
                this.outPtr = args[3]; this.outLenPtr = args[4];
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (!inside) return;
            try {
                const outLen = this.outLenPtr.readU32();
                const out = Array.from(new Uint8Array(this.outPtr.readByteArray(Math.min(outLen, 256))));
                send({type: 'oi_enc', input: this.input, key: this.key, output: out});
            } catch(e) {}
        }
    });
}

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
    md5_finals = []
    md5_buffers = []
    tea_events = []
    oi_events = []
    done = [False]
    def on_msg(msg, data):
        if msg['type'] == 'send':
            pl = msg['payload']
            if pl.get('type') == 'init':
                print(f"[exports] {pl['exports']}")
            elif pl.get('type') == 'md5_final':
                md5_finals.append(pl)
            elif pl.get('type') == 'md5_buffer':
                md5_buffers.append(pl)
            elif pl.get('type') == 'tea_enc':
                tea_events.append(pl)
            elif pl.get('type') == 'oi_enc':
                oi_events.append(pl)
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
    deadline = time.time() + 10
    while not done[0] and time.time() < deadline:
        time.sleep(0.2)

    print(f"\n=== {len(md5_finals)} XP_MD5_Final calls ===")
    for i, m in enumerate(md5_finals):
        digest_hex = bytes(m['digest']).hex()
        # Reconstruct full input by concatenating updates
        full_input = b''
        for u in m['updates']:
            full_input += bytes(u['bytes'][:u['len']])
        print(f"  [{i}] ctx={m['ctx']} digest={digest_hex}")
        print(f"      input ({len(full_input)} bytes): {full_input.hex()[:128]}{'...' if len(full_input) > 64 else ''}")

    print(f"\n=== {len(md5_buffers)} XP_Md5HashBuffer calls ===")
    for i, m in enumerate(md5_buffers):
        digest_hex = bytes(m['digest']).hex()
        input_hex = bytes(m['input']).hex()[:128]
        print(f"  [{i}] len={m['len']} input={input_hex}{'...' if m['len'] > 64 else ''}")
        print(f"      digest={digest_hex}")

    print(f"\n=== {len(tea_events)} TeaEncryptECB calls ===")
    for i, t in enumerate(tea_events[:10]):
        print(f"  [{i}] in={bytes(t['input']).hex()} key={bytes(t['key']).hex()} out={bytes(t['output']).hex()}")

    print(f"\n=== {len(oi_events)} oi_symmetry_encrypt calls ===")
    for i, o in enumerate(oi_events[:10]):
        print(f"  [{i}] in={bytes(o['input']).hex()[:64]} key={bytes(o['key']).hex()} out={bytes(o['output']).hex()[:64]}")

    # Save all
    with open('/tmp/sign_crypto_events.json', 'w') as f:
        json.dump({'md5_finals': md5_finals, 'md5_buffers': md5_buffers, 'tea': tea_events, 'oi': oi_events}, f)

    p.stdin.write('EXIT\n'); p.stdin.flush()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()


if __name__ == '__main__':
    main()
