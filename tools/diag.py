import struct, sys

META, BIN = sys.argv[1], sys.argv[2]
m = open(META, 'rb').read(); d = open(BIN, 'rb').read()
BASE = 0x100000000
S, SC = 0x74C44, 0x13F1F8
TD_O, TD_N, TCNT = 0x838CFC, 104, 9329
MD_O, MD_N, MC = 0x1FA350, 56, 70537
A, N = 0x10326CD48, 67511

def i32m(o): return struct.unpack_from('<i', m, o)[0]
def u32m(o): return struct.unpack_from('<I', m, o)[0]
def u16m(o): return struct.unpack_from('<H', m, o)[0]
def cstr(i):
    if not (0 <= i < SC): return ''
    e = m.index(b'\0', S + i); return m[S+i:e].decode('utf8', 'replace')
def tname(t):
    ns = cstr(i32m(TD_O + t*TD_N + 4)); nm = cstr(i32m(TD_O + t*TD_N))
    return (ns + '.' if ns else '') + nm
def tflags(t): return u32m(TD_O + t*TD_N + 0x2C)
def mname(i): return cstr(i32m(MD_O + i*MD_N))
def mdecl(i): return i32m(MD_O + i*MD_N + 4)
def mflags(i): return u16m(MD_O + i*MD_N + 0x30)
def miflags(i): return u16m(MD_O + i*MD_N + 0x32)
def mslot(i): return u16m(MD_O + i*MD_N + 0x34)
def mpc(i): return u16m(MD_O + i*MD_N + 0x36)
def u64d(a): return struct.unpack_from('<Q', d, a - BASE)[0]
def code(j, n=16):
    if not (0 <= j < N): return ''
    p = u64d(A + j*8)
    return d[p-BASE:p-BASE+n].hex()

print('=== methods 460..500 ===')
for i in range(460, 501):
    print(f'{i:5d} {tname(mdecl(i))[:34]:34s} {mname(i)[:26]:26s} fl=0x{mflags(i):04X} if=0x{miflags(i):04X} slot={mslot(i)} pc={mpc(i)}')
    print(f'      ptr=0x{u64d(A+i*8) if i<N else 0:X} code={code(i)}')

print('\n=== String block: type 27 methods ===')
s0 = i32m(TD_O + 27*TD_N + 0x34); sc = u16m(TD_O + 27*TD_N + 0x50)
print('methodStart', s0, 'count', sc)
for i in range(s0+125, s0+140):
    print(f'{i:5d} {mname(i)[:30]:30s} ptr=0x{u64d(A+i*8) if i<N else 0:X} code={code(i,8)}')

print('\n=== predicate counts (target gap 3026) ===')
def cnt(f):
    return sum(1 for i in range(MC) if f(i))
preds = {
 'abstract': lambda i: mflags(i) & 0x400,
 'pinvoke': lambda i: mflags(i) & 0x2000,
 'iflags_internal': lambda i: miflags(i) & 0x1000,
 'iflags_native': lambda i: miflags(i) & 0x0001,
 'iflags_none': lambda i: miflags(i) == 0,
 'specialname': lambda i: mflags(i) & 0x800,
 'pc0': lambda i: mpc(i) == 0,
 'slot_ffff': lambda i: mslot(i) == 0xFFFF,
 'decl_iface': lambda i: tflags(mdecl(i)) & 0x20,
 'decl_abstract': lambda i: tflags(mdecl(i)) & 0x80,
 'generic': lambda i: i32m(MD_O + i*MD_N + 0x14) != -1,
 'name_getset': lambda i: mname(i).startswith(('get_', 'set_')),
 'ret_void': lambda i: i32m(MD_O + i*MD_N + 8) == 0,
}
for k, f in preds.items():
    print(f'  {k:16s} {cnt(f):6d}')
print('  abstract|pinvoke', cnt(lambda i: (mflags(i) & 0x400) or (mflags(i) & 0x2000)))
print('  abstract|generic', cnt(lambda i: (mflags(i) & 0x400) or i32m(MD_O + i*MD_N + 0x14) != -1))
print('  abstract|iflags_internal', cnt(lambda i: (mflags(i) & 0x400) or (miflags(i) & 0x1000)))
print('  abstract|pinvoke|generic', cnt(lambda i: (mflags(i) & 0x400) or (mflags(i) & 0x2000) or i32m(MD_O + i*MD_N + 0x14) != -1))

print('\n=== per-image method counts ===')
IMG_O, IMG_N, icnt = 0x928C7C, 24, 18
tot = 0
for i in range(icnt):
    o = IMG_O + i*IMG_N
    name, ts, tc = i32m(o), i32m(o+8), i32m(o+12)
    mc = sum(u16m(TD_O + t*TD_N + 0x50) for t in range(ts, ts+tc))
    ab = sum(1 for t in range(ts, ts+tc) for k in range(i32m(TD_O+t*TD_N+0x34), i32m(TD_O+t*TD_N+0x34)+u16m(TD_O+t*TD_N+0x50)) if mflags(k) & 0x400) if mc else 0
    print(f'  {cstr(name):30s} methods {mc:6d} abstract {ab:5d} cum {tot}..{tot+mc}')
    tot += mc
