import struct, sys

META, BIN = sys.argv[1], sys.argv[2]
m = open(META, 'rb').read(); d = open(BIN, 'rb').read()
BASE = 0x100000000
S, SC = 0x74C44, 0x13F1F8
TD_O, TD_N, TCNT = 0x838CFC, 104, 9329
MD_O, MD_N, MC = 0x1FA350, 56, 70537
A, N = 0x10326CD48, 67511
TEXT_LO, TEXT_HI = 0x100006FE0, 0x1029A78D4

def i32m(o): return struct.unpack_from('<i', m, o)[0]
def u32m(o): return struct.unpack_from('<I', m, o)[0]
def u16m(o): return struct.unpack_from('<H', m, o)[0]
def cstr(i):
    if not (0 <= i < SC): return ''
    e = m.index(b'\0', S + i); return m[S+i:e].decode('utf8', 'replace')
def tname(t):
    ns = cstr(i32m(TD_O + t*TD_N + 4)); nm = cstr(i32m(TD_O + t*TD_N))
    return (ns + '.' if ns else '') + nm
def mname(i): return cstr(i32m(MD_O + i*MD_N))
def mdecl(i): return i32m(MD_O + i*MD_N + 4)
def u64d(a): return struct.unpack_from('<Q', d, a - BASE)[0]

ptrs = [u64d(A + i*8) for i in range(N)]
index_of = {}
for i, p in enumerate(ptrs):
    index_of.setdefault(p, []).append(i)

def find_all(pat, lo=TEXT_LO, hi=TEXT_HI):
    out = []
    start, end = lo - BASE, hi - BASE
    i = d.find(pat, start, end)
    while i != -1:
        out.append(i + BASE)
        i = d.find(pat, i+1, end)
    return out

print('=== 8-byte int getter (ldr w0,[x0,#0x10];ret) occurrences in __text ===')
pat = bytes.fromhex('001040b9c0035fd6')
occ = find_all(pat)
print('count', len(occ))
for a in occ[:10]:
    print('  0x%X -> array idx %s' % (a, index_of.get(a)))

print('\n=== ldrh w0,[x8,w1,sxtw #1] (get_Chars tail) ===')
for a in find_all(bytes.fromhex('0069e179')):
    print('  0x%X ctx: %s' % (a, d[a-BASE-16:a-BASE+8].hex()))
    for back in range(0, 40, 4):
        cand = a - 8 - back
        if cand in index_of:
            print('     array idx %s for func 0x%X' % (index_of[cand], cand))

print('\n=== raw 4-byte ret-only functions in __text? (c0 03 5f d6 count) ===')
print(len(find_all(bytes.fromhex('c0035fd6'))))

print('\n=== metadata get_Chars ===')
for i in range(MC):
    if mname(i) == 'get_Chars' and mdecl(i) < 40:
        print('  idx', i, tname(mdecl(i)))
