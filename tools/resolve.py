import struct, sys

META, BIN = sys.argv[1], sys.argv[2]
m = open(META, 'rb').read()
d = open(BIN, 'rb').read()
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
    e = m.index(b'\0', S + i)
    return m[S+i:e].decode('utf8', 'replace')
def tname(t):
    ns = cstr(i32m(TD_O + t*TD_N + 4)); nm = cstr(i32m(TD_O + t*TD_N))
    return (ns + '.' if ns else '') + nm
def tflags(t): return u32m(TD_O + t*TD_N + 0x2C)
def mname(i): return cstr(i32m(MD_O + i*MD_N))
def mdecl(i): return i32m(MD_O + i*MD_N + 4)
def mflags(i): return u16m(MD_O + i*MD_N + 0x30)
def u64d(a): return struct.unpack_from('<Q', d, a - BASE)[0]
def code(a, n=12): return d[a-BASE:a-BASE+n].hex() if a else ''

abs_pre = [0]*(MC+1)
uni_pre = [0]*(MC+1)
for i in range(MC):
    f = mflags(i); t = mdecl(i)
    a = 1 if (f & 0x400) else 0
    b = 1 if (0 <= t < TCNT and (tflags(t) & 0x20)) else 0
    abs_pre[i+1] = abs_pre[i] + a
    uni_pre[i+1] = uni_pre[i] + (a | b)

print('abstract methods      :', abs_pre[MC])
print('interface-declared    :', uni_pre[MC])
print('gap MC-N              :', MC - N)

# ---- global within-type ordering score for each hypothesis ----
def score(fn):
    ok = tot = 0
    prev = None
    for i in range(MC):
        j = fn(i)
        if j is None or j < 0 or j >= N:
            prev = None; continue
        p = u64d(A + j*8)
        if prev is not None and mdecl(i) == mdecl(i-1):
            tot += 1
            if p > prev[0]: ok += 1
        prev = (p,)
    return ok, tot, ok/tot if tot else 0

for label, fn in (
    ('H0 idx=i', lambda i: i if i < N else None),
    ('H1 i-abstract', lambda i: i - abs_pre[i] if 0 <= i - abs_pre[i] < N else None),
    ('H2 i-abstract|iface', lambda i: i - uni_pre[i] if 0 <= i - uni_pre[i] < N else None),
):
    ok, tot, r = score(fn)
    print(f'{label:24s} within-type increasing {ok}/{tot} = {r:.4f}')

# ---- target methods ----
targets = {
    ('UnityEngine.Vector3', 'get_x'), ('UnityEngine.Vector3', 'get_y'), ('UnityEngine.Vector3', 'get_z'),
    ('UnityEngine.Vector2', 'get_x'), ('UnityEngine.Vector2', 'get_y'),
    ('UnityEngine.Quaternion', 'get_x'), ('UnityEngine.Color', 'get_r'),
    ('UnityEngine.Rect', 'get_x'), ('UnityEngine.Vector4', 'get_x'),
    ('System.String', 'get_Length'), ('System.Int32', 'GetHashCode'), ('System.Boolean', 'GetHashCode'),
    ('System.Object', 'GetType'), ('System.Object', 'GetHashCode'),
}
hits = {}
for i in range(MC):
    k = (tname(mdecl(i)), mname(i))
    if k in targets:
        hits.setdefault(k, []).append(i)

print('\n%-38s %6s %6s %-18s %-18s %-18s' % ('method', 'idx', 'pred1', 'H0 code', 'H1 code', 'H2 code'))
for k in sorted(hits):
    for i in hits[k]:
        p0 = u64d(A + i*8) if i < N else 0
        j1 = i - abs_pre[i]; j2 = i - uni_pre[i]
        p1 = u64d(A + j1*8) if 0 <= j1 < N else 0
        p2 = u64d(A + j2*8) if 0 <= j2 < N else 0
        print('%-38s %6d %6d %-18s %-18s %-18s' % (
            k[0] + '.' + k[1], i, j1, code(p0, 8), code(p1, 8), code(p2, 8)))
