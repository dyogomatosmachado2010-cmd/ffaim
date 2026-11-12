import struct, re, sys, bisect

META = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Data\Managed\Metadata\global-metadata.dat'
BIN  = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\freefireth'
BASE = 0x100000000

m = open(META, 'rb').read()
d = open(BIN, 'rb').read()

S = 0x74C44
MD_O, MD_N, MC = 0x1FA350, 56, 70537
TD_O, TD_N, TC = 0x838CFC, 104, 9329
A, N = 0x10326CD48, 67511

def i32(o):
    return struct.unpack_from('<i', m, o)[0]

def u16(o):
    return struct.unpack_from('<H', m, o)[0]

def u64(a):
    return struct.unpack_from('<Q', d, a - BASE)[0]

def cstr(i):
    e = m.index(b'\0', S + i)
    return m[S + i:e].decode('utf8', 'replace')

def tname(t):
    ns = cstr(i32(TD_O + t * TD_N + 4))
    nm = cstr(i32(TD_O + t * TD_N))
    return (ns + '.' if ns else '') + nm

meth = []
for i in range(MC):
    t = i32(MD_O + i * MD_N + 4)
    nm = cstr(i32(MD_O + i * MD_N))
    j = i32(MD_O + i * MD_N + 0x18)
    if not (0 <= j < N):
        continue
    p = u64(A + j * 8)
    if not p:
        continue
    rva = p - BASE
    if rva <= 0 or rva >= len(d):
        continue
    meth.append((rva, tname(t) + '::' + nm))
meth.sort()
starts = [x[0] for x in meth]

def owner(rva):
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return '?', rva
    return meth[i][1], rva - meth[i][0]

pat = re.compile(r'(AntiCheat|Anticheat|anticheat|Security|Tamper|Integrity|Jailbr|Cheat|Detect|Hack|Root|Emulator|Debugger|Verify|Guard|Protect)', re.I)
hits = []
for t in range(TC):
    n = tname(t)
    if pat.search(n.split('.')[-1]):
        hits.append((t, n))

print('== tipos suspeitos: %d ==' % len(hits))
for t, n in hits:
    print('  [%4d] %s' % (t, n))

print('')
print('== metodos ==')
for t, n in hits:
    ms = i32(TD_O + t * TD_N + 0x34)
    mc = u16(TD_O + t * TD_N + 0x50)
    if mc == 0:
        continue
    print('-- %s  (%d metodos)' % (n, mc))
    for k in range(mc):
        i = ms + k
        nm = cstr(i32(MD_O + i * MD_N))
        j = i32(MD_O + i * MD_N + 0x18)
        p = u64(A + j * 8) if 0 <= j < N else 0
        rva = p - BASE if p else 0
        print('     %-48s 0x%X' % (nm[:48], rva))
