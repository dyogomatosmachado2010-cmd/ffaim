import struct, sys

BIN = sys.argv[1]
d = open(BIN, 'rb').read()
BASE = 0x100000000
TEXT_END = 0x10312C000
DATA_START, DATA_END = 0x10312C000, 0x1039C8000

def off(a): return a - BASE
def at(a): return d[off(a):off(a)+8]

def u32(a): return struct.unpack_from('<I', d, off(a))[0]
def i32(a): return struct.unpack_from('<i', d, off(a))[0]
def u64(a): return struct.unpack_from('<Q', d, off(a))[0]
def cstr(a, lim=200):
    o = off(a); e = d.index(b'\0', o, o+lim)
    return d[o:e].decode('utf8', 'replace')

def find_str(s, start=0):
    b = s.encode()
    res = []
    i = d.find(b)
    while i != -1:
        res.append(i + BASE)
        i = d.find(b, i+1)
    return res

# 1) find module name strings
names = ['Assembly-CSharp.dll', 'mscorlib.dll', 'UnityEngine.dll', 'Assembly-CSharp-firstpass.dll']
print('--- string locations ---')
for n in names:
    for a in find_str(n)[:4]:
        print(f'  {n} @ 0x{a:X}')

def scan_ptr_refs(target, seg_start=DATA_START, seg_end=DATA_END):
    """find 8-byte little-endian occurrences of target pointer in data segment"""
    res = []
    start = off(seg_start); end = off(seg_end)
    tgt = struct.pack('<Q', target)
    i = d.find(tgt, start, end)
    while i != -1:
        if (i - off(seg_start)) % 8 == 0:
            res.append(i + BASE)
        i = d.find(tgt, i+1, end)
    return res

print('\n--- pointer refs to Assembly-CSharp.dll ---')
acs = find_str('Assembly-CSharp.dll')
for s in acs:
    refs = scan_ptr_refs(s)
    print(f'  str@0x{s:X} refs={[hex(r) for r in refs[:6]]}')
    for r in refs[:3]:
        print(f'    module@0x{r:X}: name=0x{u64(r):X} count={u32(r+8)} ptrs=0x{u64(r+16):X}')
        p = u64(r+16)
        if TEXT_END > p > BASE:
            print(f'      first method ptrs: {[hex(u64(p+i*8)) for i in range(4)]}')
            print(f'      +0x18=0x{u64(r+24):X} +0x20=0x{u64(r+32):X} +0x28=0x{u64(r+40):X}')
