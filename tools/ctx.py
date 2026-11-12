import struct, sys
BIN = sys.argv[1]
d = open(BIN, 'rb').read()
BASE = 0x100000000
def off(a): return a - BASE
def u32(a): return struct.unpack_from('<I', d, off(a))[0]
def i32(a): return struct.unpack_from('<i', d, off(a))[0]
def u64(a): return struct.unpack_from('<Q', d, off(a))[0]
def cstr(a, lim=120):
    o = off(a)
    if not (0 <= o < len(d)): return ''
    try:
        e = d.index(b'\0', o, o+lim)
    except ValueError:
        return ''
    return d[o:e].decode('utf8','replace')

for target in [0x10326CD48, 0x1031B6998, 0x103131020]:
    print(f'=== around 0x{target:X} ===')
    for delta in range(-0x60, 0x40, 4):
        a = target + delta
        v = u32(a)
        v8 = u64(a)
        print(f'  {delta:+04X}: u32={v:12d} 0x{v:08X}  u64=0x{v8:012X}  {cstr(v8)!r}')
    print()
