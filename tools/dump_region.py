import struct, sys
BIN = sys.argv[1]
d = open(BIN, 'rb').read()
BASE = 0x100000000
def off(a): return a - BASE
def u32(a): return struct.unpack_from('<I', d, off(a))[0]
def i32(a): return struct.unpack_from('<i', d, off(a))[0]
def u64(a): return struct.unpack_from('<Q', d, off(a))[0]
def cstr(a, lim=100):
    o = off(a)
    if not (0 <= o < len(d)): return ''
    try: e = d.index(b'\0', o, o+lim)
    except ValueError: return ''
    return d[o:e].decode('utf8', 'replace')

print('--- around 0x10315EB40 ---')
for a in range(0x10315EB00, 0x10315EC00, 8):
    print(f'  0x{a:X}: u64=0x{u64(a):012X} u32lo={u32(a):10d} u32hi={u32(a+4):10d} str={cstr(u64(a))!r}')

print('\n--- array at 0x10326CD48: entries and end ---')
A = 0x10326CD48
for i in (0, 1, 2, 67508, 67509, 67510, 67511, 67512, 67513, 67584, 67585, 67586):
    a = A + i*8
    print(f'  [{i}] 0x{a:X} = 0x{u64(a):X}')

print('\n--- what is at 0x1032F0C00 (A+67511*8) ---')
for a in range(0x1032F0BE0, 0x1032F0C60, 8):
    print(f'  0x{a:X}: 0x{u64(a):012X} {cstr(u64(a))!r}')
