import struct, sys
META = sys.argv[1]
m = open(META, 'rb').read()
S = 0x74C44; SC = 0x13F1F8
TD_O, TD_N, tcnt = 0x838CFC, 104, 9329
MD_O, MD_N, mcnt = 0x1FA350, 56, 70537
IMG_O, IMG_N, icnt = 0x928C7C, 24, 18
def i32m(o): return struct.unpack_from('<i', m, o)[0]
def u16m(o): return struct.unpack_from('<H', m, o)[0]
def cstr(i):
    if not (0 <= i < SC): return '?'
    e = m.index(b'\0', S+i); return m[S+i:e].decode('utf8','replace')
def td(i,o): return TD_O+i*TD_N+o

print(f'{"image":32s} {"typeStart":>10s} {"typeCount":>10s} {"methodStart":>12s} {"methodEnd":>10s}')
for i in range(icnt):
    o = IMG_O + i*IMG_N
    name, asm, ts, tc = i32m(o), i32m(o+4), i32m(o+8), i32m(o+12)
    # method range from first type
    ms = i32m(td(ts, 0x34)) if ts < tcnt else -1
    # method end: last type in range
    last = ts + tc - 1
    me = -1
    if last < tcnt:
        s = i32m(td(last, 0x34)); c = u16m(td(last, 0x50))
        me = (s + c) if s >= 0 else s
    print(f'{cstr(name):32s} {ts:10d} {tc:10d} {ms:12d} {me:10d}')
print('total methods', mcnt, ' methodPointers', 67511)
