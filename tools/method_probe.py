import struct, sys
META = sys.argv[1]; BIN = sys.argv[2]
m = open(META, 'rb').read()
d = open(BIN, 'rb').read()
BASE = 0x100000000
TD_O, TD_N, cnt = 0x838CFC, 104, 9329
MD_O, MD_N, mcnt = 0x1FA350, 56, 70537
FD_O, FD_N, fcnt = 0x6F283C, 16, 51480
PA_O, PA_N, pcnt = 0x60F91C, 16, 58098
def u32m(o): return struct.unpack_from('<I', m, o)[0]
def i32m(o): return struct.unpack_from('<i', m, o)[0]
def u16m(o): return struct.unpack_from('<H', m, o)[0]
def td(i, off): return TD_O + i*TD_N + off
def md(i, off): return MD_O + i*MD_N + off
def u64d(a): return struct.unpack_from('<Q', d, a - BASE)[0]

# methodStart / counts per type
def mstart(i): return i32m(td(i, 0x34))
def mcount(i): return u16m(td(i, 0x50))
def fstart(i): return i32m(td(i, 0x30))
def fcount(i): return u16m(td(i, 0x54))

print('--- validating fieldStart/methodStart bounds ---')
bad_f = sum(1 for i in range(cnt) if not (fstart(i) == -1 and fcount(i) == 0 or 0 <= fstart(i) < fcnt))
bad_m = sum(1 for i in range(cnt) if not (mstart(i) == -1 and mcount(i) == 0 or 0 <= mstart(i) < mcnt))
print('bad fieldStart', bad_f, 'bad methodStart', bad_m)

# declaringType test: for each candidate int32 offset, method's index must fall in declaring type range
print('\n--- declaringType offset candidates ---')
for o in range(0x00, 0x34, 4):
    ok = 0
    for i in range(0, mcnt, 7):
        dt = i32m(md(i, o))
        if 0 <= dt < cnt:
            s, c = mstart(dt), mcount(dt)
            if s >= 0 and s <= i < s + c:
                ok += 1
    print(f'  +0x{o:02X}: match={ok/ (mcnt//7):.3f}')

print('\n--- sample method records ---')
S = 0x74C44
def cstr(i):
    if not (0 <= i < 0x13F1F8): return ''
    e = m.index(b'\0', S+i); return m[S+i:e].decode('utf8','replace')
for i in range(0, 3):
    print(f'  m[{i}]', [(hex(o), i32m(md(i,o)), cstr(i32m(md(i,o))) if o == 0 else '') for o in range(0, 56, 4)])

# find code registration: search for pointer to known method-pointer array
print('\n--- refs to 0x10326CD48 / 0x1031B6998 / 0x103131020 ---')
for tgt in (0x10326CD48, 0x1031B6998, 0x103131020):
    pat = struct.pack('<Q', tgt)
    idx = d.find(pat)
    found = []
    while idx != -1 and len(found) < 8:
        found.append(idx + BASE)
        idx = d.find(pat, idx+1)
    print(f'  0x{tgt:X}: refs {[hex(x) for x in found]}')
    for a in found[:2]:
        print(f'     around: prev u32s {[struct.unpack_from("<i", d, a-BASE-k)[0] for k in (16,12,8,4)]}')
