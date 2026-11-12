import struct, sys
META = sys.argv[1]
m = open(META, 'rb').read()
TD_O, TD_N, tcnt = 0x838CFC, 104, 9329
MD_O, MD_N, mcnt = 0x1FA350, 56, 70537
S = 0x74C44; SC = 0x13F1F8
def i32m(o): return struct.unpack_from('<i', m, o)[0]
def u32m(o): return struct.unpack_from('<I', m, o)[0]
def u16m(o): return struct.unpack_from('<H', m, o)[0]
def cstr(i):
    if not (0 <= i < SC): return None
    e = m.index(b'\0', S+i); return m[S+i:e].decode('utf8','replace')
def md(i,o): return MD_O + i*MD_N + o
def td(i,o): return TD_O + i*TD_N + o

def tname(t):
    ns = cstr(i32m(td(t,4))) or ''
    nm = cstr(i32m(td(t,0))) or ''
    return f'{ns}.{nm}' if ns else nm

print('records 67505..67522:')
for i in range(67505, 67523):
    print(f'  {i}: {tname(i32m(md(i,4))):40s} {cstr(i32m(md(i,0))):32s} token=0x{u32m(md(i,0x2C)):X}')

# which type has methodStart <= 67511 < methodStart+count
for i in range(tcnt):
    s = i32m(td(i,0x34)); c = u16m(td(i,0x50))
    if s >= 0 and s <= 67511 < s + c:
        print(f'\nboundary falls inside type {i} {tname(i)} methodStart={s} count={c}')

# global method ranges: max methodStart
mx = max((i32m(td(i,0x34)), i) for i in range(tcnt) if i32m(td(i,0x34)) >= 0)
print('max methodStart', mx, tname(mx[1]))
mx2 = max((i32m(td(i,0x30)), i) for i in range(tcnt) if i32m(td(i,0x30)) >= 0)
print('max fieldStart', mx2, tname(mx2[1]))

# image list attempt: find strings ending .dll in string table and their indices
names = {}
for i in range(SC):
    pass
import re
blob = m[S:S+SC]
for mo in re.finditer(rb'[A-Za-z0-9_.\-]{3,40}\.dll', blob):
    names[mo.start()] = mo.group().decode()
print('\ndll strings at string offsets:', {k: v for k, v in list(names.items())[:25]})
