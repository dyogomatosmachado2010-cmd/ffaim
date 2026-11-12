import struct, sys
META = sys.argv[1]; BIN = sys.argv[2]
m = open(META, 'rb').read(); d = open(BIN, 'rb').read()
BASE = 0x100000000
MD_O, MD_N, mcnt = 0x1FA350, 56, 70537
S = 0x74C44; SC = 0x13F1F8
def i32m(o): return struct.unpack_from('<i', m, o)[0]
def u32m(o): return struct.unpack_from('<I', m, o)[0]
def cstr(i):
    if not (0 <= i < SC): return None
    e = m.index(b'\0', S+i); return m[S+i:e].decode('utf8','replace')
def md(i,o): return MD_O + i*MD_N + o

seq = sum(1 for i in range(mcnt) if u32m(md(i,0x2C)) == 0x06000001 + i)
print(f'token sequential: {seq}/{mcnt}')
valid_names = sum(1 for i in range(mcnt) if cstr(i32m(md(i,0))) is not None)
print(f'valid names: {valid_names}/{mcnt}')
print('last 3 records:')
for i in range(mcnt-3, mcnt):
    print(f'  {i}: name={cstr(i32m(md(i,0)))!r} decl={i32m(md(i,4))} token=0x{u32m(md(i,0x2C)):X}')

# check code pointers array
A = 0x10326CD48
def u64d(a): return struct.unpack_from('<Q', d, a-BASE)[0]
print('\nfirst code pointers:', [hex(u64d(A+i*8)) for i in range(6)])
print('at A+67511*8:', hex(u64d(A+67511*8)))
# disasm-ish check for method 0 (Object..ctor)
t = u64d(A)
print(f'\nmethodPointers[0]=0x{t:X} bytes:', d[t-BASE:t-BASE+16].hex())
