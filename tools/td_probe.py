import struct, sys
d = open(sys.argv[1], 'rb').read()
S = 0x74C44; SC = 0x13F1F8
def c(i):
    if not (0 <= i < SC): return ''
    e = d.index(b'\0', S+i)
    return d[S+i:e].decode('utf8','replace')

TD_O, TD_SZ, TD_N = 0x838CFC, 0xECDE8, 104
n = TD_SZ // TD_N
print('typeDefs count', n)

def td(i):
    return d[TD_O + i*TD_N: TD_O + (i+1)*TD_N]

for i in (0,1,2,3):
    b = td(i)
    print(f'--- typeDef {i} ({c(struct.unpack_from("<i",b,0)[0])}) ---')
    for j in range(0, TD_N, 4):
        v32 = struct.unpack_from('<i', b, j)[0]
        u32 = v32 & 0xFFFFFFFF
        h1, h2 = struct.unpack_from('<HH', b, j)
        s = c(v32) if 0 <= v32 < SC else ''
        print(f'  +{j:02X} i32={v32:12d} u32=0x{u32:08X} u16=({h1},{h2}) {s!r}')
