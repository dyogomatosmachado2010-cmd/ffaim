import struct, sys
d = open(sys.argv[1], 'rb').read()
S = 0x74C44
SC = 0x13F1F8
def c(i):
    if not (0 <= i < SC): return ''
    e = d.index(b'\0', S+i)
    return d[S+i:e].decode('utf8','replace')

for name, o, sz in [('images',0x925AE4,0x3198), ('assemblies',0x928C7C,0x1B0),
                    ('typeDefs',0x838CFC,0xECDE8), ('methods',0x1FA350,0x3C45F8),
                    ('fields',0x6F283C,0xC9180), ('parameters',0x60F91C,0xE2F20)]:
    print('===', name, 'offset=0x%X size=%d' % (o, sz))
    for i in range(0, 96, 4):
        v = struct.unpack_from('<i', d, o+i)[0]
        s = c(v) if 0 <= v < SC else ''
        print('  +%02X %12d 0x%08X  %r' % (i, v, v & 0xFFFFFFFF, s))
