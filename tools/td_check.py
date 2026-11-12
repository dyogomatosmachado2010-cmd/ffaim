import struct, sys
META = sys.argv[1]
m = open(META, 'rb').read()
TD_O, TD_SZ, TD_N = 0x838CFC, 0xECDE8, 104
cnt = TD_SZ // TD_N
def u32(i,o): return struct.unpack_from('<I', m, TD_O+i*TD_N+o)[0]
def i32(i,o): return struct.unpack_from('<i', m, TD_O+i*TD_N+o)[0]
def u16(i,o): return struct.unpack_from('<H', m, TD_O+i*TD_N+o)[0]

tok_ok = sum(1 for i in range(cnt) if u32(i,0x64) == 0x02000000 + i + 1)
print(f'token == 0x02000000|(i+1): {tok_ok}/{cnt}')

SC = 0x13F1F8
name_ok = sum(1 for i in range(cnt) if 0 <= i32(i,0) < SC and 0 <= i32(i,4) < SC)
print(f'valid name/ns: {name_ok}/{cnt}')

# monotonicity of each int32 field
print('\nmonotonic int32 offsets (>=99% non-decreasing):')
for o in range(0x08, 0x60, 4):
    nondec = sum(1 for i in range(cnt-1) if i32(i,o) <= i32(i+1,o))
    vals = [i32(i,o) for i in range(6)]
    rng = (min(i32(i,o) for i in range(cnt)), max(i32(i,o) for i in range(cnt)))
    print(f'  +0x{o:02X} nondec={nondec/(cnt-1):.3f} range={rng} first6={vals}')

# check u16 counts per record plausibility vs offsets
print('\nfirst 12 typeDefs: name, +0x24..0x2C, counts block')
for i in range(12):
    nm = m[0x74C44+i32(i,0):].split(b'\0')[0].decode('utf8','replace')
    print(f'  {i:4d} {nm:32s} +24={i32(i,0x24):8d} +28={i32(i,0x28):8d} +2C=0x{u32(i,0x2C):08X} '
          f'+30={i32(i,0x30):7d} +34={i32(i,0x34):7d} +38={i32(i,0x38):7d} +3C={i32(i,0x3C):7d} '
          f'+40={i32(i,0x40):7d} +44={i32(i,0x44):7d} +48={i32(i,0x48):7d} +4C={i32(i,0x4C):7d} '
          f'+60=0x{u32(i,0x60):08X} counts={[u16(i,0x50+2*k) for k in range(8)]}')
