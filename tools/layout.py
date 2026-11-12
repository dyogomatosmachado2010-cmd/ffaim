import struct, sys
BIN = sys.argv[1]; META = sys.argv[2]
d = open(BIN, 'rb').read()
m = open(META, 'rb').read()
BASE = 0x100000000
def off(a): return a - BASE
def u32(a): return struct.unpack_from('<I', d, off(a))[0]
def i32(a): return struct.unpack_from('<i', d, off(a))[0]
def u64(a): return struct.unpack_from('<Q', d, off(a))[0]

MR = 0x10321F110
print('--- metadata registration @0x%X ---' % MR)
names = ['genericClasses','genericInsts','genericMethodTable','types','methodSpecs','fieldOffsets','typeDefinitionsSizes','metadataUsages']
for i, n in enumerate(names):
    a = MR + i*16
    print(f'  {n:22s} count={u32(a):10d} ptr=0x{u64(a+8):X}')

# metadata: typeDefs
TD_O, TD_SZ, TD_N = 0x838CFC, 0xECDE8, 104
cnt = TD_SZ // TD_N
print(f'\ntypeDefs records={cnt} stride={TD_N}')

def u16(i, o): return struct.unpack_from('<H', m, TD_O + i*TD_N + o)[0]
def i32m(i, o): return struct.unpack_from('<i', m, TD_O + i*TD_N + o)[0]

# candidate fieldStart / methodStart by consistency with counts
for count_off, cname in ((0x50,'method'), (0x52,'property'), (0x54,'field'), (0x56,'event'),
                          (0x58,'nested'), (0x5A,'vtable'), (0x5C,'iface'), (0x5E,'ifaceOff')):
    print(f'\n[{cname}_count @+0x{count_off:X}] total={sum(u16(i,count_off) for i in range(cnt))}')
    best = []
    for j in range(0x24, 0x50, 4):
        ok = 0; tot = 0
        for i in range(cnt-1):
            if i32m(i,j) + u16(i,count_off) == i32m(i+1,j):
                ok += 1
            tot += 1
        if ok / tot > 0.9:
            best.append((j, ok/tot))
    for j, r in best:
        print(f'   int32 @+0x{j:02X} consistency={r:.3f} first5={[i32m(i,j) for i in range(5)]}')
