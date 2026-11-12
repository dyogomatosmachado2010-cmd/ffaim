import struct, sys
BIN = sys.argv[1]
d = open(BIN, 'rb').read()
BASE = 0x100000000
DATA_LO, DATA_HI = 0x10312C000, 0x3710000 + BASE
def off(a): return a - BASE
def u32(a): return struct.unpack_from('<I', d, off(a))[0]
def i32(a): return struct.unpack_from('<i', d, off(a))[0]
def u64(a): return struct.unpack_from('<Q', d, off(a))[0]

def in_data(p): return DATA_LO <= p < 0x1039C8000
def in_text(p): return 0x100006FE0 <= p < 0x1029A78D4

# 1) method count 70537 -> code registration
target = 70537
print('--- searching u32 == 70537 in data ---')
start, end = off(DATA_LO), min(off(DATA_HI), 0x3710000-8)
i = start
hits = []
while i < end:
    if struct.unpack_from('<I', d, i)[0] == target:
        a = i + BASE
        p = struct.unpack_from('<Q', d, i+8)[0] if i+12 <= end else 0
        hits.append((a, p))
    i += 4
for a, p in hits[:40]:
    print(f'  count@0x{a:X} ptr=0x{p:X} in_data={in_data(p)} in_text={in_text(p)}')
print('total hits', len(hits))

# 2) metadata registration: fieldOffsetsCount == typeDefinitionsSizesCount == 9329
print('\n--- searching u32 == 9329 pairs ---')
i = start
while i < end:
    if struct.unpack_from('<I', d, i)[0] == 9329:
        a = i + BASE
        if i + 0x18 <= end:
            c2 = struct.unpack_from('<I', d, i+0x10)[0]
            p1 = struct.unpack_from('<Q', d, i+8)[0]
            p2 = struct.unpack_from('<Q', d, i+0x18)[0]
            if c2 == 9329 and in_data(p1) and in_data(p2):
                print(f'  MR candidate @0x{a:X} p1=0x{p1:X} p2=0x{p2:X}')
                for k in range(-0x50, 0x30, 8):
                    print(f'     {k:+03X}: u32={u32(a+k):12d} u64=0x{u64(a+k):X}')
    i += 4
