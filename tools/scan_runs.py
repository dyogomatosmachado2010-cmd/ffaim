import struct, sys
BIN = sys.argv[1]
d = open(BIN, 'rb').read()
BASE = 0x100000000
TEXT_LO, TEXT_HI = 0x100006FE0, 0x1029A78D4
DATA_LO, DATA_HI = 0x10312C000, 0x1039C8000
def off(a): return a - BASE
def u64(a): return struct.unpack_from('<Q', d, off(a))[0]

# find runs of pointers into __TEXT inside data segment
start = off(DATA_LO); end = min(off(DATA_HI), 0x3710000 - 8)
runs = []
cur_start = None
count = 0
i = start
while i < end - 8:
    v = struct.unpack_from('<Q', d, i)[0]
    if TEXT_LO <= v < TEXT_HI:
        if cur_start is None:
            cur_start = i
        count += 1
    else:
        if count >= 200:
            runs.append((cur_start + BASE, count))
        cur_start = None
        count = 0
    i += 8
if count >= 200:
    runs.append((cur_start + BASE, count))

print('pointer runs into __TEXT (len>=200):', len(runs))
for a, c in sorted(runs, key=lambda x: -x[1])[:15]:
    print(f'  0x{a:X} count={c}')

# check the biggest for uniqueness / method-like density
