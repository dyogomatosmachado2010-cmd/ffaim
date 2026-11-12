import struct, sys
d = open(sys.argv[1], 'rb').read()
TD_O, TD_SZ, TD_N = 0x838CFC, 0xECDE8, 104
n = TD_SZ // TD_N

print('total bytes methods=3950072 fields=823680 params=929568')
print('candidate method counts:', [3950072//s for s in range(8,60,4) if 3950072 % s == 0], [s for s in range(8,60,4) if 3950072 % s == 0])
print('candidate field counts:', [(s, 823680//s) for s in range(8,40,4) if 823680 % s == 0])

# sum of each u16 slot at each byte offset
hits = {}
for p in range(0, TD_N - 1, 2):
    sums = [0]*1
    total = 0
    for i in range(n):
        v = struct.unpack_from('<H', d, TD_O + i*TD_N + p)[0]
        total += v
    if total in (141074, 70537, 51480, 68640, 58098, 16464//2):
        print(f'  u16 @+{p:02X} sum={total}')
    hits[p] = total

print('\nall u16 sums:')
for p in range(0, TD_N-1, 2):
    print(f'  +{p:02X} sum={hits[p]}')
