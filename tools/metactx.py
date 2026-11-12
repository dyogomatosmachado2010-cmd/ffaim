import sys, re

path = sys.argv[1]
needle = sys.argv[2].encode()
span = int(sys.argv[3]) if len(sys.argv) > 3 else 900

data = open(path, 'rb').read()
print('tamanho:', len(data))
for m in re.finditer(re.escape(needle), data):
    a = max(0, m.start() - span)
    b = min(len(data), m.end() + span)
    chunk = data[a:b]
    # strings ascii imprimiveis >= 3
    out = re.findall(rb'[\x20-\x7e]{3,}', chunk)
    print('=' * 70)
    print('offset 0x%X' % m.start())
    for s in out:
        t = s.decode('latin-1')
        print('   ', t[:160])
