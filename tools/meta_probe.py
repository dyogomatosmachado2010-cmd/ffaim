import struct, sys

path = sys.argv[1]
d = open(path, 'rb').read()

# header: (offset, size) pairs, validated by contiguous chaining
names = ["stringLiteral","stringLiteralData","string","events","properties","methods",
         "parameterDefaultValues","fieldDefaultValues","fieldAndParameterDefaultValueData",
         "fieldMarshaledSizes","parameters","fields","genericParameters","genericParameterConstraints",
         "genericContainers","nestedTypes","interfaces","vtableMethods","interfaceOffsets",
         "typeDefinitions","images","assemblies","fieldRefs","referencedAssemblies",
         "attributeData","attributeDataRange","unresolvedVirtualCallParameterTypes",
         "unresolvedVirtualCallParameterRanges","windowsRuntimeTypeNames","windowsRuntimeStrings",
         "exportedTypeDefinitions"]

hdr = {}
off = 8
for n in names:
    o, s = struct.unpack_from('<Ii', d, off)
    hdr[n] = (o, s)
    off += 8

STR_OFF, STR_SIZE = hdr['string']
print(f"file={len(d)} version={struct.unpack_from('<i',d,4)[0]}")

def cstr(base, i):
    e = d.index(b'\0', base+i)
    return d[base+i:e]

def check_type_defs(size):
    o, sz = hdr['typeDefinitions']
    if sz % size: return None, "not divisible"
    n = sz // size
    bad = 0
    for i in range(0, n, max(1, n//2000)):
        e = o + i*size
        ni, nsi = struct.unpack_from('<ii', d, e)
        if not (0 <= ni < STR_SIZE and 0 <= nsi < STR_SIZE):
            bad += 1
    return n, bad

print("\n--- typeDefinitions element size candidates ---")
for s in range(48, 200, 4):
    n, bad = check_type_defs(s)
    if n and bad == 0:
        o, sz = hdr['typeDefinitions']
        samples = []
        for i in range(min(6, n)):
            e = o + i*s
            ni, nsi = struct.unpack_from('<ii', d, e)
            samples.append((cstr(STR_OFF, ni).decode('utf8','replace'), cstr(STR_OFF, nsi).decode('utf8','replace')))
        print(f"  size={s} count={n} samples={samples}")

print("\n--- methods element size candidates ---")
mo, ms = hdr['methods']
def check_methods(size):
    if ms % size: return None, None
    n = ms // size
    bad = 0
    for i in range(0, n, max(1, n//2000)):
        e = mo + i*size
        ni = struct.unpack_from('<i', d, e)[0]
        if not (0 <= ni < STR_SIZE): bad += 1
    return n, bad
for s in range(20, 80, 4):
    n, bad = check_methods(s)
    if n and bad == 0:
        samples = []
        for i in range(min(6, n)):
            ni = struct.unpack_from('<i', d, mo+i*s)[0]
            samples.append(cstr(STR_OFF, ni).decode('utf8','replace'))
        print(f"  size={s} count={n} samples={samples}")

print("\n--- images element size candidates ---")
io_, isz = hdr['images']
for s in range(16, 64, 4):
    if isz % s: continue
    n = isz // s
    ok = True
    out = []
    for i in range(n):
        ni = struct.unpack_from('<i', d, io_+i*s)[0]
        if not (0 <= ni < STR_SIZE): ok = False; break
        out.append(cstr(STR_OFF, ni).decode('utf8','replace'))
    if ok:
        print(f"  size={s} count={n} names={out}")

print("\n--- assemblies element size candidates ---")
ao, asz = hdr['assemblies']
for s in range(40, 120, 4):
    if asz % s: continue
    n = asz // s
    ok = True
    out = []
    for i in range(n):
        ni = struct.unpack_from('<i', d, ao+i*s+4)[0]
        if not (0 <= ni < STR_SIZE): ok = False; break
        out.append(cstr(STR_OFF, ni).decode('utf8','replace'))
    if ok:
        print(f"  size={s} count={n} names={out}")
