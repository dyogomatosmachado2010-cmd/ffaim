import sys, struct
sys.path.insert(0, 'tools')
from machosym import MachO

# le a metadata ObjC da dylib: classes, seletores, tipos e IMP de cada metodo.
# e o mapa que diz o que o ACAntiCheat expoe pra fora.

m = MachO(sys.argv[1])
d = m.data


def va2off(va):
    for name, (a, sz, foff, *_rest) in m.sections.items():
        if a <= va < a + sz:
            return foff + (va - a)
    return None


def cstr_at(va):
    o = va2off(va)
    if o is None:
        return None
    e = d.index(b'\0', o)
    return d[o:e].decode('latin-1')


def u64(va):
    o = va2off(va)
    if o is None:
        return None
    return struct.unpack_from('<Q', d, o)[0]


def u32(va):
    o = va2off(va)
    if o is None:
        return None
    return struct.unpack_from('<I', d, o)[0]


def methods(mlist_va, label):
    if not mlist_va:
        return
    flags = u32(mlist_va)
    count = u32(mlist_va + 4)
    if flags is None or count is None or count > 400:
        return
    rel = bool(flags & 0x80000000)
    print('  %s  flags=0x%08X count=%d rel=%s' % (label, flags, count, rel))
    ent = 12 if rel else 24
    base = mlist_va + 8
    for i in range(count):
        e = base + i * ent
        if rel:
            off = struct.unpack_from('<i', d, va2off(e))[0]
            name_va = e + off
            typ_off = struct.unpack_from('<i', d, va2off(e + 4))[0]
            types_va = e + 4 + typ_off
            imp_off = struct.unpack_from('<i', d, va2off(e + 8))[0]
            imp = e + 8 + imp_off
        else:
            name_va, types_va, imp = struct.unpack_from('<QQQ', d, va2off(e))
        nm = cstr_at(name_va)
        ty = cstr_at(types_va)
        print('     %-46s %-28s imp=0x%05X' % (nm, ty, imp))


cl = m.sections.get('__objc_classlist')
if not cl:
    print('sem __objc_classlist'); sys.exit(0)
a, sz, foff, *_r = cl
n = sz // 8
print('classes:', n)

for i in range(n):
    cls = struct.unpack_from('<Q', d, foff + i * 8)[0]
    data_bits = u64(cls + 32)
    ro = data_bits & ~0x7
    flags = u32(ro)
    name_va = u64(ro + 24)
    mlist = u64(ro + 32)
    nm = cstr_at(name_va)
    print('=' * 78)
    print('classe %-28s  ro=0x%X flags=0x%X' % (nm, ro, flags))
    if flags & 0x1:
        # meta class: pula
        pass
    methods(mlist, 'metodos de instancia')
    # metaclass -> metodos de classe
    isa = u64(cls)
    if isa:
        ro2 = u64(isa + 32) & ~0x7
        mlist2 = u64(ro2 + 32)
        methods(mlist2, 'metodos de classe')
