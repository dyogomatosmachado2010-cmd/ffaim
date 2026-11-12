import zipfile, struct, sys, re, io

# 1) confere a cirurgia de header do inject.py: o binario nosso e o original so
#    podem diferir por um LC_LOAD_DYLIB a mais e pelo blob de assinatura zerado.
# 2) valida cada RVA de ff_offsets.h contra a linha de dump.cs que tem aquele RVA.

ORIG = r'FreeFire(IOS).ipa'
OURS = r'FreeFire_lunar.ipa'
EXE = 'Payload/freefireth.app/freefireth'


def lcs(data):
    magic, cpu, sub, ft, ncmds, sizeofcmds = struct.unpack_from('<IiiIII', data, 0)
    out = []
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        out.append((cmd, size, data[off:off + size]))
        off += size
    return ncmds, sizeofcmds, out


a = zipfile.ZipFile(ORIG).read(EXE)
b = zipfile.ZipFile(OURS).read(EXE)
na, sa, la = lcs(a)
nb, sb, lb = lcs(b)

print('original : ncmds=%d sizeofcmds=0x%X' % (na, sa))
print('nosso    : ncmds=%d sizeofcmds=0x%X' % (nb, sb))

ca = [(c, s) for c, s, _ in la]
cb = [(c, s) for c, s, _ in lb]
print('load commands iguais (tipo/tamanho):', ca == cb)

extra = [x for x in lb if x not in la]
falta = [x for x in la if x not in lb]
print('comandos a mais :', len(extra))
for c, s, raw in extra:
    print('   cmd=0x%X size=%d  %s' % (c, s, raw[8:8 + s - 8].split(b'\0')[0].decode('latin-1')))
print('comandos a menos:', len(falta))
for c, s, raw in falta:
    print('   cmd=0x%X size=%d' % (c, s))

# onde termina o header em cada um e onde comeca o primeiro conteudo real
def first_content(data):
    _, _, ls = lcs(data)
    end = 32 + sum(s for _, s, _ in ls)
    # menor fileoff de secao != 0
    mn = 1 << 62
    off = 32
    magic, cpu, sub, ft, ncmds, scmds = struct.unpack_from('<IiiIII', data, 0)
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            so = off + 72
            for _ in range(nsects):
                foff = struct.unpack_from('<I', data, so + 48)[0]
                sz = struct.unpack_from('<Q', data, so + 40)[0]
                if sz and foff:
                    mn = min(mn, foff)
                so += 80
        off += size
    return end, mn


ea, fa = first_content(a)
eb, fb = first_content(b)
print('header termina em  : orig 0x%X / nosso 0x%X' % (ea, eb))
print('1a secao com dados : orig 0x%X / nosso 0x%X' % (fa, fb))
print('espaco livre       : orig %d bytes / nosso %d bytes' % (fa - ea, fb - eb))
print('nao invadiu secao  :', eb <= fb)

# bytes diferentes fora do header e fora do blob de assinatura
sig = None
off = 32
for _ in range(nb):
    cmd, size = struct.unpack_from('<II', b, off)
    if cmd == 0x1D:
        sig = struct.unpack_from('<II', b, off + 8)
    off += size
print('LC_CODE_SIGNATURE  : dataoff=0x%X size=%d' % sig)

diff = 0
first = None
for i in range(min(len(a), len(b))):
    if a[i] != b[i]:
        diff += 1
        if first is None:
            first = i
print('bytes diferentes   :', diff, 'primeiro em 0x%X' % first if first is not None else '')

# 3) offsets vs dump.cs
print()
print('== RVA -> assinatura (dump.cs) ==')
src = io.open('dump.cs', encoding='utf-8', errors='replace').read().splitlines()
idx = {}
for ln in src:
    m = re.search(r'RVA: (0x[0-9A-Fa-f]+)', ln)
    if not m:
        continue
    rva = int(m.group(1), 16)
    body = ln.split('// VA:')[0].strip()
    body = body.lstrip('/').strip()
    idx.setdefault(rva, body)

hdr = io.open('cheat/ff_offsets.h', encoding='utf-8').read()
ok = bad = 0
for m in re.finditer(r'(RVA_\w+)\s*=\s*(0x[0-9A-Fa-f]+)', hdr):
    name, rva = m.group(1), int(m.group(2), 16)
    sig = idx.get(rva)
    if sig is None:
        print('  %-34s 0x%-8X  NAO ACHADO' % (name, rva)); bad += 1
    else:
        print('  %-34s 0x%-8X  %s' % (name, rva, sig[:90])); ok += 1
print('encontrados: %d  ausentes: %d' % (ok, bad))
