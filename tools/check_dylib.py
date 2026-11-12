#!/usr/bin/env python3
"""check_dylib.py - confere o ffaim.dylib antes de injetar.

o que importa nesta build:
  - Mach-O arm64 valido, __interpose com 2 entradas (access, usleep)
  - nenhum literal sensivel em texto claro (libac_sdk, identifierForVendor,
    ffpp-ac-v2, caminhos de jailbreak)
  - sem simbolos exportados alem do necessario (ff_* do core)

uso: python tools/check_dylib.py [cheat/ffaim.dylib]
"""
import re
import struct
import sys

# literais que o ffac.mm ofusca: se aparecerem em claro, o -O2 dobrou o XOR.
AC_LITERALS = [
    b'libac_sdk', b'identifierForVendor', b'ffpp-ac-v2',
    b'Cydia', b'Sileo', b'Zebra', b'MobileSubstrate',
    b'libsubstrate', b'libhooker', b'/bin/bash', b'sshd',
]
# caminhos que outros modulos carregam de proposito (ffaim.cfg, dlopen do
# substrate no ffhook). nao sao checados pelo libac_sdk; so' informativo.
JB_PATHS = [b'/var/jb', b'/var/mobile/ffaim.cfg']


def sections(d):
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from('<IiiIIIII', d, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit('nao e Mach-O 64: 0x%08X' % magic)
    off = 32
    out = {}
    segs = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', d, off)
        if cmd == 0x19:
            name = d[off + 8:off + 24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, off + 24)
            nsects = struct.unpack_from('<I', d, off + 64)[0]
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
            so = off + 72
            for _ in range(nsects):
                sect = d[so:so + 16].rstrip(b'\0').decode()
                sseg = d[so + 16:so + 32].rstrip(b'\0').decode()
                addr, sz, fo = struct.unpack_from('<QQI', d, so + 32)
                out[(sseg, sect)] = (addr, sz, fo)
                so += 80
        off += size
    return out, segs


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'cheat/ffaim.dylib'
    d = open(path, 'rb').read()
    print('arquivo   %s' % path)
    print('tamanho   %d bytes' % len(d))

    secs, segs = sections(d)
    print('segmentos %s' % ', '.join(s[0] for s in segs))

    inter = secs.get(('__DATA', '__interpose'))
    if not inter:
        print('FALHA     sem __DATA,__interpose')
        return 1
    addr, sz, fo = inter
    n = sz // 16
    print('interpose %d entradas' % n)
    if n != 2:
        print('FALHA     esperado 2 (access, usleep)')

    # varre o arquivo inteiro: literal sensivel nao pode aparecer em claro
    low = d.lower()
    bad = [p.decode() for p in AC_LITERALS if p.lower() in low]
    if bad:
        print('FALHA     literais do AC em claro: %s' % ', '.join(bad))
    else:
        print('strings   ok (nenhum literal do AC em claro)')
    jb = [p.decode() for p in JB_PATHS if p.lower() in low]
    if jb:
        print('aviso     caminhos de outros modulos: %s' % ', '.join(jb))

    # simbolos: o -x do linker deve ter deixado so o que o painel precisa
    off = 32
    ncmds = struct.unpack_from('<I', d, 16)[0]
    syms = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', d, off)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', d, off + 8)
            for i in range(nsyms):
                strx, ntype, _, ndesc, nval = struct.unpack_from(
                    '<IBBHQ', d, symoff + i * 16)
                if ntype & 0x01 and not ntype & 0x10:  # externo e nao-stab
                    e = d.index(b'\0', stroff + strx)
                    syms.append(d[stroff + strx:e].decode('latin-1'))
        off += size
    pub = sorted(s for s in syms if not s.startswith('_OBJC'))
    print('exportados %d' % len(pub))
    for s in pub[:20]:
        print('           %s' % s)
    if len(pub) > 20:
        print('           ... +%d' % (len(pub) - 20))

    ok = (not bad) and n == 2
    print('resultado %s' % ('OK' if ok else 'REVISAR'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
