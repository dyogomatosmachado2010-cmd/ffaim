#!/usr/bin/env python3
# verify_ipa.py - confere um .ipa antes de instalar
#
#   python tools/verify_ipa.py FreeFire_ffaim.ipa
#   python tools/verify_ipa.py FreeFire_ffaim.ipa --expect-appid 98573T3W6L.com.privateproject.ff2018.v128
#
# o que checa, por binario Mach-O do bundle:
#   - LC_CODE_SIGNATURE existe e aponta pra dentro do arquivo
#   - o superblob cabe dentro de __LINKEDIT (senao o kernel nao mapeia)
#   - o hash de cada pagina confere com o CodeDirectory
#   - o hash do blob de requirements confere
# tambem:
#   - Info.plist: CFBundleIdentifier, CFBundleExecutable, o executavel existe
#   - _CodeSignature presente? (opcional, o instalador recria)
#   - application-identifier dos entitlements x bundle id
#   - arquivos de lixo (*.orig/*.bak/*.tmp/*.rej/*.old) dentro do bundle
#
# sai com codigo 1 se qualquer binario falhar. falha fechado.
import hashlib, os, plistlib, struct, sys, zipfile

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_REQUIREMENTS = 0xFADE0C01
JUNK = ('.orig', '.bak', '.tmp', '.rej', '.old')


def is_macho(head):
    return head in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe')


def layout(b):
    magic, cpu, sub, ft, ncmds, sizeofcmds, flags, res = struct.unpack_from('<IiiIIIII', b, 0)
    out = {'sig': None, 'linkedit': None, 'fat': magic == 0xCAFEBABE, 'magic': magic}
    if magic != MH_MAGIC_64:
        return out
    off = 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from('<II', b, off)
        if cs < 8:
            raise ValueError('load command corrompido em 0x%X' % off)
        if cmd == LC_SEGMENT_64:
            seg = bytes(b[off + 8:off + 24]).split(b'\0')[0]
            if seg == b'__LINKEDIT':
                out['linkedit'] = struct.unpack_from('<QQQQ', b, off + 24)
        elif cmd == LC_CODE_SIGNATURE:
            out['sig'] = struct.unpack_from('<II', b, off + 8)
        off += cs
    return out


def check_macho(name, b):
    """devolve (ok, linhas de diagnostico)"""
    info = layout(b)
    lines = []
    if info['fat']:
        return False, ['fat binary - assinatura nao conferida']
    if info['magic'] != MH_MAGIC_64:
        return False, ['nao e Mach-O 64']
    sig = info['sig']
    if sig is None:
        return False, ['SEM LC_CODE_SIGNATURE']
    dataoff, datasize = sig
    if dataoff == 0 or datasize == 0:
        return False, ['LC_CODE_SIGNATURE vazio (dataoff 0x%X datasize %d)' % (dataoff, datasize)]
    if dataoff + datasize > len(b):
        return False, ['blob fora do arquivo (0x%X+%d > %d)' % (dataoff, datasize, len(b))]
    seg = info['linkedit']
    if seg is None:
        return False, ['sem __LINKEDIT']
    fileoff, filesize = seg[2], seg[3]
    if not (fileoff <= dataoff and dataoff + datasize <= fileoff + filesize):
        return False, ['blob fora do __LINKEDIT (0x%X..0x%X vs 0x%X..0x%X)'
                       % (dataoff, dataoff + datasize, fileoff, fileoff + filesize)]

    blob = b[dataoff:dataoff + datasize]
    magic, length, count = struct.unpack_from('>III', blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return False, ['superblob com magic errado 0x%08X' % magic]
    if length > datasize:
        return False, ['superblob declara %d bytes, LC diz %d' % (length, datasize)]

    cd = None
    blobs = {}
    for i in range(count):
        typ, off = struct.unpack_from('>II', blob, 12 + i * 8)
        if off + 8 > len(blob):
            return False, ['entrada %d do superblob fora do blob' % i]
        bmagic, blen = struct.unpack_from('>II', blob, off)
        if blen < 8 or off + blen > len(blob):
            return False, ['blob tipo %d com tamanho invalido (%d)' % (typ, blen)]
        blobs[typ] = blob[off:off + blen]
        if typ == 0:
            cd = blobs[typ]
    if cd is None:
        return False, ['sem CodeDirectory']

    (cmagic, clen, cver, cflags, hashoff, identoff,
     nspecial, ncode, codelimit) = struct.unpack_from('>IIIIIIIII', cd, 0)
    if cmagic != CSMAGIC_CODEDIRECTORY:
        return False, ['CodeDirectory com magic errado']
    if clen > len(cd):
        return False, ['CodeDirectory declara %d bytes, so tem %d' % (clen, len(cd))]
    if codelimit > len(b):
        return False, ['codeLimit 0x%X > tamanho do arquivo' % codelimit]

    hsize = cd[36]
    if hsize == 32:
        algo = hashlib.sha256
    elif hsize == 20:
        algo = hashlib.sha1
    else:
        return False, ['hash de %d bytes (esperado 20 ou 32)' % hsize]

    bad = 0
    for i in range(ncode):
        page = bytes(b[i * 4096:min((i + 1) * 4096, codelimit)])
        want = cd[hashoff + i * hsize:hashoff + (i + 1) * hsize]
        if algo(page).digest() != want:
            bad += 1
    if bad:
        return False, ['%d de %d paginas com hash diferente' % (bad, ncode)]

    for slot in range(1, nspecial + 1):
        pos = hashoff - slot * hsize
        digest = cd[pos:pos + hsize]
        if digest == b'\0' * hsize:
            continue
        if slot in (2, 5):
            part = blobs.get(slot)
            if part is None or algo(part).digest() != digest:
                return False, ['slot -%d (%s) com hash diferente'
                               % (slot, 'requirements' if slot == 2 else 'entitlements')]

    ident = cd[identoff:cd.index(b'\0', identoff)].decode('utf8', 'replace')
    flags = 'adhoc' if cflags & 0x2 else 'flags 0x%X' % cflags
    lines.append('%d paginas ok, %s, ident %s, cdhash %s'
                 % (ncode, flags, ident, hashlib.sha256(cd).hexdigest()[:16]))
    return True, lines


def main():
    if len(sys.argv) < 2:
        sys.exit('uso: python tools/verify_ipa.py <arquivo.ipa> [--expect-appid ID]')
    path = sys.argv[1]
    expect_appid = None
    if '--expect-appid' in sys.argv:
        expect_appid = sys.argv[sys.argv.index('--expect-appid') + 1]
    no_sign_check = '--no-sign-check' in sys.argv
    reference = None
    if '--reference' in sys.argv:
        reference = sys.argv[sys.argv.index('--reference') + 1]
    if not os.path.isfile(path):
        sys.exit('nao existe: %s' % path)

    z = zipfile.ZipFile(path)
    names = [n for n in z.namelist() if not n.endswith('/')]
    apps = sorted({n.split('/')[1] for n in names if n.startswith('Payload/') and n.count('/') > 1})
    if len(apps) != 1:
        print('ERRO: Payload com %d apps: %s' % (len(apps), apps))
        sys.exit(1)
    app = apps[0]
    root = 'Payload/%s/' % app
    print('ipa      : %s' % path)
    print('tamanho  : %d bytes, %d arquivos' % (os.path.getsize(path), len(names)))
    print('app      : %s' % app)

    fails = 0
    print('')
    print('%-46s %10s  %s' % ('binario', 'bytes', 'assinatura'))
    print('-' * 96)
    for n in sorted(names):
        b = z.read(n)
        if len(b) < 32 or not is_macho(b[:4]):
            continue
        ok, lines = check_macho(n, b)
        rel = n[len(root):] if n.startswith(root) else n
        print('%-46s %10d  %s' % (rel[:46], len(b), lines[0]))
        for extra in lines[1:]:
            print('%-46s %10s    %s' % ('', '', extra))
        if not ok and not no_sign_check:
            fails += 1
        elif not ok:
            print('%-46s %10s    (ignorado: --no-sign-check)' % ('', ''))

    print('')
    info = plistlib.loads(z.read(root + 'Info.plist'))
    bid = info.get('CFBundleIdentifier')
    exe = info.get('CFBundleExecutable')
    print('bundle id: %s' % bid)
    print('exec     : %s %s' % (exe, '(existe)' if root + exe in names else '(NAO EXISTE)'))
    if root + exe not in names:
        fails += 1

    sig_files = [n for n in names if '/_CodeSignature/' in n]
    print('_CodeSignature: %s' % ('presente (%d arquivos)' % len(sig_files) if sig_files else 'ausente (o instalador recria)'))

    junk = [n for n in names if n.lower().endswith(JUNK)]
    print('lixo no bundle : %s' % (junk if junk else 'nenhum'))
    if junk:
        fails += 1

    # entitlements embutidos no binario principal
    main_b = z.read(root + exe)
    info_m = layout(main_b)
    if info_m['sig']:
        dataoff, datasize = info_m['sig']
        blob = main_b[dataoff:dataoff + datasize]
        magic, length, count = struct.unpack_from('>III', blob, 0)
        appid = None
        for i in range(count):
            typ, off = struct.unpack_from('>II', blob, 12 + i * 8)
            if typ == 5:
                m, l = struct.unpack_from('>II', blob, off)
                ent = plistlib.loads(blob[off + 8:off + l])
                appid = ent.get('application-identifier')
                print('entitlements   : %s' % ', '.join(sorted(ent)))
        print('app-identifier : %s' % appid)
        if appid and bid and not appid.endswith('.' + bid):
            print('  AVISO: application-identifier nao casa com o bundle id')
            print('         (o IPA original tem o mesmo desvio - o instalador gera os seus)')
            if expect_appid:
                fails += 1
        if expect_appid and appid != expect_appid:
            print('  AVISO: esperado %s' % expect_appid)
            fails += 1

    if reference:
        zr = zipfile.ZipFile(reference)
        nr = {x for x in zr.namelist() if not x.endswith('/')}
        nn = set(names)
        print('')
        print('comparacao com %s:' % os.path.basename(reference))
        print('  original : %d arquivos' % len(nr))
        print('  este     : %d arquivos' % len(nn))
        print('  so aqui  : %s' % (sorted(nn - nr) or 'nada'))
        print('  so no original: %s' % (sorted(nr - nn) or 'nada'))
        changed = []
        for x in sorted(nr & nn):
            if zr.getinfo(x).CRC != z.getinfo(x).CRC:
                changed.append(x[len(root):] if x.startswith(root) else x)
        print('  conteudo diferente: %s' % (changed or 'nada'))

    print('')
    print('resultado: %s' % ('OK - pronto pra instalar' if not fails else '%d PROBLEMA(S)' % fails))
    sys.exit(0 if not fails else 1)


if __name__ == '__main__':
    main()
