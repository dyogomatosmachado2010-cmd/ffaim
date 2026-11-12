#!/usr/bin/env python3
# inject.py - injeta dylibs num .app e empacota um .ipa novo (Windows/Linux/macOS, sem toolchain)
#
# uso:
#   python tools/inject.py --app "<caminho do freefireth.app>" \
#                          --dylib build/ffaim.dylib \
#                          --dylib build/libsubstrate.dylib \
#                          --out FreeFire_ffaim.ipa
#
# o que faz:
#   1. copia o .app pra uma pasta de trabalho (nao mexe no original)
#   2. copia cada dylib pra <app>/Frameworks/
#   3. adiciona um LC_LOAD_DYLIB "@executable_path/Frameworks/<nome>" no binario principal
#   4. zera o LC_CODE_SIGNATURE e apaga _CodeSignature (quem assina de novo e o TrollStore/Sideloadly/ldid)
#   5. zipa em Payload/<app>/... e escreve o .ipa
#
# falha fechado: sem espaco no header, magic errado, dylib inexistente ou LC duplicado -> recusa.
import argparse, os, shutil, struct, sys, tempfile, zipfile

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_CODE_SIGNATURE = 0x1D
DYLIB_CMDS = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB)


def die(msg):
    sys.exit('erro: ' + msg)


def align8(n):
    return (n + 7) & ~7


def parse(b):
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = \
        struct.unpack_from('<IiiIIIII', b, 0)
    if magic != MH_MAGIC_64:
        die('nao e Mach-O 64-bit little endian (magic 0x%08X)' % magic)
    if cputype != 0x0100000C:
        die('nao e arm64 (cputype 0x%X)' % cputype)
    return {'ncmds': ncmds, 'sizeofcmds': sizeofcmds, 'filetype': filetype}


def iter_cmds(b, hdr):
    off = 32
    for _ in range(hdr['ncmds']):
        cmd, cmdsize = struct.unpack_from('<II', b, off)
        if cmdsize < 8 or off + cmdsize > len(b):
            die('load command corrompido em 0x%X' % off)
        yield off, cmd, cmdsize
        off += cmdsize


def first_section_offset(b, hdr):
    """menor file offset de secao com conteudo - limite de onde o header pode crescer"""
    best = 1 << 62
    for off, cmd, cmdsize in iter_cmds(b, hdr):
        if cmd != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from('<I', b, off + 64)[0]
        for i in range(nsects):
            s = off + 72 + i * 80
            size = struct.unpack_from('<Q', b, s + 40)[0]
            foff = struct.unpack_from('<I', b, s + 48)[0]
            if foff and size and foff < best:
                best = foff
    return best


def existing_dylibs(b, hdr):
    out = []
    for off, cmd, cmdsize in iter_cmds(b, hdr):
        if cmd not in DYLIB_CMDS:
            continue
        name_off = struct.unpack_from('<I', b, off + 8)[0]
        raw = b[off + name_off: off + cmdsize].split(b'\0')[0]
        out.append(raw.decode('utf8', 'replace'))
    return out


def strip_signature(b):
    hdr = parse(b)
    for off, cmd, cmdsize in iter_cmds(b, hdr):
        if cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from('<II', b, off + 8)
            struct.pack_into('<II', b, off + 8, 0, 0)
            return dataoff, datasize
    return 0, 0


# chaves que o hook inline (cheat/ffhook.mm) precisa pra poder escrever em pagina
# de codigo e criar o trampoline. sem elas o dylib carrega mas o hook falha.
JIT_KEYS = ('dynamic-codesigning', 'com.apple.security.cs.allow-jit')


def add_jit_entitlements(xml):
    """insere as chaves de JIT no XML de entitlements, se ainda nao existirem"""
    text = xml.decode('utf8', 'replace')
    extra = ''
    for k in JIT_KEYS:
        if '<key>%s</key>' % k in text:
            continue
        extra += '\t<key>%s</key>\n\t<true/>\n' % k
    if not extra:
        return xml
    i = text.rfind('</dict>')
    if i < 0:
        return xml
    return (text[:i] + extra + text[i:]).encode('utf8')


def extract_entitlements(b, dataoff, datasize):
    if not dataoff or not datasize or dataoff + datasize > len(b):
        return None
    blob = bytes(b[dataoff:dataoff + datasize])
    magic, length, count = struct.unpack_from('>III', blob, 0)
    if magic != 0xFADE0CC0:
        return None
    for i in range(count):
        typ, off = struct.unpack_from('>II', blob, 12 + i * 8)
        if typ != 5:
            continue
        m, l = struct.unpack_from('>II', blob, off)
        if m != 0xFADE7171 or off + l > len(blob):
            return None
        return blob[off + 8: off + l]
    return None


def add_dylib(b, path):
    """b: bytearray. adiciona LC_LOAD_DYLIB com esse path."""
    hdr = parse(b)
    if path in existing_dylibs(b, hdr):
        print('  ja presente: %s' % path)
        return False

    name = path.encode('utf8') + b'\0'
    cmdsize = align8(24 + len(name))
    end = 32 + hdr['sizeofcmds']
    limit = first_section_offset(b, hdr)
    if end + cmdsize > limit:
        die('sem espaco no header: precisa %d bytes, sobram %d' % (cmdsize, limit - end))

    struct.pack_into('<IIIIII', b, end, LC_LOAD_DYLIB, cmdsize, 24, 2, 0x00010000, 0x00010000)
    b[end + 24: end + 24 + len(name)] = name
    # padding
    for i in range(end + 24 + len(name), end + cmdsize):
        b[i] = 0

    struct.pack_into('<I', b, 16, hdr['ncmds'] + 1)
    struct.pack_into('<I', b, 20, hdr['sizeofcmds'] + cmdsize)
    print('  LC_LOAD_DYLIB %s (%d bytes)' % (path, cmdsize))
    return True


def find_main_binary(app):
    info = os.path.join(app, 'Info.plist')
    if not os.path.isfile(info):
        die('sem Info.plist em %s' % app)
    name = None
    raw = open(info, 'rb').read()
    # procura CFBundleExecutable sem plistlib binario
    key = b'<key>CFBundleExecutable</key>'
    i = raw.find(key)
    if i >= 0:
        s = raw.find(b'<string>', i)
        e = raw.find(b'</string>', s)
        if s > 0 and e > s:
            name = raw[s + 8:e].decode('utf8')
    if not name:
        # binario do plist: pega o arquivo executavel obvio
        for f in os.listdir(app):
            p = os.path.join(app, f)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                with open(p, 'rb') as fh:
                    if fh.read(4) == b'\xcf\xfa\xed\xfe':
                        name = f
                        break
    if not name:
        die('nao consegui descobrir o executavel principal')
    path = os.path.join(app, name)
    if not os.path.isfile(path):
        die('executavel nao existe: %s' % path)
    return name, path


def zip_dir(src_root, out_ipa):
    if os.path.exists(out_ipa):
        os.remove(out_ipa)
    n = 0
    with zipfile.ZipFile(out_ipa, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for root, dirs, files in os.walk(src_root):
            for d in dirs:
                full = os.path.join(root, d)
                rel = os.path.relpath(full, src_root).replace('\\', '/') + '/'
                z.writestr(rel, b'')
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, src_root).replace('\\', '/')
                z.write(full, rel)
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--app', required=True, help='pasta .app extraida')
    ap.add_argument('--dylib', action='append', default=[], help='dylib a injetar (pode repetir)')
    ap.add_argument('--out', required=True, help='.ipa de saida')
    ap.add_argument('--work', default=None, help='pasta de trabalho (default: temp)')
    a = ap.parse_args()

    app = os.path.abspath(a.app)
    if not os.path.isdir(app):
        die('app nao encontrada: %s' % app)

    dylibs = []
    for d in a.dylib:
        d = os.path.abspath(d)
        if not os.path.isfile(d):
            die('dylib nao existe: %s' % d)
        with open(d, 'rb') as f:
            if f.read(4) != b'\xcf\xfa\xed\xfe':
                die('%s nao e Mach-O arm64' % d)
        dylibs.append(d)

    work = a.work or tempfile.mkdtemp(prefix='ffipa_')
    payload = os.path.join(work, 'Payload')
    if os.path.isdir(work):
        pass
    os.makedirs(payload, exist_ok=True)

    dst_app = os.path.join(payload, os.path.basename(app))
    if os.path.isdir(dst_app):
        shutil.rmtree(dst_app)
    print('copiando app...')
    shutil.copytree(app, dst_app, symlinks=True)

    exe_name, exe_path = find_main_binary(dst_app)

    fw = os.path.join(dst_app, 'Frameworks')
    os.makedirs(fw, exist_ok=True)

    with open(exe_path, 'rb') as f:
        b = bytearray(f.read())

    print('binario: %s (%d bytes)' % (exe_name, len(b)))
    print('injeta:')
    for d in dylibs:
        base = os.path.basename(d)
        shutil.copy2(d, os.path.join(fw, base))
        print('  copia %s -> Frameworks/%s' % (base, base))
        add_dylib(b, '@executable_path/Frameworks/' + base)

    dataoff, datasize = strip_signature(b)
    if datasize:
        print('assinatura removida: LC_CODE_SIGNATURE 0x%X/0x%X' % (dataoff, datasize))

    ent = extract_entitlements(b, dataoff, datasize)
    ent_path = os.path.abspath(a.out) + '.entitlements.plist'
    if ent:
        ent = add_jit_entitlements(ent)
        with open(ent_path, 'wb') as f:
            f.write(ent)
        print('entitlements salvos: %s (com dynamic-codesigning)' % ent_path)
    else:
        ent_path = None
        print('sem entitlements embutidos (o app sera assinado sem eles)')

    with open(exe_path, 'wb') as f:
        f.write(b)

    sig_dir = os.path.join(dst_app, '_CodeSignature')
    if os.path.isdir(sig_dir):
        shutil.rmtree(sig_dir)
        print('_CodeSignature removida')

    print('empacotando...')
    n = zip_dir(work, os.path.abspath(a.out))
    print('ok: %s (%d arquivos)' % (os.path.abspath(a.out), n))
    print('')
    print('proximo passo: assinar e instalar')
    print('  TrollStore  -> instala o .ipa direto (ele assina)')
    print('  Sideloadly  -> abre o .ipa, ele reassina com seu Apple ID')
    if ent_path:
        print('')
        print('  jailbreak / assinatura manual:')
        print('    unzip -o "%s" -d ipa_build' % os.path.abspath(a.out))
        print('    ldid -S"%s" ipa_build/Payload/%s' % (ent_path, exe_name))
        for d in dylibs:
            print('    ldid -S ipa_build/Payload/%s/Frameworks/%s'
                  % (os.path.basename(app), os.path.basename(d)))
    else:
        print('  jailbreak   -> unzip, ldid -S cada dylib e o binario, depois dpkg/cp')


if __name__ == '__main__':
    main()
