#!/usr/bin/env python3
# inject.py - injeta dylibs num .app e empacota um .ipa novo (Windows/Linux/macOS, sem toolchain)
#
# uso:
#   python tools/inject.py --app "<caminho do freefireth.app>" \
#                          --dylib build/ffaim.dylib \
#                          --out FreeFire_ffaim.ipa
#
# o que faz:
#   1. copia o .app pra uma pasta de trabalho (nao mexe no original)
#   2. copia cada dylib pra <app>/Frameworks/ e assina ad-hoc se estiver sem assinatura
#   3. adiciona um LC_LOAD_DYLIB "@executable_path/Frameworks/<nome>" no binario principal
#   4. assina ad-hoc o binario principal (load commands mudaram) e todo Mach-O
#      do bundle que esteja sem assinatura, e apaga a _CodeSignature antiga
#   5. zipa em Payload/<app>/... e escreve o .ipa
#
# falha fechado: sem espaco no header, magic errado, dylib inexistente ou LC duplicado -> recusa.
import argparse, hashlib, os, shutil, struct, sys, tempfile, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import ldid as ffldid
except ImportError:
    ffldid = None

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
    """le o LC_CODE_SIGNATURE atual (nao mexe no binario)"""
    hdr = parse(b)
    for off, cmd, cmdsize in iter_cmds(b, hdr):
        if cmd == LC_CODE_SIGNATURE:
            return struct.unpack_from('<II', b, off + 8)
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


def read_bundle_id(app):
    import plistlib
    with open(os.path.join(app, 'Info.plist'), 'rb') as f:
        try:
            return plistlib.load(f).get('CFBundleIdentifier')
        except Exception:
            return None


def align_entitlements(xml, bid):
    """o application-identifier tem que casar com o CFBundleIdentifier do Info.plist,
    senao o instalador recusa o bundle com erro de assinatura"""
    if not bid:
        return xml
    text = xml.decode('utf8', 'replace')
    i = text.find('<key>application-identifier</key>')
    if i < 0:
        return xml
    s = text.find('<string>', i)
    e = text.find('</string>', s)
    if s < 0 or e < s:
        return xml
    cur = text[s + 8:e]
    team = cur.split('.', 1)[0]
    new = '%s.%s' % (team, bid)
    if new == cur:
        return xml
    print('  entitlements: application-identifier %s -> %s' % (cur, new))
    return (text[:s + 8] + new + text[e:]).encode('utf8')


def sign_main(path, ident, ent):
    """assina ad-hoc o executavel principal: o inject muda os load commands,
    entao a assinatura original deixa de valer"""
    if ffldid is None:
        print('  AVISO: tools/ldid.py nao encontrado - binario principal fica sem assinatura')
        return
    with open(path, 'rb') as f:
        data = f.read()
    out, cd = ffldid.sign(data, ident, ent)
    with open(path, 'wb') as f:
        f.write(out)
    print('  assinado adhoc: %s (%d -> %d bytes, cdhash %s)'
          % (ident, len(data), len(out), hashlib.sha256(cd).hexdigest()[:16]))


def has_code_signature(b):
    hdr = parse(b)
    for off, cmd, cmdsize in iter_cmds(b, hdr):
        if cmd == LC_CODE_SIGNATURE:
            return True
    return False


def sign_dylib(path, base):
    """assina ad-hoc o dylib copiado, se estiver sem assinatura ou com assinatura quebrada"""
    with open(path, 'rb') as f:
        data = f.read()
    if ffldid is not None:
        ok, why = ffldid.check(data)
    else:
        ok, why = has_code_signature(data), 'sem ldid.py'
    if ok:
        print('  ja assinado: %s' % base)
        return
    if ffldid is None:
        print('  AVISO: %s sem assinatura valida (%s) e tools/ldid.py nao foi encontrado'
              % (base, why))
        return
    out, cd = ffldid.sign(data, base.rsplit('.', 1)[0])
    with open(path, 'wb') as f:
        f.write(out)
    print('  assinado adhoc: %s (%s, cdhash %s)'
          % (base, why, hashlib.sha256(cd).hexdigest()[:16]))


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


JUNK_SUFFIXES = ('.orig', '.bak', '.tmp', '.rej', '.old')
# arquivos que ferramentas de analise deixam dentro do .app e que nao existem no IPA original
JUNK_NAMES = ('symbols.txt', 'dump.cs', 'offsets_ff.txt')


def scrub_junk(app):
    """remove backups do ffpatch.py e restos de analise que ficam dentro do .app
    (eles nao existem no IPA original e mudam a estrutura do bundle)"""
    removed = []
    for root, dirs, files in os.walk(app):
        for fn in files:
            if fn.lower().endswith(JUNK_SUFFIXES) or fn.lower() in JUNK_NAMES:
                p = os.path.join(root, fn)
                os.remove(p)
                removed.append(os.path.relpath(p, app))
    for r in removed:
        print('  removido lixo: %s' % r)
    return removed


def ensure_signed(app, skip):
    """garante que todo Mach-O do bundle tenha assinatura valida.
    assina ad-hoc quem estiver sem assinatura ou com assinatura quebrada
    (o framework VK do IPA de origem, por exemplo, ja vem invalido)."""
    if ffldid is None:
        print('  AVISO: tools/ldid.py nao encontrado - binarios sem assinatura ficam como estao')
        return []
    signed = []
    for root, dirs, files in os.walk(app):
        for fn in files:
            p = os.path.join(root, fn)
            if os.path.abspath(p) == os.path.abspath(skip):
                continue
            try:
                with open(p, 'rb') as f:
                    head = f.read(4)
            except OSError:
                continue
            if head not in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe'):
                continue
            with open(p, 'rb') as f:
                data = f.read()
            rel = os.path.relpath(p, app)
            if head == b'\xca\xfe\xba\xbe':
                print('  AVISO: %s e fat binary, assinatura manual necessaria' % rel)
                continue
            ok, why = ffldid.check(data)
            if ok:
                continue
            ident = fn.rsplit('.', 1)[0]
            out, cd = ffldid.sign(data, ident)
            with open(p, 'wb') as f:
                f.write(out)
            signed.append(rel)
            print('  assinado adhoc: %s (motivo: %s, cdhash %s)'
                  % (rel, why, hashlib.sha256(cd).hexdigest()[:16]))
    return signed


def zip_dir(src_root, out_ipa, stored=()):
    if os.path.exists(out_ipa):
        os.remove(out_ipa)
    stored = set(stored)
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
                if rel in stored:
                    # iTunesArtwork fica armazenado sem compressao, igual ao IPA original
                    z.write(full, rel, compress_type=zipfile.ZIP_STORED)
                else:
                    z.write(full, rel)
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--app', required=True, help='pasta .app extraida')
    ap.add_argument('--dylib', action='append', default=[], help='dylib a injetar (pode repetir)')
    ap.add_argument('--out', required=True, help='.ipa de saida')
    ap.add_argument('--work', default=None, help='pasta de trabalho (default: temp)')
    ap.add_argument('--no-entitlements', action='store_true',
                    help='assina o binario principal sem entitlements (instalador com perfil proprio)')
    ap.add_argument('--preserve-signatures', action='store_true',
                    help='nao mexe em assinatura nenhuma: deixa o bundle com a mesma '
                         'estrutura do IPA original (instalador reassina)')
    ap.add_argument('--itunes-artwork', default=None,
                    help='iTunesArtwork do IPA original (vai pro zip sem compressao, como no original)')
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

    print('limpeza:')
    scrub_junk(dst_app)

    exe_name, exe_path = find_main_binary(dst_app)

    fw = os.path.join(dst_app, 'Frameworks')
    os.makedirs(fw, exist_ok=True)

    with open(exe_path, 'rb') as f:
        b = bytearray(f.read())

    print('binario: %s (%d bytes)' % (exe_name, len(b)))
    print('injeta:')
    for d in dylibs:
        base = os.path.basename(d)
        dst = os.path.join(fw, base)
        shutil.copy2(d, dst)
        print('  copia %s -> Frameworks/%s' % (base, base))
        # SEMPRE assina o dylib injetado, inclusive com --preserve-signatures.
        # dylib sem LC_CODE_SIGNATURE nao carrega em iOS: o dyld recusa e o app
        # fecha na hora de abrir. assinar um arquivo que nao existe no IPA
        # original nao muda a estrutura do bundle.
        sign_dylib(dst, base)
        add_dylib(b, '@executable_path/Frameworks/' + base)

    dataoff, datasize = strip_signature(b)
    if datasize:
        print('assinatura original: LC_CODE_SIGNATURE 0x%X/0x%X (sera refeita)' % (dataoff, datasize))

    ent = extract_entitlements(b, dataoff, datasize)
    ent_path = os.path.abspath(a.out) + '.entitlements.plist'
    if ent and a.no_entitlements:
        print('entitlements: ignorados (--no-entitlements)')
        ent = None
        ent_path = None
    elif ent:
        ent = add_jit_entitlements(ent)
        ent = align_entitlements(ent, read_bundle_id(dst_app))
        with open(ent_path, 'wb') as f:
            f.write(ent)
        print('entitlements salvos: %s (com dynamic-codesigning)' % ent_path)
    else:
        ent_path = None
        print('sem entitlements embutidos (o app sera assinado sem eles)')

    with open(exe_path, 'wb') as f:
        f.write(b)

    if a.preserve_signatures:
        print('assinatura: preservada (estrutura igual ao IPA original)')
    else:
        print('limpeza de _CodeSignature antigas:')
        removed_sig = 0
        for root, dirs, files in os.walk(dst_app):
            if '_CodeSignature' in dirs:
                p = os.path.join(root, '_CodeSignature')
                shutil.rmtree(p)
                dirs.remove('_CodeSignature')
                removed_sig += 1
                print('  removida: %s' % os.path.relpath(p, dst_app))
        if not removed_sig:
            print('  nenhuma')

        print('assinatura dos binarios do bundle:')
        sign_main(exe_path, exe_name, ent)
        ensure_signed(dst_app, exe_path)

    print('empacotando...')
    if a.itunes_artwork:
        shutil.copy2(a.itunes_artwork, os.path.join(work, 'iTunesArtwork'))
        print('  iTunesArtwork: %s' % a.itunes_artwork)
    n = zip_dir(work, os.path.abspath(a.out), stored=('iTunesArtwork',))
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
