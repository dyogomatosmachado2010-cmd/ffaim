#!/usr/bin/env python3
# ldid.py - assinatura ad-hoc de Mach-O arm64 sem toolchain (equivalente a `ldid -S`)
#
#   python tools/ldid.py --sign cheat/ffaim.dylib
#   python tools/ldid.py --verify cheat/ffaim.dylib
#   python tools/ldid.py --sign cheat/ffaim.dylib --entitlements ent.plist
#
# o que escreve:
#   - LC_CODE_SIGNATURE (cria se nao existir, usando a folga do header)
#   - CodeDirectory v0x20400, SHA-256, paginas de 4096, flag CS_ADHOC
#   - SuperBlob com CodeDirectory + Requirements (+ Entitlements)
#   - estende __LINKEDIT pra cobrir o blob
#
# falha fechado: magic errado, fat binary, sem __LINKEDIT, sem folga no header
# ou LC_CODE_SIGNATURE apontando pra fora do arquivo -> recusa e nao grava nada.
import argparse, hashlib, os, struct, sys

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D

CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171

CS_ADHOC = 0x2
PAGE = 4096
HASH_SIZE = 32
HASH_TYPE_SHA256 = 2
CD_VERSION = 0x20400

SLOT_INFO = -1
SLOT_REQUIREMENTS = -2
SLOT_RESOURCES = -3
SLOT_ENTITLEMENTS = -5


def die(msg):
    sys.exit('erro: ' + msg)


def align(n, a):
    return (n + a - 1) & ~(a - 1)


def parse(b):
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = \
        struct.unpack_from('<IiiIIIII', b, 0)
    if magic == FAT_MAGIC:
        die('fat binary (universal) nao suportado - extraia a fatia arm64 antes')
    if magic != MH_MAGIC_64:
        die('nao e Mach-O 64-bit little endian (magic 0x%08X)' % magic)
    return {'cputype': cputype, 'filetype': filetype,
            'ncmds': ncmds, 'sizeofcmds': sizeofcmds}


def iter_cmds(b, ncmds):
    off = 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from('<II', b, off)
        if cs < 8 or off + cs > len(b):
            die('load command corrompido em 0x%X' % off)
        yield off, cmd, cs
        off += cs


def layout(b):
    hdr = parse(b)
    linkedit = None
    sig_cmd = None
    first_section = 1 << 62
    for off, cmd, cs in iter_cmds(b, hdr['ncmds']):
        if cmd == LC_SEGMENT_64:
            segname = bytes(b[off + 8:off + 24]).split(b'\0')[0]
            if segname == b'__LINKEDIT':
                linkedit = off
            nsects = struct.unpack_from('<I', b, off + 64)[0]
            for i in range(nsects):
                s = off + 72 + i * 80
                foff = struct.unpack_from('<I', b, s + 48)[0]
                size = struct.unpack_from('<Q', b, s + 40)[0]
                if foff and size and foff < first_section:
                    first_section = foff
        if cmd == LC_CODE_SIGNATURE:
            sig_cmd = off
    return hdr, linkedit, sig_cmd, first_section


def requirements_blob():
    # conjunto de requisitos vazio, igual ao que o ldid emite pra adhoc
    return struct.pack('>III', CSMAGIC_REQUIREMENTS, 12, 0)


def entitlements_blob(xml):
    return struct.pack('>II', CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(xml)) + xml


def code_directory(identifier, code_limit, code_hashes, special, flags=CS_ADHOC):
    ident = identifier.encode('utf8') + b'\0'
    n_special = max([abs(k) for k in special] + [0])
    ident_off = 88
    hash_off = ident_off + len(ident) + n_special * HASH_SIZE
    length = hash_off + len(code_hashes) * HASH_SIZE

    cd = bytearray(length)
    struct.pack_into('>IIIIIIIII', cd, 0,
                     CSMAGIC_CODEDIRECTORY, length, CD_VERSION, flags,
                     hash_off, ident_off, n_special, len(code_hashes), code_limit)
    cd[36] = HASH_SIZE
    cd[37] = HASH_TYPE_SHA256
    cd[38] = 0                     # platform
    cd[39] = 12                    # pageSize = 2^12
    struct.pack_into('>I', cd, 40, 0)          # spare2
    struct.pack_into('>I', cd, 44, 0)          # scatterOffset
    struct.pack_into('>I', cd, 48, 0)          # teamOffset
    struct.pack_into('>I', cd, 52, 0)          # spare3
    struct.pack_into('>Q', cd, 56, 0)          # codeLimit64
    struct.pack_into('>QQQ', cd, 64, 0, 0, 0)  # execSegBase / Limit / Flags
    cd[ident_off:ident_off + len(ident)] = ident

    for slot, digest in special.items():
        pos = hash_off + slot * HASH_SIZE     # slot negativo -> antes das paginas
        cd[pos:pos + HASH_SIZE] = digest

    for i, h in enumerate(code_hashes):
        pos = hash_off + i * HASH_SIZE
        cd[pos:pos + HASH_SIZE] = h
    return bytes(cd)


def superblob(parts):
    header = 12 + 8 * len(parts)
    total = header + sum(len(blob) for _, blob in parts)
    out = bytearray(header)
    struct.pack_into('>III', out, 0, CSMAGIC_EMBEDDED_SIGNATURE, total, len(parts))
    offset = header
    for i, (typ, blob) in enumerate(parts):
        struct.pack_into('>II', out, 12 + i * 8, typ, offset)
        out += blob
        offset += len(blob)
    return bytes(out)


def sign(data, identifier, entitlements=None):
    b = bytearray(data)
    hdr, linkedit, sig_cmd, first_section = layout(b)
    if linkedit is None:
        die('sem segmento __LINKEDIT')

    header_end = 32 + hdr['sizeofcmds']
    dataoff = 0

    if sig_cmd is not None:
        old_off, old_size = struct.unpack_from('<II', b, sig_cmd + 8)
        if old_off and old_off >= header_end and old_off + old_size <= len(b):
            # assinatura antiga: reaproveita o espaco reservado (nao cresce o arquivo)
            dataoff = align(old_off, 16)
        elif old_off == 0 and old_size == 0:
            # comando presente mas zerado (inject.py): assinatura vai pro fim
            dataoff = align(len(b), 16)
        else:
            die('LC_CODE_SIGNATURE existente aponta pra fora (0x%X/0x%X)' % (old_off, old_size))
    else:
        if header_end + 16 > first_section:
            die('sem folga no header: precisa 16 bytes, sobram %d' % (first_section - header_end))
        dataoff = align(len(b), 16)

    code_limit = dataoff

    req = requirements_blob()
    ent = entitlements_blob(entitlements) if entitlements else None

    ncode = (code_limit + PAGE - 1) // PAGE
    n_special = 5 if ent else 2
    cd_len = 88 + len(identifier.encode('utf8')) + 1 + n_special * HASH_SIZE + ncode * HASH_SIZE
    parts_len = 2 + (1 if ent else 0)
    blob_len = 12 + 8 * parts_len + cd_len + len(req) + (len(ent) if ent else 0)

    # 1. grava os load commands ANTES de calcular os hashes: a pagina 0 contem eles
    if sig_cmd is not None:
        struct.pack_into('<II', b, sig_cmd + 8, dataoff, blob_len)
    else:
        struct.pack_into('<IIII', b, header_end, LC_CODE_SIGNATURE, 16, dataoff, blob_len)
        struct.pack_into('<I', b, 16, hdr['ncmds'] + 1)
        struct.pack_into('<I', b, 20, hdr['sizeofcmds'] + 16)

    # 2. reserva o espaco do blob: cresce se faltar, limpa se sobrar assinatura velha
    end = dataoff + blob_len
    if end > len(b):
        b += b'\0' * (end - len(b))
    else:
        b[dataoff:end] = b'\0' * blob_len

    vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', b, linkedit + 24)
    new_filesize = end - fileoff
    if new_filesize > filesize:
        struct.pack_into('<Q', b, linkedit + 32, max(vmsize, align(new_filesize, 0x4000)))
        struct.pack_into('<Q', b, linkedit + 48, new_filesize)

    # 3. hashes das paginas do arquivo ja finalizado
    #    a ultima pagina conta so ate codeLimit (igual ao codesign da Apple)
    code_hashes = [hashlib.sha256(bytes(b[i:min(i + PAGE, code_limit)])).digest()
                   for i in range(0, code_limit, PAGE)]

    special = {SLOT_REQUIREMENTS: hashlib.sha256(req).digest()}
    parts = [(0, None), (2, req)]
    if ent:
        special[SLOT_ENTITLEMENTS] = hashlib.sha256(ent).digest()
        parts.append((5, ent))

    cd = code_directory(identifier, code_limit, code_hashes, special)
    parts[0] = (0, cd)
    blob = superblob(parts)
    if len(blob) != blob_len:
        die('tamanho do blob divergiu (%d != %d)' % (len(blob), blob_len))

    b[dataoff:dataoff + blob_len] = blob
    return bytes(b), cd


def check(data):
    """valida a assinatura sem imprimir nada. devolve (ok, motivo)"""
    try:
        hdr, linkedit, sig_cmd, _ = layout(data)
    except SystemExit:
        return False, 'cabecalho invalido'
    if sig_cmd is None:
        return False, 'sem LC_CODE_SIGNATURE'
    dataoff, datasize = struct.unpack_from('<II', data, sig_cmd + 8)
    if not dataoff or not datasize:
        return False, 'LC_CODE_SIGNATURE vazio'
    if dataoff + datasize > len(data):
        return False, 'blob fora do arquivo'
    blob = data[dataoff:dataoff + datasize]
    magic, length, count = struct.unpack_from('>III', blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE or length > datasize:
        return False, 'superblob invalido'
    cd = None
    parts = {}
    for i in range(count):
        typ, off = struct.unpack_from('>II', blob, 12 + i * 8)
        if off + 8 > len(blob):
            return False, 'entrada do superblob fora do blob'
        bm, bl = struct.unpack_from('>II', blob, off)
        if bl < 8 or off + bl > len(blob):
            return False, 'blob com tamanho invalido'
        parts[typ] = blob[off:off + bl]
        if typ == 0:
            cd = parts[typ]
    if cd is None:
        return False, 'sem CodeDirectory'
    (cmagic, clen, cver, cflags, hashoff, identoff,
     nspecial, ncode, codelimit) = struct.unpack_from('>IIIIIIIII', cd, 0)
    if cmagic != CSMAGIC_CODEDIRECTORY:
        return False, 'CodeDirectory invalido'
    if codelimit > len(data):
        return False, 'codeLimit maior que o arquivo'
    hsize = cd[36]
    algo = {32: hashlib.sha256, 20: hashlib.sha1}.get(hsize)
    if algo is None:
        return False, 'hash de %d bytes' % hsize
    for i in range(ncode):
        page = bytes(data[i * PAGE:min((i + 1) * PAGE, codelimit)])
        if algo(page).digest() != cd[hashoff + i * hsize:hashoff + (i + 1) * hsize]:
            return False, 'pagina %d com hash diferente' % i
    for slot in range(1, nspecial + 1):
        pos = hashoff - slot * hsize
        digest = cd[pos:pos + hsize]
        if digest == b'\0' * hsize:
            continue
        if slot in (2, 5):
            part = parts.get(slot)
            if part is None or algo(part).digest() != digest:
                return False, 'slot -%d com hash diferente' % slot
    if linkedit is not None:
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, linkedit + 24)
        if not (fileoff <= dataoff and dataoff + datasize <= fileoff + filesize):
            return False, 'blob fora do __LINKEDIT'
    return True, 'ok'


def verify(data):
    hdr, linkedit, sig_cmd, _ = layout(data)
    if sig_cmd is None:
        print('sem LC_CODE_SIGNATURE')
        return False
    dataoff, datasize = struct.unpack_from('<II', data, sig_cmd + 8)
    if dataoff + datasize > len(data):
        print('blob fora do arquivo')
        return False
    blob = data[dataoff:dataoff + datasize]
    magic, length, count = struct.unpack_from('>III', blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE or length != datasize:
        print('superblob invalido')
        return False
    cd = None
    for i in range(count):
        typ, off = struct.unpack_from('>II', blob, 12 + i * 8)
        if typ == 0:
            cd = blob[off:]
    if cd is None:
        print('sem CodeDirectory')
        return False
    (cmagic, clen, cver, cflags, hashoff, identoff,
     nspecial, ncode, codelimit) = struct.unpack_from('>IIIIIIIII', cd, 0)
    if cmagic != CSMAGIC_CODEDIRECTORY:
        print('CodeDirectory invalido')
        return False
    ident = cd[identoff:cd.index(b'\0', identoff)].decode('utf8', 'replace')
    hsize, htype = cd[36], cd[37]
    print('CodeDirectory: version 0x%X flags 0x%X' % (cver, cflags))
    print('  identifier  : %s' % ident)
    print('  hash        : %s  (%d bytes, pagina %d)'
          % ('sha256' if htype == 2 else htype, hsize, 1 << cd[39]))
    print('  codeLimit   : 0x%X   paginas: %d   slots especiais: %d'
          % (codelimit, ncode, nspecial))
    print('  cdhash      : %s' % hashlib.sha256(cd).hexdigest()[:40])

    ok = True
    for i in range(ncode):
        page = bytes(data[i * PAGE:min((i + 1) * PAGE, codelimit)])
        want = cd[hashoff + i * hsize:hashoff + (i + 1) * hsize]
        if hashlib.sha256(page).digest() != want:
            print('  pagina %d: HASH DIFERENTE' % i)
            ok = False
    for slot in range(1, nspecial + 1):
        pos = hashoff - slot * hsize
        digest = cd[pos:pos + hsize]
        if digest == b'\0' * hsize:
            continue
        if slot in (2, 5):
            blob2 = data[dataoff:dataoff + datasize]
            part = None
            for i in range(count):
                typ, off = struct.unpack_from('>II', blob2, 12 + i * 8)
                if typ == slot:
                    m, l = struct.unpack_from('>II', blob2, off)
                    if l >= 8 and off + l <= len(blob2):
                        part = blob2[off:off + l]
            name = {2: 'requirements', 5: 'entitlements'}[slot]
            if part is None or hashlib.sha256(part).digest() != digest:
                print('  slot -%d (%s): HASH DIFERENTE' % (slot, name))
                ok = False
    print('  assinatura  : %s' % ('OK' if ok else 'CORROMPIDA'))

    # o blob tem que caber dentro de __LINKEDIT, senao o kernel nao mapeia
    seg = None
    for off, cmd, cs in iter_cmds(data, hdr['ncmds']):
        if cmd == LC_SEGMENT_64 and bytes(data[off + 8:off + 24]).split(b'\0')[0] == b'__LINKEDIT':
            seg = struct.unpack_from('<QQQQ', data, off + 24)
    if seg:
        vmaddr, vmsize, fileoff, filesize = seg
        if not (fileoff <= dataoff and dataoff + datasize <= fileoff + filesize):
            print('  __LINKEDIT : NAO COBRE O BLOB (fileoff 0x%X filesize 0x%X, blob 0x%X..0x%X)'
                  % (fileoff, filesize, dataoff, dataoff + datasize))
            ok = False
        else:
            print('  __LINKEDIT : cobre o blob (fileoff 0x%X filesize 0x%X)' % (fileoff, filesize))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sign', metavar='MACHO')
    ap.add_argument('--verify', metavar='MACHO')
    ap.add_argument('--entitlements', metavar='PLIST')
    ap.add_argument('--identifier', metavar='ID')
    a = ap.parse_args()

    if not a.sign and not a.verify:
        die('use --sign <arquivo> ou --verify <arquivo>')

    target = a.sign or a.verify
    if not os.path.isfile(target):
        die('nao existe: %s' % target)

    with open(target, 'rb') as f:
        data = f.read()

    if a.verify:
        ok = verify(data)
        sys.exit(0 if ok else 1)

    ident = a.identifier or os.path.basename(target).rsplit('.', 1)[0]
    ent = None
    if a.entitlements:
        with open(a.entitlements, 'rb') as f:
            ent = f.read()

    out, cd = sign(data, ident, ent)
    tmp = target + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(out)
    os.replace(tmp, target)

    print('%s assinado (adhoc)' % target)
    print('  identifier : %s' % ident)
    print('  tamanho    : %d -> %d bytes' % (len(data), len(out)))
    print('  cdhash     : %s' % hashlib.sha256(cd).hexdigest()[:40])
    print('')
    print('conferindo...')
    with open(target, 'rb') as f:
        verify(f.read())


if __name__ == '__main__':
    main()
