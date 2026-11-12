#!/usr/bin/env python3
# ffpatch.py - bypass de arquivo do anti-cheat do FreeFire 1.28.0 (iOS)
#
# Alvo: Frameworks/libac_sdk.dylib dentro do .app.
# O dylib faz 7 checagens e publica as flags em AcSDK_flags()/AcSDK_tick()/
# AcSDK_get_report() (JSON "flags":%u enviado pro servidor).
#
# Este script:
#   1. neutraliza cada funcao de checagem no ponto de retorno (2 instrucoes)
#   2. recalcula o CRC32 de __TEXT.__text e regrava o valor esperado em __data
#      (o check de auto-integridade continua rodando e continua passando)
#
# Nada no binario principal e tocado -> o hash/assinatura do jogo fica igual.
#
# uso:
#   python ffpatch.py --info
#   python ffpatch.py --apply            # modo A: mantem o check de CRC vivo
#   python ffpatch.py --apply --full     # modo B: mata o check de CRC tambem
#   python ffpatch.py --verify
#   python ffpatch.py --restore
import argparse, os, shutil, struct, sys, zlib

DEFAULT = os.path.join(os.environ.get('TEMP', r'C:\Windows\Temp'),
                       'ff_ipa', 'Payload', 'freefireth.app', 'Frameworks', 'libac_sdk.dylib')

TEXT_OFF  = 0x4000
TEXT_SIZE = 0x4718
CRC_SLOT  = 0xC254          # __data: crc32 esperado de __TEXT.__text
CONST_SLOT = 0xC258         # __data: crc32 esperado de __TEXT.__const (0 = desarmado)
STOCK_CRC = 0xE836EF99
EXPECTED_SIZE = 70312

# (rva, valor de retorno "limpo", nome, o que detecta)
CHECKS = [
    (0x5438, 0, 'dbg_ptrace',    'P_TRACED via sysctl (debugger)'),
    (0x54E0, 0, 'dyld_images',   'nomes de imagem no dyld (substrate/frida/cycript/...)'),
    (0x503C, 1, 'self_crc',      'crc32 do proprio __TEXT.__text'),
    (0x63DC, 1, 'bundle_paths',  'sonda de arquivos dentro do bundle'),
    (0x6BD0, 1, 'dyld_filetype', 'varredura de imagens por filetype'),
    (0x6990, 1, 'bundle_id',     'CFBundleIdentifier == com.privateproject.ff2018'),
    (0x6A68, 0, 'jb_paths',      'Cydia/Sileo/sshd/apt/var-jb/... por access()'),
]

STOCK = {
    0x5438: 'fc6fbea9fd7b01a9',
    0x54E0: 'fc6fbaa9fa6701a9',
    0x503C: 'ff4301d1f65702a9',
    0x63DC: 'fc6fbaa9fa6701a9',
    0x6BD0: 'f657bda9f44f01a9',
    0x6990: 'ffc304d1fc6f11a9',
    0x6A68: 'ff8300d1fd7b01a9',
}

def stub(val):
    mov = 0x52800000 | ((val & 0xFFFF) << 5)
    return struct.pack('<II', mov, 0xD65F03C0)

def text_crc(d):
    return zlib.crc32(d[TEXT_OFF:TEXT_OFF + TEXT_SIZE]) & 0xFFFFFFFF

def load(path):
    if not os.path.isfile(path):
        sys.exit('nao achei: %s' % path)
    d = open(path, 'rb').read()
    if len(d) != EXPECTED_SIZE:
        sys.exit('tamanho inesperado (%d, esperado %d) - build diferente, nao vou tocar' % (len(d), EXPECTED_SIZE))
    if struct.unpack_from('<I', d, 0)[0] != 0xFEEDFACF:
        sys.exit('nao e Mach-O arm64 64-bit')
    return d

def status(d):
    rows = []
    for rva, clean, name, desc in CHECKS:
        cur = d[rva:rva + 8]
        if cur == stub(clean):
            st = 'PATCHED'
        elif cur.hex() == STOCK[rva]:
            st = 'stock'
        else:
            st = 'DESCONHECIDO'
        rows.append((rva, name, desc, st, cur.hex()))
    return rows

def cmd_info(path):
    d = load(path)
    print('arquivo : %s' % path)
    print('crc32(__text) = 0x%08X   slot[0x%X] = 0x%08X' %
          (text_crc(d), CRC_SLOT, struct.unpack_from('<I', d, CRC_SLOT)[0]))
    print('')
    print('%-8s %-14s %-8s %-18s %s' % ('rva', 'nome', 'estado', 'bytes', 'detecta'))
    for rva, name, desc, st, cur in status(d):
        print('0x%05X  %-14s %-8s %-18s %s' % (rva, name, st, cur, desc))
    print('')
    print('flags publicadas: AcSDK_flags() -> __data:0xCAA0 (0 = limpo)')

def cmd_apply(path, full):
    d = bytearray(load(path))

    # fail-closed: todo site tem que estar no estado esperado
    for rva, clean, name, desc in CHECKS:
        cur = bytes(d[rva:rva + 8])
        if cur == stub(clean):
            continue
        if cur.hex() != STOCK[rva]:
            sys.exit('site 0x%X (%s) nao bate com este build: %s' % (rva, name, cur.hex()))

    changed = []
    for rva, clean, name, desc in CHECKS:
        if name == 'self_crc' and not full:
            continue
        if bytes(d[rva:rva + 8]) == stub(clean):
            continue
        d[rva:rva + 8] = stub(clean)
        changed.append((rva, name, clean))

    newcrc = text_crc(bytes(d))
    oldcrc = struct.unpack_from('<I', d, CRC_SLOT)[0]
    struct.pack_into('<I', d, CRC_SLOT, newcrc)

    bak = path + '.orig'
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print('backup : %s' % bak)

    open(path, 'wb').write(bytes(d))

    print('patches:')
    for rva, name, clean in changed:
        print('  0x%05X %-14s -> mov w0,#%d; ret' % (rva, name, clean))
    print('crc    : 0x%08X -> 0x%08X  (gravado em 0x%X)' % (oldcrc, newcrc, CRC_SLOT))
    if full:
        print('modo   : FULL - o check de CRC tambem foi desligado')
    else:
        print('modo   : A - check de CRC continua ativo e continua passando')
    print('')
    print('assine de novo (obrigatorio, o patch invalida a assinatura):')
    print('  ldid -S %s' % path)
    print('  # ou: codesign -f -s - --preserve-metadata=entitlements %s' % path)

def cmd_verify(path):
    d = load(path)
    calc = text_crc(d)
    slot = struct.unpack_from('<I', d, CRC_SLOT)[0]
    ok = calc == slot
    print('crc32(__text) = 0x%08X' % calc)
    print('slot 0x%X    = 0x%08X' % (CRC_SLOT, slot))
    print('integridade   : %s' % ('OK' if ok else 'FALHA - rode --apply de novo'))
    if not ok:
        sys.exit(1)

def cmd_restore(path):
    bak = path + '.orig'
    if not os.path.exists(bak):
        sys.exit('sem backup: %s' % bak)
    shutil.copy2(bak, path)
    print('restaurado de %s' % bak)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', default=DEFAULT)
    ap.add_argument('--info', action='store_true')
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--verify', action='store_true')
    ap.add_argument('--restore', action='store_true')
    ap.add_argument('--full', action='store_true', help='mata tambem o check de crc do proprio dylib')
    a = ap.parse_args()

    if a.restore: cmd_restore(a.inp)
    elif a.apply: cmd_apply(a.inp, a.full)
    elif a.verify: cmd_verify(a.inp)
    else: cmd_info(a.inp)

if __name__ == '__main__':
    main()
