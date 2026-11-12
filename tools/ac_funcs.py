import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

P = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Frameworks\libac_sdk.dylib'
d = open(P, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

FUNCS = [
    (0x4FF4, 'check_init_only'),
    (0x5438, 'check_bit1'),
    (0x54E0, 'check_bit2'),
    (0x503C, 'check_bit4'),
    (0x63DC, 'check_bit8'),
    (0x6BD0, 'check_bit10'),
    (0x6990, 'check_bit20'),
    (0x6A68, 'check_bit40'),
]

for a, lbl in FUNCS:
    print('==== %s @ 0x%X' % (lbl, a))
    n = 0
    for i in md.disasm(d[a:a+400], a):
        print('   0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))
        n += 1
        if i.mnemonic in ('ret',) or n >= 45:
            break
    print('')

print('==== AcSDK_get_report tail (flags field) ====')
for i in md.disasm(d[0x4ED4:0x4ED4+0x60], 0x4ED4):
    print('   0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))

print('')
print('==== LC_LOAD_DYLIB do binario principal ====')
B = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\freefireth'
b = open(B, 'rb').read()
ncmds = struct.unpack_from('<I', b, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', b, off)
    if cmd in (0xC, 0x8000001F, 0x18):
        name = b[off+24:off+cmdsize].split(b'\0')[0].decode('utf8', 'replace')
        tag = {0xC: 'LOAD', 0x8000001F: 'REEXPORT', 0x18: 'WEAK'}[cmd]
        print('  %-9s %s' % (tag, name))
    off += cmdsize
