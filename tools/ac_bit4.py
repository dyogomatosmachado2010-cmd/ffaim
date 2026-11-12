import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

P = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Frameworks\libac_sdk.dylib'
d = open(P, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def show(a, n, lbl):
    print('--- %s @ 0x%X' % (lbl, a))
    for i in md.disasm(d[a:a + n * 4], a):
        print('   0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))
    print('')

show(0x503C, 74, 'bit4 integridade __TEXT')
print('bytes @0x5164:', d[0x5164:0x5180])
print('')
show(0x6990, 40, 'bit20')
show(0x6A68, 30, 'bit40 jailbreak paths')
print('')
print('== LC_LOAD_DYLIB do binario principal ==')
B = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\freefireth'
b = open(B, 'rb').read()
ncmds = struct.unpack_from('<I', b, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', b, off)
    if cmd in (0xC, 0x8000001F, 0x18, 0x80000022):
        name = b[off+24:off+cmdsize].split(b'\0')[0].decode('utf8', 'replace')
        print('  cmd 0x%X  %s' % (cmd, name))
    off += cmdsize
