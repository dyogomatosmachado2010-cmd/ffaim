import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

P = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Frameworks\libac_sdk.dylib'
d = open(P, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

print('--- hash fn @ 0x411c ---')
n = 0
for i in md.disasm(d[0x411c:0x411c + 200], 0x411c):
    print('   0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))
    n += 1
    if i.mnemonic == 'ret' or n > 40:
        break
print('')
print('--- 0x7d2c (bundle id?) ---')
for i in md.disasm(d[0x7d2c:0x7d2c + 120], 0x7d2c):
    print('   0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))
