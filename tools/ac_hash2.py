import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

P = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Frameworks\libac_sdk.dylib'
d = open(P, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for i in md.disasm(d[0x4000:0x411c], 0x4000):
    print('   0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))
