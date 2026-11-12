import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

P = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Frameworks\libac_sdk.dylib'
d = open(P, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

TEXT = (0x4000, 0x4718)
lines = []
for i in md.disasm(d[TEXT[0]:TEXT[0]+TEXT[1]], TEXT[0]):
    lines.append('0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))

open(r'C:\Users\user\Desktop\DUMPER\tools\ac_text.txt', 'w', encoding='utf8').write('\n'.join(lines))
print('instrucoes:', len(lines))

def show(a, n, label):
    print('--- %s @ 0x%X' % (label, a))
    for i in md.disasm(d[a:a+n*4], a):
        print('  0x%05X  %-8s %s' % (i.address, i.mnemonic, i.op_str))
    print('')

show(0x4BE8, 40, 'AcSDK_init')
show(0x4D64, 40, 'AcSDK_tick')
show(0x4DFC, 6, 'AcSDK_flags')
show(0x4E08, 14, 'AcSDK_set_session')
show(0x4E38, 40, 'AcSDK_get_report')
