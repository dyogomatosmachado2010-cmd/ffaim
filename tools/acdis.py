import sys
from capstone import *

path = sys.argv[1]
rva = int(sys.argv[2], 16)
n = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x180

data = open(path, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

prev_epilogue = False
for ins in md.disasm(data[rva:rva + n], rva):
    print('  0x%06X  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
    if ins.mnemonic == 'ldp' and 'x29, x30' in ins.op_str:
        prev_epilogue = True
        continue
    if ins.mnemonic == 'ret' and prev_epilogue:
        break
    prev_epilogue = False
