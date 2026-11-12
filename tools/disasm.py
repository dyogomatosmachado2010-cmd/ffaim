import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

d = open(r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\freefireth', 'rb').read()
BASE = 0x100000000
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def dis(rva, n=48, label=''):
    a = rva
    code = d[a:a+n*4]
    print('--- %s  RVA 0x%X' % (label, rva))
    for i in md.disasm(code, BASE + a):
        print('  0x%08X  %-8s %s' % (i.address - BASE, i.mnemonic, i.op_str))

FUNCS = [
    (0x919E34, 12, 'Player::get_HeadTF'),
    (0x9291B4, 40, 'Player::GetHeadPosition'),
    (0x927208, 24, 'Player::get_AimStartPostion'),
    (0x8FB818, 24, 'Player::GetAimRotation'),
    (0x909D3C, 30, 'Player::SetAimRotation'),
    (0x919E50, 20, 'Player::IsLocalPlayer'),
    (0x8EA308, 24, 'Player::IsLocalPlayer#2'),
    (0x923DFC, 30, 'Player::IsVisible'),
    (0x92C118, 12, 'Player::get_EAimAssit'),
    (0x8E7898, 12, 'NetworkAIPawn::get_HeadTF'),
]
for rva, n, lbl in FUNCS:
    dis(rva, n, lbl)
    print()
