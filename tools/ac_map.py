import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

P = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Frameworks\libac_sdk.dylib'
d = open(P, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# --- parse load commands: sections + symtab + dysymtab ---
ncmds = struct.unpack_from('<I', d, 16)[0]
off = 32
secs = {}
symtab = None
dysym = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == 0x19:
        nsects = struct.unpack_from('<I', d, off + 64)[0]
        for i in range(nsects):
            s = off + 72 + i * 80
            nm = d[s:s+16].rstrip(b'\0').decode()
            addr, size = struct.unpack_from('<QQ', d, s + 32)
            foff = struct.unpack_from('<I', d, s + 48)[0]
            secs[nm] = (addr, size, foff)
    elif cmd == 0x2:
        symtab = struct.unpack_from('<IIII', d, off + 8)
    elif cmd == 0xB:
        dysym = struct.unpack_from('<IIIIII', d, off + 8)
    off += cmdsize

symoff, nsyms, stroff, strsize = symtab
strtab = d[stroff:stroff + strsize]
syms = []
for i in range(nsyms):
    n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', d, symoff + i * 16)
    e = strtab.find(b'\0', n_strx)
    syms.append(strtab[n_strx:e].decode('utf8', 'replace'))

# undefined symbols, in symbol-table order -> __la_symbol_ptr order
undef = [s for s in syms if s]
la_addr, la_size, ind_addr, ind_size = dysym[2], dysym[3], dysym[4], dysym[5]
nla = la_size // 8
ind = struct.unpack_from('<%dI' % (ind_size // 4), d, ind_addr)
la2sym = {}
for i in range(nla):
    idx = ind[i]
    if idx < len(syms):
        la2sym[la_addr + i * 8] = syms[idx]

# stub -> symbol : stub[i] = adrp x16,#page ; ldr x16,[x16,#off] ; br x16
stub_addr, stub_size, stub_off = secs['__stubs']
stub2sym = {}
for i in range(stub_size // 12):
    a = stub_addr + i * 12
    ins = list(md.disasm(d[stub_off + i * 12: stub_off + i * 12 + 12], a))
    if len(ins) >= 2 and ins[0].mnemonic == 'adrp' and ins[1].mnemonic == 'ldr':
        ops = ins[1].op_str
        try:
            imm = int(ops.split('#')[-1], 0)
        except Exception:
            continue
        page = int(ins[0].op_str.split('#')[-1], 0)
        tgt = page + imm
        if tgt in la2sym:
            stub2sym[a] = la2sym[tgt]

print('stubs mapeados:', len(stub2sym))
for a in sorted(stub2sym):
    print('   stub 0x%X -> %s' % (a, stub2sym[a]))

# --- strings in __cstring / __objc_methname with addresses ---
cstr_addr, cstr_size, cstr_off = secs['__cstring']
strings = {}
blob = d[cstr_off:cstr_off + cstr_size]
p = 0
while p < len(blob):
    e = blob.find(b'\0', p)
    if e < 0: break
    s = blob[p:e]
    if len(s) >= 3:
        strings[cstr_addr + p] = s.decode('utf8', 'replace')
    p = e + 1

print('')
print('== __cstring com enderecos ==')
for a in sorted(strings):
    print('   0x%05X  %s' % (a, strings[a]))

# --- for each check function: which strings / imports it touches ---
CHECKS = [(0x5438, 'bit1'), (0x54E0, 'bit2'), (0x503C, 'bit4'),
          (0x63DC, 'bit8'), (0x6BD0, 'bit10'), (0x6990, 'bit20'), (0x6A68, 'bit40')]
FUNC_ENDS = {0x5438: 0x54E0, 0x54E0: 0x57b8, 0x503C: 0x5164, 0x63DC: 0x6990,
             0x6BD0: 0x6990, 0x6990: 0x6A68, 0x6A68: 0x6BD0}

print('')
for a, lbl in CHECKS:
    end = FUNC_ENDS.get(a, a + 0x400)
    used_s, used_i = [], []
    for i in md.disasm(d[a:end], a):
        if i.mnemonic in ('adr', 'adrp'):
            try:
                t = int(i.op_str.split('#')[-1], 0)
            except Exception:
                continue
            if t in strings:
                used_s.append(strings[t])
            if t + 0 in strings:
                pass
        if i.mnemonic == 'bl':
            try:
                t = int(i.op_str.lstrip('#'), 0)
            except Exception:
                continue
            if t in stub2sym:
                used_i.append(stub2sym[t])
    print('== %s @ 0x%X  (%d bytes)' % (lbl, a, end - a))
    print('   strings:', used_s)
    print('   imports:', sorted(set(used_i)))
    print('')
