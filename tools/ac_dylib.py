import struct, sys

P = r'C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app\Frameworks\libac_sdk.dylib'
d = open(P, 'rb').read()

magic, cpu, sub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from('<IiiIIIII', d, 0)
print('magic %08X cpu %d ftype %d ncmds %d' % (magic, cpu, ftype, ncmds))
off = 32
secs = []
syms = []
strtab = b''
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = d[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, off+24)
        nsects = struct.unpack_from('<I', d, off+64)[0]
        for i in range(nsects):
            s = off + 72 + i * 80
            sectname = d[s:s+16].rstrip(b'\0').decode()
            segn = d[s+16:s+32].rstrip(b'\0').decode()
            addr, size = struct.unpack_from('<QQ', d, s+32)
            foff = struct.unpack_from('<I', d, s+48)[0]
            secs.append((sectname, segn, addr, size, foff))
    elif cmd == 0x2:  # LC_SYMTAB
        symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', d, off+8)
        strtab = d[stroff:stroff+strsize]
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', d, symoff + i * 16)
            e = strtab.find(b'\0', n_strx)
            name = strtab[n_strx:e].decode('utf8', 'replace')
            syms.append((n_value, n_type, n_sect, name))
    off += cmdsize

print('')
print('== secoes ==')
for n, sg, a, sz, f in secs:
    print('  %-18s %-10s addr 0x%X size 0x%-6X file 0x%X' % (n, sg, a, sz, f))

print('')
print('== simbolos (%d) ==' % len(syms))
for v, t, s, n in sorted(syms):
    if not n:
        continue
    if n.startswith('ltmp') or n.startswith('l_'): continue
    print('  0x%08X  %s' % (v, n))

def dump_section(name):
    for n, sg, a, sz, f in secs:
        if n == name:
            blob = d[f:f+sz]
            print('')
            print('== %s ==' % name)
            for s in blob.split(b'\0'):
                if len(s) >= 3:
                    try:
                        print('   ', s.decode('utf8'))
                    except Exception:
                        pass

for s in ('__cstring', '__objc_methname', '__objc_classname', '__const'):
    dump_section(s)
