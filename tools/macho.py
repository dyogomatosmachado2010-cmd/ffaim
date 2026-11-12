import struct, sys, os

path = sys.argv[1]
data = open(path, 'rb').read()
magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from('<IiiIIIII', data, 0)
print(f"size={len(data)} magic=0x{magic:08X} cputype=0x{cputype:08X} sub=0x{cpusub:X} ftype={ftype} ncmds={ncmds} flags=0x{flags:X}")

cpu_names = {0x0100000C: 'arm64', 0x01000007: 'x86_64'}
print("arch:", cpu_names.get(cputype, hex(cputype)))

off = 32
segs = []
sects = []
symtab = None
encrypt = []
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off+24)
        maxprot, initprot, nsects, sflags = struct.unpack_from('<iiII', data, off+56)
        segs.append((segname, vmaddr, vmsize, fileoff, filesize, initprot, nsects))
        so = off + 72
        for s in range(nsects):
            sname = data[so:so+16].rstrip(b'\0').decode()
            sgname = data[so+16:so+32].rstrip(b'\0').decode()
            addr, size, offset, align, reloff, nreloc, sflags2 = struct.unpack_from('<QQIIIII', data, so+32)
            sects.append((sgname, sname, addr, size, offset, sflags2))
            so += 80
    elif cmd == 0x2:  # LC_SYMTAB
        symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', data, off+8)
        symtab = (symoff, nsyms, stroff, strsize)
    elif cmd == 0x21:  # LC_ENCRYPTION_INFO_64
        cryptoff, cryptsize, cryptid = struct.unpack_from('<III', data, off+8)
        encrypt.append((cryptoff, cryptsize, cryptid))
    elif cmd == 0x2A:  # LC_SOURCE_VERSION
        pass
    off += cmdsize

print("\n--- segments ---")
for s in segs:
    print(f"{s[0]:16s} vmaddr=0x{s[1]:X} vmsize=0x{s[2]:X} fileoff=0x{s[3]:X} filesize=0x{s[4]:X} prot={s[5]} nsects={s[6]}")

print("\n--- sections (interesting) ---")
for sg, sn, addr, size, offset, fl in sects:
    if size > 0 and (sn in ('__text','__stubs','__cstring','__const','__data','__objc_classlist','__unwind_info') or 'il2cpp' in sn.lower()):
        print(f"{sg},{sn:24s} addr=0x{addr:X} size=0x{size:X} off=0x{offset:X}")

print("\n--- encryption ---")
for e in encrypt:
    print(f"cryptoff=0x{e[0]:X} cryptsize=0x{e[1]:X} cryptid={e[2]}")

if symtab:
    symoff, nsyms, stroff, strsize = symtab
    print(f"\n--- symtab: nsyms={nsyms} strsize={strsize} symoff=0x{symoff:X}")
    if nsyms:
        names = []
        for i in range(min(nsyms, 3000000)):
            strx, ntype, nsect, ndesc, nvalue = struct.unpack_from('<IBBHQ', data, symoff + i*16)
            if strx == 0: continue
            end = data.index(b'\0', stroff+strx)
            names.append((data[stroff+strx:end].decode('utf-8','replace'), nvalue, ntype))
        print("total parsed:", len(names))
        il = [n for n in names if 'il2cpp' in n[0].lower()]
        print("il2cpp symbols:", len(il))
        for n in il[:40]:
            print(f"  0x{n[1]:X} {n[0]}")
        # save full symbol list
        with open(os.path.join(os.path.dirname(path), 'symbols.txt'), 'w') as f:
            for n in names:
                f.write(f"0x{n[1]:X}\t{n[0]}\n")
