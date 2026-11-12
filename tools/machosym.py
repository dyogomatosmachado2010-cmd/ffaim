import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

# lista as referencias de uma dylib: funcao -> string de __cstring / simbolo de stub.
# serve pra saber o que o AC olha (dyld, sysctl, nomes de jailbreak) e onde.

class MachO:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        d = self.data
        magic, cputype, cpusub, ft, ncmds, sizeofcmds, flags, res = struct.unpack_from('<IiiIIIII', d, 0)
        assert magic == 0xFEEDFACF, hex(magic)
        self.ncmds = ncmds
        self.sections = {}      # nome -> (addr, size, off, flags, reserved1, sectname)
        self.segs = []
        self.symtab = None
        self.dysymtab = None
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', d, off)
            if cmd == 0x19:      # LC_SEGMENT_64
                segname = d[off+8:off+24].rstrip(b'\0').decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, off+24)
                nsects = struct.unpack_from('<I', d, off+64)[0]
                self.segs.append((segname, vmaddr, vmsize, fileoff, filesize))
                so = off + 72
                for _ in range(nsects):
                    sect = d[so:so+16].rstrip(b'\0').decode()
                    sg = d[so+16:so+32].rstrip(b'\0').decode()
                    addr, sz = struct.unpack_from('<QQ', d, so+32)
                    foff = struct.unpack_from('<I', d, so+48)[0]
                    flags = struct.unpack_from('<I', d, so+64)[0]
                    r1 = struct.unpack_from('<I', d, so+68)[0]
                    self.sections[sect] = (addr, sz, foff, flags, r1, sg)
                    so += 80
            elif cmd == 0x2:     # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', d, off+8)
                self.symtab = (symoff, nsyms, stroff, strsize)
            elif cmd == 0xB:     # LC_DYSYMTAB
                (self.dysymtab,) = struct.unpack_from('<I', d, off+8)  # indireto
                vals = struct.unpack_from('<18I', d, off+8)
                self.dysymtab = vals
            off += size

    def cstr(self, addr):
        for name in ('__cstring', '__objc_methname'):
            if name in self.sections:
                a, sz, foff, *_ = self.sections[name]
                if a <= addr < a + sz:
                    p = foff + (addr - a)
                    e = self.data.index(b'\0', p)
                    return self.data[p:e].decode('latin-1')
        return None

    def symbols(self):
        out = []
        if not self.symtab:
            return out
        symoff, nsyms, stroff, strsize = self.symtab
        for i in range(nsyms):
            so = symoff + i * 16
            strx, ntype, sect, desc, value = struct.unpack_from('<IBBHQ', self.data, so)
            p = stroff + strx
            e = self.data.index(b'\0', p)
            out.append((self.data[p:e].decode('latin-1'), value, ntype))
        return out

    def stubs(self):
        # __stubs (12 bytes) na ordem dos ponteiros indiretos
        if '__stubs' not in self.sections:
            return {}
        a, sz, foff, flags, r1, _ = self.sections['__stubs']
        syms = self.symbols()
        ind = []
        for nm in ('__la_symbol_ptr', '__got', '__auth_got'):
            if nm in self.sections:
                _, _, _, _, res1, _ = self.sections[nm]
                ind.append(res1)
        if not ind:
            return {}
        base = ind[0]
        dt = self.dysymtab
        indoff = dt[12] if dt else 0
        out = {}
        n = sz // 12
        for i in range(n):
            idx = struct.unpack_from('<I', self.data, indoff + (base + i) * 4)[0]
            if idx == 0x80000000 or idx >= len(syms):
                name = '?'
            else:
                name = syms[idx][0]
            out[a + i * 12] = name
        return out


def main(path):
    m = MachO(path)
    print('secoes:', ', '.join(sorted(m.sections.keys())))
    stubs = m.stubs()
    print('stubs resolvidos:', len(stubs))

    if '__text' not in m.sections:
        print('sem __text'); return
    ta, tsz, tfoff, *_ = m.sections['__text']
    code = m.data[tfoff:tfoff + tsz]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False

    reg = {}
    fn = ta
    for ins in md.disasm(code, ta):
        mn, ops = ins.mnemonic, ins.op_str
        if mn == 'stp' and 'x29, x30' in ops and '[sp' in ops:
            fn = ins.address
        if mn == 'adrp':
            try:
                r, imm = ops.split(', #')
                reg[r.strip()] = int(imm, 0) & ~0xFFF
            except ValueError:
                pass
        elif mn in ('add', 'ldr') and ops.count(',') >= 2:
            parts = [p.strip() for p in ops.split(',')]
            if parts[1] in reg:
                try:
                    imm = int(parts[2].lstrip('#').strip(']'), 0)
                except ValueError:
                    continue
                tgt = reg[parts[1]] + imm
                s = m.cstr(tgt)
                if s:
                    print('  fn 0x%05X  %-28s 0x%05X  "%s"' % (fn, mn, tgt, s[:80]))
        elif mn == 'bl':
            try:
                tgt = int(ops.lstrip('#'), 0)
            except ValueError:
                continue
            if tgt in stubs:
                print('  fn 0x%05X  bl                        %s' % (fn, stubs[tgt]))
        elif mn == 'b' or mn == 'ret':
            reg.clear()


if __name__ == '__main__':
    main(sys.argv[1])
