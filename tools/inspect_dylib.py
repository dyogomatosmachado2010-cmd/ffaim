#!/usr/bin/env python3
"""Dump Mach-O load commands for a dylib/binary. Diagnostic only."""
import struct, sys

NAMES = {
    0x1: "LC_SEGMENT", 0x19: "LC_SEGMENT_64", 0x2: "LC_SYMTAB",
    0xb: "LC_DYSYMTAB", 0xc: "LC_LOAD_DYLIB", 0xd: "LC_ID_DYLIB",
    0xe: "LC_LOAD_DYLINKER", 0x1b: "LC_UUID", 0x32: "LC_BUILD_VERSION",
    0x1d: "LC_CODE_SIGNATURE", 0x26: "LC_FUNCTION_STARTS",
    0x29: "LC_DATA_IN_CODE", 0x22: "LC_DYLD_INFO", 0x80000022: "LC_DYLD_INFO_ONLY",
    0x2a: "LC_SOURCE_VERSION", 0x21: "LC_ENCRYPTION_INFO",
    0x25: "LC_VERSION_MIN_IPHONEOS", 0x24: "LC_VERSION_MIN_MACOSX",
    0x80000028: "LC_MAIN", 0x1f: "LC_SEGMENT_SPLIT_INFO",
    0x2b: "LC_DYLIB_CODE_SIGN_DRS", 0x80000034: "LC_DYLD_CHAINED_FIXUPS",
    0x80000033: "LC_DYLD_EXPORTS_TRIE", 0x80000035: "LC_ATOM_INFO",
    0x8000001c: "LC_RPATH", 0x1e: "LC_LINKER_OPTION", 0x23: "LC_LINKER_OPTIMIZATION_HINT",
    0x2c: "LC_ENCRYPTION_INFO_64", 0x2f: "LC_VERSION_MIN_TVOS",
    0x31: "LC_VERSION_MIN_WATCHOS", 0x33: "LC_NOTE", 0x34: "LC_BUILD_VERSION?",
}


def cstr(b):
    return b.split(b"\0")[0].decode("utf8", "replace")


def dump(path):
    d = open(path, "rb").read()
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from("<IiiIIII", d, 0)
    is64 = magic == 0xFEEDFACF
    print(f"{path}")
    print(f"  magic=0x{magic:08X} 64={is64} cputype=0x{cputype:X} sub=0x{cpusub:X} "
          f"filetype={filetype} ncmds={ncmds} sizeofcmds=0x{sizeofcmds:X} flags=0x{flags:08X}")
    off = 32
    segs = []
    has_cs = False
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", d, off)
        nm = NAMES.get(cmd, f"0x{cmd:X}")
        extra = ""
        if cmd in (0xc, 0xd, 0x8000001c, 0xe):
            noff = struct.unpack_from("<I", d, off + 8)[0]
            extra = cstr(d[off + noff: off + cs])
        elif cmd == 0x19:
            seg = cstr(d[off + 8: off + 24])
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24)
            nsects = struct.unpack_from("<I", d, off + 64)[0]
            segs.append((seg, vmaddr, vmsize, fileoff, filesize, nsects))
            extra = f"{seg} vm=0x{vmaddr:X} vsz=0x{vmsize:X} fo=0x{fileoff:X} fsz=0x{filesize:X} nsects={nsects}"
        elif cmd == 0x1d:
            doff, dsz = struct.unpack_from("<II", d, off + 8)
            extra = f"dataoff=0x{doff:X} datasize={dsz}"
            has_cs = True
        elif cmd in (0x25, 0x24, 0x2f, 0x31):
            extra = str(struct.unpack_from("<II", d, off + 8))
        elif cmd == 0x32:
            plat, minos, sdk, ntools = struct.unpack_from("<IIII", d, off + 8)
            extra = f"platform={plat} minos={minos:#x} sdk={sdk:#x} tools={ntools}"
        elif cmd == 0x22 or cmd == 0x80000022:
            extra = str(struct.unpack_from("<IIIIIIIIII", d, off + 8))
        print(f"  {nm:<24} cs={cs:<5} {extra}")
        off += cs
    print(f"  --> LC_CODE_SIGNATURE: {'YES' if has_cs else 'NO'}")

    # sections of interest
    off = 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            nsects = struct.unpack_from("<I", d, off + 64)[0]
            for i in range(nsects):
                s = off + 72 + i * 80
                sect = cstr(d[s: s + 16])
                sg = cstr(d[s + 16: s + 32])
                addr, size, offset = struct.unpack_from("<QQI", d, s + 32)
                print(f"    sect {sg},{sect} addr=0x{addr:X} size=0x{size:X} off=0x{offset:X}")
        off += cs


if __name__ == "__main__":
    for p in sys.argv[1:]:
        dump(p)
