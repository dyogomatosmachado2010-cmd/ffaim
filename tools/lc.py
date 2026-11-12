import struct, sys
d = open(sys.argv[1], 'rb').read()
ncmds = struct.unpack_from('<I', d, 16)[0]
off = 32
names = {0x1:'LC_SEGMENT',0x2:'LC_SYMTAB',0x3:'LC_SYMSEG',0x4:'LC_THREAD',0x5:'LC_UNIXTHREAD',0x6:'LC_LOADFVMLIB',0x7:'LC_IDFVMLIB',0x8:'LC_IDENT',0x9:'LC_FVMFILE',0xA:'LC_PREPAGE',0xB:'LC_DYSYMTAB',0xC:'LC_LOAD_DYLIB',0xD:'LC_ID_DYLIB',0xE:'LC_LOAD_DYLINKER',0xF:'LC_ID_DYLINKER',0x10:'LC_PREBOUND_DYLIB',0x11:'LC_ROUTINES',0x12:'LC_SUB_FRAMEWORK',0x13:'LC_SUB_UMBRELLA',0x14:'LC_SUB_CLIENT',0x15:'LC_SUB_LIBRARY',0x16:'LC_TWOLEVEL_HINTS',0x17:'LC_PREBIND_CKSUM',0x18:'LC_LOAD_WEAK_DYLIB',0x19:'LC_SEGMENT_64',0x1A:'LC_ROUTINES_64',0x1B:'LC_UUID',0x1C:'LC_RPATH',0x1D:'LC_CODE_SIGNATURE',0x1E:'LC_SEGMENT_SPLIT_INFO',0x1F:'LC_REEXPORT_DYLIB',0x20:'LC_LAZY_LOAD_DYLIB',0x21:'LC_ENCRYPTION_INFO',0x22:'LC_DYLD_INFO',0x23:'LC_DYLD_INFO_ONLY',0x24:'LC_LOAD_UPWARD_DYLIB',0x25:'LC_VERSION_MIN_MACOSX',0x26:'LC_VERSION_MIN_IPHONEOS',0x27:'LC_FUNCTION_STARTS',0x28:'LC_DYLD_ENVIRONMENT',0x29:'LC_MAIN',0x2A:'LC_DATA_IN_CODE',0x2B:'LC_SOURCE_VERSION',0x2C:'LC_DYLIB_CODE_SIGN_DRS',0x2D:'LC_ENCRYPTION_INFO_64',0x2E:'LC_LINKER_OPTION',0x2F:'LC_LINKER_OPTIMIZATION_HINT',0x30:'LC_VERSION_MIN_TVOS',0x31:'LC_VERSION_MIN_WATCHOS',0x32:'LC_NOTE',0x33:'LC_BUILD_VERSION',0x34:'LC_DYLD_EXPORTS_TRIE',0x35:'LC_DYLD_CHAINED_FIXUPS'}
for i in range(ncmds):
    cmd, size = struct.unpack_from('<II', d, off)
    print(f'{i:2d} 0x{cmd:X} {names.get(cmd & 0x7FFFFFFF, "?"):24s} size={size}')
    if cmd == 0x80000034:
        doff, dsize = struct.unpack_from('<II', d, off+8)
        print(f'     chained fixups at 0x{doff:X} size 0x{dsize:X}')
        hdr = struct.unpack_from('<IIIIII', d, doff)
        print('     version=%d starts_offset=0x%X imports_offset=0x%X symbols_offset=0x%X imports_count=%d imports_format=%d' % hdr)
    if cmd == 0x80000033:
        doff, dsize = struct.unpack_from('<II', d, off+8)
        print(f'     exports trie at 0x{doff:X} size 0x{dsize:X}')
    if cmd == 0x80000022:
        doff, dsize = struct.unpack_from('<II', d, off+8)
        print(f'     dyld info at 0x{doff:X} size 0x{dsize:X}')
    off += size
