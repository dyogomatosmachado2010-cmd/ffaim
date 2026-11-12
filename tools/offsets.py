"""FreeFire iOS - focused offsets extract (fields + method RVAs) from il2cpp metadata.

usage: python tools/offsets.py <global-metadata.dat> <binary> <out.txt>
"""
import struct, sys, os

META, BIN = sys.argv[1], sys.argv[2]
OUT = sys.argv[3] if len(sys.argv) > 3 else 'offsets_ff.txt'

m = open(META, 'rb').read()
d = open(BIN, 'rb').read()
BASE = 0x100000000

S, SC = 0x74C44, 0x13F1F8
TD_O, TD_N, TCNT = 0x838CFC, 104, 9329
MD_O, MD_N, MC = 0x1FA350, 56, 70537
FD_O, FD_N, FCNT = 0x6F283C, 16, 51480
PA_O, PA_N, PCNT = 0x60F91C, 16, 58098
NT_O = 0x7C0218
IF_O = 0x7C239C
IMG_O, IMG_N, ICNT = 0x928C7C, 24, 18

TYPES, TYPES_N = 0x103354A98, 51153
FIELD_OFFSETS = 0x1035E86D8
TYPE_SIZES = 0x1035FAA60
METHOD_PTRS = 0x10326CD48
METHOD_PTR_COUNT = 67511

def i32m(o): return struct.unpack_from('<i', m, o)[0]
def u32m(o): return struct.unpack_from('<I', m, o)[0]
def u16m(o): return struct.unpack_from('<H', m, o)[0]
def u64d(a): return struct.unpack_from('<Q', d, a - BASE)[0]
def u32d(a): return struct.unpack_from('<I', d, a - BASE)[0]

def cstr(i):
    if not (0 <= i < SC): return ''
    e = m.index(b'\0', S + i)
    return m[S+i:e].decode('utf8', 'replace')

def td(t, o): return TD_O + t*TD_N + o
def md(i, o): return MD_O + i*MD_N + o
def fd(f, o): return FD_O + f*FD_N + o
def pa(p, o): return PA_O + p*PA_N + o

types = []
addr_to_idx = {}
for i in range(TYPES_N):
    p = u64d(TYPES + i*8)
    types.append((u64d(p), (u32d(p + 8) >> 16) & 0xFF, u32d(p + 8) & 0xFFFF))
    addr_to_idx.setdefault(p, i)

PRIM = {1:'void',2:'bool',3:'char',4:'sbyte',5:'byte',6:'short',7:'ushort',8:'int',
        9:'uint',10:'long',11:'ulong',12:'float',13:'double',14:'string',22:'TypedReference',
        24:'IntPtr',25:'UIntPtr',28:'object'}

GP_O = 0x7BB9BC
def gp_name(idx):
    o = GP_O + idx*16
    if idx < 0 or o + 4 > len(m): return 'T'
    return cstr(i32m(o)) or 'T'

def tname_def(t):
    ns = cstr(i32m(td(t, 4))); nm = cstr(i32m(td(t, 0)))
    return (ns + '.' + nm) if ns else nm

def resolve(ti, depth=0):
    if ti < 0 or ti >= TYPES_N or depth > 6: return '?'
    data, t, attrs = types[ti]
    if t in PRIM: return PRIM[t]
    if t in (17, 18): return tname_def(data & 0xFFFFFFFF)
    if t == 15:
        j = addr_to_idx.get(data); return (resolve(j, depth+1) if j is not None else 'void') + '*'
    if t == 16:
        j = addr_to_idx.get(data); return 'ref ' + (resolve(j, depth+1) if j is not None else '?')
    if t == 29:
        j = addr_to_idx.get(data); return (resolve(j, depth+1) if j is not None else '?') + '[]'
    if t == 20:
        j = addr_to_idx.get(u64d(data))
        et = resolve(j, depth+1) if j is not None else '?'
        rank = struct.unpack_from('<B', d, data - BASE + 8)[0] if data else 1
        return et + '[' + ','*(max(rank,1)-1) + ']'
    if t in (19, 30): return gp_name(data & 0xFFFFFFFF)
    if t == 21:
        gclass = data
        tdef = u32d(gclass) & 0xFFFFFFFF
        cls_inst = u64d(gclass + 8)
        base = tname_def(tdef)
        if cls_inst:
            argc = u32d(cls_inst); argv = u64d(cls_inst + 8)
            args = []
            for k in range(min(argc, 16)):
                j = addr_to_idx.get(u64d(argv + k*8))
                args.append(resolve(j, depth+1) if j is not None else '?')
            return base + '<' + ','.join(args) + '>'
        return base
    if t == 27: return 'fnptr'
    return 'type%d' % t

def type_flags(t): return u32m(td(t, 0x2C))
def field_start(t): return i32m(td(t, 0x30))
def field_count(t): return u16m(td(t, 0x54))
def method_start(t): return i32m(td(t, 0x34))
def method_count(t): return u16m(td(t, 0x50))
def nested_start(t): return i32m(td(t, 0x40))
def nested_count(t): return u16m(td(t, 0x58))
def iface_start(t): return i32m(td(t, 0x44))
def iface_count(t): return u16m(td(t, 0x5C))
def parent_of(t):
    p = i32m(td(t, 0x18))
    if not (0 <= p < TYPES_N): return -1
    data, ty, _ = types[p]
    if ty in (17, 18) and 0 <= (data & 0xFFFFFFFF) < TCNT: return data & 0xFFFFFFFF
    return -1
def inst_size(t):
    p = u64d(TYPE_SIZES + t*8)
    return u32d(p) if p else 0
def static_size(t):
    p = u64d(TYPE_SIZES + t*8)
    return struct.unpack_from('<i', d, p - BASE + 8)[0] if p else 0

def meth_name(i): return cstr(i32m(md(i, 0)))
def meth_ret(i): return i32m(md(i, 8))
def meth_param_start(i): return i32m(md(i, 0x0C))
def meth_flags(i): return u16m(md(i, 0x30))
def meth_pcount(i): return u16m(md(i, 0x36))
def meth_ptr_idx(i): return i32m(md(i, 0x18))
def meth_rva(i):
    j = meth_ptr_idx(i)
    if not (0 <= j < METHOD_PTR_COUNT): return None
    p = u64d(METHOD_PTRS + j*8)
    return (p - BASE) if p else None

outer = {}
for t in range(TCNT):
    ns = nested_start(t)
    if ns < 0: continue
    for k in range(nested_count(t)):
        c = i32m(NT_O + (ns + k)*4)
        if 0 <= c < TCNT: outer[c] = t

def full_name(t, depth=0):
    nm = cstr(i32m(td(t, 0)))
    if t in outer and depth < 8: return full_name(outer[t], depth+1) + '/' + nm
    ns = cstr(i32m(td(t, 4)))
    return (ns + '.' + nm) if ns else nm

def type_sig(t):
    p = parent_of(t)
    return full_name(t) + (' : ' + tname_def(p) if p >= 0 else '')

img_ranges = []
tot = 0
for i in range(ICNT):
    o = IMG_O + i*IMG_N
    nm, ts, tc = cstr(i32m(o)), i32m(o+8), i32m(o+12)
    mc = sum(method_count(t) for t in range(ts, ts+tc))
    img_ranges.append((nm, ts, ts+tc)); tot += mc
def image_of_type(t):
    for nm, a, b in img_ranges:
        if a <= t < b: return nm
    return '?'

GAME_IMAGES = ('Assembly-CSharp.dll', 'Assembly-CSharp-firstpass.dll',
               'UnityEngine.dll', 'UnityEngine.UI.dll', 'UnityEngine.Networking.dll')

KEY = [
    4670,  # COW.GamePlay.Player
    4694,  # COW.GamePlay.PlayerAttributes
    4700,  # COW.GamePlay.PlayerNetwork
    4660,  # COW.GamePlay.NetworkAIPawn
    4075,  # COW.GameFacade
    4130,  # COW.GamePlay.AvatarManager
    4137,  # COW.GamePlay.AttackableEntity
    4144,  # COW.GamePlay.CameraControllerBase
    4150,  # COW.GamePlay.FollowCamera
    4152,  # COW.GamePlay.FreeCamera
    4475,  # COW.GamePlay.BoneNameRef
    4548,  # COW.GamePlay.HitDetectColliderHelper
    4358,  # COW.GamePlay.LevelDamageZone
]

def emit_type(out, t, full):
    isz = inst_size(t)
    out.write('\n[%s]  TypeDefIndex %d  InstanceSize 0x%X  StaticSize 0x%X  image %s\n'
              % (type_sig(t), t, isz, static_size(t), image_of_type(t)))
    fs, fc = field_start(t), field_count(t)
    if fc > 0 and fs >= 0:
        arr = u64d(FIELD_OFFSETS + t*8)
        offs = [struct.unpack_from('<i', d, arr - BASE + k*4)[0] for k in range(fc)] if arr else [0]*fc
        seen = set()
        for k in range(fc):
            f = fs + k
            if f >= FCNT: break
            fname = cstr(i32m(fd(f, 0)))
            ftype = resolve(i32m(fd(f, 4)))
            off = offs[k]
            if isz <= 0x10 or off < 0x10 or off >= max(isz, 0x10) or off in seen:
                # static block (this build reuses offsets across the two blocks)
                out.write('  static %-26s %-46s = 0x%X\n' % (fname, ftype, off))
            else:
                seen.add(off)
                out.write('  0x%03X  %-26s %-46s\n' % (off, fname, ftype))
    ms, mc = method_start(t), method_count(t)
    if full and mc > 0 and ms >= 0:
        for k in range(mc):
            i = ms + k
            if i >= MC: break
            rva = meth_rva(i)
            if rva is None: continue
            pc = meth_pcount(i); ps = meth_param_start(i)
            plist = []
            for q in range(pc):
                pp = ps + q
                if pp < 0 or pp >= PCNT: break
                plist.append('%s %s' % (resolve(i32m(pa(pp, 12))), cstr(i32m(pa(pp, 0)))))
            out.write('  %-52s RVA 0x%X\n' % ('%s(%s)' % (meth_name(i), ', '.join(plist)), rva))

out = open(OUT, 'w', encoding='utf-8', errors='replace')
out.write('# FreeFire iOS (freefireth.app) - il2cpp offsets\n')
out.write('# arm64 Mach-O, image base 0x100000000 (file offset == RVA)\n')
out.write('# instance field offsets are absolute, 0x10 = first field after the object header\n')
out.write('# method address = 0x100000000 + RVA\n')
out.write('# format: Class -> instance field 0xOFF, static field = 0xOFF, method RVA 0x...\n')

out.write('\n\n########## KEY CLASSES ##########\n')
for t in KEY:
    if 0 <= t < TCNT: emit_type(out, t, True)

out.write('\n\n########## FULL INDEX: Assembly-CSharp (+firstpass) ##########\n')
for t in range(TCNT):
    if image_of_type(t) not in GAME_IMAGES: continue
    emit_type(out, t, True)

out.close()
print('wrote %s  %.2f MB' % (OUT, os.path.getsize(OUT)/1048576))
