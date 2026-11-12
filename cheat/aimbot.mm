// ffaim - aimbot interno para FreeFire iOS (com.privateproject.ff2018.v128)
// alvo: arm64 / arm64e, il2cpp sem simbolos -> offsets fixos (ff_offsets.h)
// build: Theos, ver Makefile. install: tweak injetado no processo freefireth.
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <substrate.h>
#import <math.h>
#import <sys/stat.h>
#import <stdlib.h>
#import <stdio.h>
#import <string.h>
#include <string>

#include "ff_offsets.h"

// ---------------------------------------------------------------- math

struct Vec3 { float x, y, z; };
struct Quat { float x, y, z, w; };

static inline Vec3 vadd(Vec3 a, Vec3 b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
static inline Vec3 vsub(Vec3 a, Vec3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
static inline Vec3 vmul(Vec3 a, float s) { return {a.x * s, a.y * s, a.z * s}; }
static inline float vdot(Vec3 a, Vec3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
static inline float vlen(Vec3 a) { return sqrtf(vdot(a, a)); }
static inline Vec3 vnorm(Vec3 a) {
    float l = vlen(a);
    if (l < 1e-6f) return {0, 0, 1};
    return vmul(a, 1.0f / l);
}
static inline Vec3 vcross(Vec3 a, Vec3 b) {
    return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
}

// forward = q * (0,0,1)
static inline Vec3 forwardFromQuat(Quat q) {
    return {2.0f * (q.x * q.z + q.w * q.y),
            2.0f * (q.y * q.z - q.w * q.x),
            1.0f - 2.0f * (q.x * q.x + q.y * q.y)};
}

// Unity LookRotation(forward, up) - matriz com colunas right/up/forward
static Quat lookRotation(Vec3 f, Vec3 up) {
    f = vnorm(f);
    Vec3 r = vcross(up, f);
    if (vlen(r) < 1e-5f) r = vcross({0, 0, 1}, f);
    r = vnorm(r);
    Vec3 u = vcross(f, r);

    float m00 = r.x, m01 = u.x, m02 = f.x;
    float m10 = r.y, m11 = u.y, m12 = f.y;
    float m20 = r.z, m21 = u.z, m22 = f.z;

    Quat q{0, 0, 0, 1};
    float tr = m00 + m11 + m22;
    if (tr > 0.0f) {
        float s = sqrtf(tr + 1.0f) * 2.0f;
        q.w = 0.25f * s;
        q.x = (m21 - m12) / s;
        q.y = (m02 - m20) / s;
        q.z = (m10 - m01) / s;
    } else if (m00 > m11 && m00 > m22) {
        float s = sqrtf(1.0f + m00 - m11 - m22) * 2.0f;
        q.w = (m21 - m12) / s;
        q.x = 0.25f * s;
        q.y = (m01 + m10) / s;
        q.z = (m02 + m20) / s;
    } else if (m11 > m22) {
        float s = sqrtf(1.0f + m11 - m00 - m22) * 2.0f;
        q.w = (m02 - m20) / s;
        q.x = (m01 + m10) / s;
        q.y = 0.25f * s;
        q.z = (m12 + m21) / s;
    } else {
        float s = sqrtf(1.0f + m22 - m00 - m11) * 2.0f;
        q.w = (m10 - m01) / s;
        q.x = (m02 + m20) / s;
        q.y = (m12 + m21) / s;
        q.z = 0.25f * s;
    }
    float n = sqrtf(q.x * q.x + q.y * q.y + q.z * q.z + q.w * q.w);
    if (n > 1e-6f) { q.x /= n; q.y /= n; q.z /= n; q.w /= n; }
    return q;
}

static Quat nlerp(Quat a, Quat b, float t) {
    float d = a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w;
    if (d < 0.0f) { b.x = -b.x; b.y = -b.y; b.z = -b.z; b.w = -b.w; }
    Quat r{a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t,
           a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t};
    float n = sqrtf(r.x * r.x + r.y * r.y + r.z * r.z + r.w * r.w);
    if (n > 1e-6f) { r.x /= n; r.y /= n; r.z /= n; r.w /= n; }
    return r;
}

// ---------------------------------------------------------------- config

enum Bone { BONE_HEAD = 0, BONE_NECK, BONE_CHEST, BONE_HIP };

struct Config {
    bool enabled = true;
    float fov = 25.0f;       // graus, cone a partir da mira atual
    float maxDist = 250.0f;  // metros
    float smooth = 0.35f;    // 0 = snap, 1 = nao mexe
    int bone = BONE_HEAD;
    bool teamCheck = true;
    bool visCheck = false;
    int neckHops = 1;        // HeadTF -> parent x N = neck
    bool invertPitch = false;
    bool debug = false;
};

static Config g_cfg;
static time_t g_cfgMtime = 0;

static const char *kCfgPaths[] = {
    "/var/jb/var/mobile/ffaim.cfg",
    "/var/mobile/ffaim.cfg",
};

static const char *cfgPath() {
    struct stat st;
    for (const char *p : kCfgPaths)
        if (stat(p, &st) == 0) return p;
    return nullptr;
}

static void loadConfig() {
    const char *path = cfgPath();
    if (!path) return;
    struct stat st;
    if (stat(path, &st) != 0) return;
    if (st.st_mtime == g_cfgMtime) return;
    g_cfgMtime = st.st_mtime;

    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char key[64] = {0};
        char val[128] = {0};
        if (sscanf(line, "%63[^=#]=%127s", key, val) != 2) continue;
        std::string k(key), v(val);
        while (!k.empty() && (k.back() == ' ' || k.back() == '\t')) k.pop_back();
        if (k == "enabled") g_cfg.enabled = atoi(val) != 0;
        else if (k == "fov") g_cfg.fov = (float)atof(val);
        else if (k == "maxdist") g_cfg.maxDist = (float)atof(val);
        else if (k == "smooth") g_cfg.smooth = (float)atof(val);
        else if (k == "bone") {
            if (v == "head") g_cfg.bone = BONE_HEAD;
            else if (v == "neck") g_cfg.bone = BONE_NECK;
            else if (v == "chest") g_cfg.bone = BONE_CHEST;
            else if (v == "hip") g_cfg.bone = BONE_HIP;
        }
        else if (k == "teamcheck") g_cfg.teamCheck = atoi(val) != 0;
        else if (k == "vischeck") g_cfg.visCheck = atoi(val) != 0;
        else if (k == "neckhops") g_cfg.neckHops = atoi(val);
        else if (k == "invertpitch") g_cfg.invertPitch = atoi(val) != 0;
        else if (k == "debug") g_cfg.debug = atoi(val) != 0;
    }
    fclose(f);
    if (g_cfg.smooth < 0.0f) g_cfg.smooth = 0.0f;
    if (g_cfg.smooth > 1.0f) g_cfg.smooth = 1.0f;
}

// ---------------------------------------------------------------- module

static uintptr_t g_base = 0;

static void resolveBase() {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "/freefireth") || strstr(name, "freefireth.app")) {
            // __TEXT vmaddr == 0x100000000, header carregado == base do slide
            g_base = (uintptr_t)_dyld_get_image_header(i);
            return;
        }
    }
}

template <typename T>
static inline T at(uintptr_t rva) { return (T)(g_base + rva); }

static inline void *rd_ptr(void *o, uint32_t off) {
    if (!o) return nullptr;
    return *(void **)((char *)o + off);
}
static inline bool rd_bool(void *o, uint32_t off) {
    if (!o) return false;
    return *(bool *)((char *)o + off);
}
static inline int rd_i32(void *o, uint32_t off) {
    if (!o) return 0;
    return *(int32_t *)((char *)o + off);
}

// ---------------------------------------------------------------- registry

struct Entry { void *player; uint64_t tick; };

static const int kMaxPlayers = 160;
static Entry g_players[kMaxPlayers];
static uint64_t g_tick = 0;

static void regAdd(void *p) {
    for (int i = 0; i < kMaxPlayers; i++) {
        if (g_players[i].player == p) { g_players[i].tick = g_tick; return; }
    }
    for (int i = 0; i < kMaxPlayers; i++) {
        if (!g_players[i].player || g_tick - g_players[i].tick > 900) {
            g_players[i].player = p;
            g_players[i].tick = g_tick;
            return;
        }
    }
}

// ---------------------------------------------------------------- game calls

typedef bool (*fn_isLocal)(void *);
typedef bool (*fn_isVisible)(void *);
typedef Vec3 (*fn_vec3_this)(void *);
typedef void *(*fn_ptr_this)(void *);

static fn_isLocal g_isLocal = nullptr;
static fn_isVisible g_isVisible = nullptr;
static fn_vec3_this g_getHeadPos = nullptr;
static fn_vec3_this g_getHipPos = nullptr;
static fn_vec3_this g_getAimStart = nullptr;
static fn_vec3_this g_transformPos = nullptr;
static fn_ptr_this g_transformParent = nullptr;

// ---------------------------------------------------------------- bone

static Vec3 bonePosition(void *p) {
    switch (g_cfg.bone) {
    case BONE_NECK: {
        void *tf = rd_ptr(p, OFF_Player_HeadTF);
        for (int i = 0; i < g_cfg.neckHops && tf; i++) tf = g_transformParent(tf);
        if (tf) return g_transformPos(tf);
        Vec3 h = g_getHeadPos(p);
        return {h.x, h.y - 0.12f, h.z};
    }
    case BONE_CHEST: {
        Vec3 h = g_getHeadPos(p), hip = g_getHipPos(p);
        return vadd(hip, vmul(vsub(h, hip), 0.55f));
    }
    case BONE_HIP:
        return g_getHipPos(p);
    case BONE_HEAD:
    default:
        return g_getHeadPos(p);
    }
}

// ---------------------------------------------------------------- aimbot

static void aimbot(void *self) {
    if (!g_cfg.enabled) return;

    void *headTF = rd_ptr(self, OFF_Player_HeadTF);
    if (!headTF) return;

    Vec3 origin = g_getAimStart(self);
    if (!isfinite(origin.x) || !isfinite(origin.y) || !isfinite(origin.z))
        origin = g_getHeadPos(self);

    Quat cur = *(Quat *)((char *)self + OFF_Player_AimRotation);
    Vec3 fwd = forwardFromQuat(cur);
    int localTeam = rd_i32(self, OFF_Player_TeamIndex);

    float cosFov = cosf(g_cfg.fov * 3.14159265f / 180.0f);
    void *best = nullptr;
    Vec3 bestPos{0, 0, 0};
    float bestDot = cosFov;
    float bestDist = 1e9f;

    for (int i = 0; i < kMaxPlayers; i++) {
        void *p = g_players[i].player;
        if (!p || p == self) continue;
        if (g_tick - g_players[i].tick > 300) continue;
        // objeto il2cpp sempre tem o klass em +0x0 e alinhamento 8
        if (((uintptr_t)p & 7) || !*(void **)p) continue;
        if (rd_bool(p, OFF_Entity_IsDead)) continue;
        if (g_cfg.teamCheck && rd_i32(p, OFF_Player_TeamIndex) == localTeam) continue;
        if (g_cfg.visCheck && g_isVisible && !g_isVisible(p)) continue;

        Vec3 pos = bonePosition(p);
        if (!isfinite(pos.x) || !isfinite(pos.y) || !isfinite(pos.z)) continue;

        Vec3 d = vsub(pos, origin);
        float dist = vlen(d);
        if (dist < 0.5f || dist > g_cfg.maxDist) continue;

        float dot = vdot(fwd, vmul(d, 1.0f / dist));
        if (dot <= bestDot) continue;
        if (dot == bestDot && dist >= bestDist) continue;

        best = p;
        bestPos = pos;
        bestDot = dot;
        bestDist = dist;
    }

    if (!best) return;

    Vec3 dir = vnorm(vsub(bestPos, origin));
    if (g_cfg.invertPitch) dir.y = -dir.y;

    Quat want = lookRotation(dir, {0, 1, 0});
    if (g_cfg.smooth > 0.001f && g_cfg.smooth < 0.999f)
        want = nlerp(cur, want, 1.0f - g_cfg.smooth);

    *(Quat *)((char *)self + OFF_Player_AimRotation) = want;

    if (g_cfg.debug) {
        NSLog(@"[ffaim] target=%p dist=%.1f dot=%.3f bone=%d", best, bestDist, bestDot, g_cfg.bone);
    }
}

// ---------------------------------------------------------------- hook

static void (*orig_LateUpdate)(void *) = nullptr;

static void hook_LateUpdate(void *self) {
    orig_LateUpdate(self);

    if (!g_base || !self) return;

    g_tick++;
    if ((g_tick & 0x3F) == 0) loadConfig();

    regAdd(self);

    if (g_isLocal(self)) aimbot(self);
}

// ---------------------------------------------------------------- init

__attribute__((constructor))
static void ffaim_init(void) {
    resolveBase();
    if (!g_base) {
        NSLog(@"[ffaim] freefireth nao encontrado no dyld");
        return;
    }

    loadConfig();

    g_isLocal         = at<fn_isLocal>(RVA_Player_IsLocalPlayer);
    g_isVisible       = at<fn_isVisible>(RVA_Entity_IsVisible);
    g_getHeadPos      = at<fn_vec3_this>(RVA_Player_GetHeadPosition);
    g_getHipPos       = at<fn_vec3_this>(RVA_Player_GetHipPosition);
    g_getAimStart     = at<fn_vec3_this>(RVA_Player_GetAimStartPostion);
    g_transformPos    = at<fn_vec3_this>(RVA_Transform_GetPosition);
    g_transformParent = at<fn_ptr_this>(RVA_Transform_GetParent);

    MSHookFunction((void *)(g_base + RVA_Player_LateUpdate),
                   (void *)hook_LateUpdate,
                   (void **)&orig_LateUpdate);

    NSLog(@"[ffaim] base=0x%lx enabled=%d fov=%.0f bone=%d",
          (unsigned long)g_base, g_cfg.enabled, g_cfg.fov, g_cfg.bone);
}
