// ffaim.mm - core: base il2cpp, registro de Players, aimbot, snapshot do ESP.
// build: Theos (ver Makefile). alvo: freefireth 1.28.0 / arm64 / arm64e.
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <math.h>
#import <sys/stat.h>
#import <stdlib.h>
#import <stdio.h>
#import <string.h>
#import <os/lock.h>
#include <string>

#include "ffaim.h"
#include "ff_offsets.h"
#include "ffhook.h"

// ---------------------------------------------------------------- math

static inline FVec3 vadd(FVec3 a, FVec3 b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
static inline FVec3 vsub(FVec3 a, FVec3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
static inline FVec3 vmul(FVec3 a, float s) { return {a.x * s, a.y * s, a.z * s}; }
static inline float vdot(FVec3 a, FVec3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
static inline float vlen(FVec3 a) { return sqrtf(vdot(a, a)); }
static inline FVec3 vnorm(FVec3 a) {
    float l = vlen(a);
    if (l < 1e-6f) return {0, 0, 1};
    return vmul(a, 1.0f / l);
}
static inline FVec3 vcross(FVec3 a, FVec3 b) {
    return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
}

// forward = q * (0,0,1)
static inline FVec3 forwardFromQuat(FQuat q) {
    return {2.0f * (q.x * q.z + q.w * q.y),
            2.0f * (q.y * q.z - q.w * q.x),
            1.0f - 2.0f * (q.x * q.x + q.y * q.y)};
}

static FQuat lookRotation(FVec3 f, FVec3 up) {
    f = vnorm(f);
    FVec3 r = vcross(up, f);
    if (vlen(r) < 1e-5f) r = vcross({0, 0, 1}, f);
    r = vnorm(r);
    FVec3 u = vcross(f, r);

    float m00 = r.x, m01 = u.x, m02 = f.x;
    float m10 = r.y, m11 = u.y, m12 = f.y;
    float m20 = r.z, m21 = u.z, m22 = f.z;

    FQuat q{0, 0, 0, 1};
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

static FQuat nlerp(FQuat a, FQuat b, float t) {
    float d = a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w;
    if (d < 0.0f) { b.x = -b.x; b.y = -b.y; b.z = -b.z; b.w = -b.w; }
    FQuat r{a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t,
            a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t};
    float n = sqrtf(r.x * r.x + r.y * r.y + r.z * r.z + r.w * r.w);
    if (n > 1e-6f) { r.x /= n; r.y /= n; r.z /= n; r.w /= n; }
    return r;
}

// ---------------------------------------------------------------- config

FFConfig g_cfg = {
    /*aimbot*/ true, /*esp*/ true, /*teamCheck*/ true, /*visCheck*/ false,
    /*drawBox*/ true, /*drawLine*/ true, /*drawName*/ true, /*drawDist*/ true,
    /*bone*/ FF_BONE_HEAD,
    /*fov*/ 25.0f, /*smooth*/ 0.35f, /*maxDist*/ 250.0f, /*espMaxDist*/ 300.0f,
};

static time_t g_cfgMtime = 0;

static const char *kCfgPaths[] = {
    "/var/jb/var/mobile/ffaim.cfg",
    "/var/mobile/ffaim.cfg",
};

static const char *cfgReadPath(void) {
    struct stat st;
    for (const char *p : kCfgPaths)
        if (stat(p, &st) == 0) return p;
    return nullptr;
}

static const char *cfgWritePath(void) {
    for (const char *p : kCfgPaths) {
        FILE *f = fopen(p, "a");
        if (f) { fclose(f); return p; }
    }
    return nullptr;
}

static void cfgSanitize(void) {
    if (g_cfg.fov < 1.0f) g_cfg.fov = 1.0f;
    if (g_cfg.fov > 180.0f) g_cfg.fov = 180.0f;
    if (g_cfg.smooth < 0.0f) g_cfg.smooth = 0.0f;
    if (g_cfg.smooth > 1.0f) g_cfg.smooth = 1.0f;
    if (g_cfg.maxDist < 5.0f) g_cfg.maxDist = 5.0f;
    if (g_cfg.espMaxDist < 5.0f) g_cfg.espMaxDist = 5.0f;
    if (g_cfg.bone < 0 || g_cfg.bone > 3) g_cfg.bone = FF_BONE_HEAD;
}

static void cfgLoad(void) {
    const char *path = cfgReadPath();
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
        if (k == "aimbot") g_cfg.aimbot = atoi(val) != 0;
        else if (k == "esp") g_cfg.esp = atoi(val) != 0;
        else if (k == "fov") g_cfg.fov = (float)atof(val);
        else if (k == "maxdist") g_cfg.maxDist = (float)atof(val);
        else if (k == "espdist") g_cfg.espMaxDist = (float)atof(val);
        else if (k == "smooth") g_cfg.smooth = (float)atof(val);
        else if (k == "bone") {
            if (v == "head") g_cfg.bone = FF_BONE_HEAD;
            else if (v == "neck") g_cfg.bone = FF_BONE_NECK;
            else if (v == "chest") g_cfg.bone = FF_BONE_CHEST;
            else if (v == "hip") g_cfg.bone = FF_BONE_HIP;
        }
        else if (k == "teamcheck") g_cfg.teamCheck = atoi(val) != 0;
        else if (k == "vischeck") g_cfg.visCheck = atoi(val) != 0;
        else if (k == "box") g_cfg.drawBox = atoi(val) != 0;
        else if (k == "line") g_cfg.drawLine = atoi(val) != 0;
        else if (k == "name") g_cfg.drawName = atoi(val) != 0;
        else if (k == "dist") g_cfg.drawDist = atoi(val) != 0;
    }
    fclose(f);
    cfgSanitize();
}

void ff_config_save(void) {
    const char *path = cfgWritePath();
    if (!path) return;
    FILE *f = fopen(path, "w");
    if (!f) return;
    const char *boneName = "head";
    switch (g_cfg.bone) {
        case FF_BONE_NECK: boneName = "neck"; break;
        case FF_BONE_CHEST: boneName = "chest"; break;
        case FF_BONE_HIP: boneName = "hip"; break;
        default: break;
    }
    fprintf(f,
            "aimbot=%d\nesp=%d\nfov=%.1f\nmaxdist=%.0f\nespdist=%.0f\nsmooth=%.2f\n"
            "bone=%s\nteamcheck=%d\nvischeck=%d\nbox=%d\nline=%d\nname=%d\ndist=%d\n",
            g_cfg.aimbot, g_cfg.esp, g_cfg.fov, g_cfg.maxDist, g_cfg.espMaxDist,
            g_cfg.smooth, boneName, g_cfg.teamCheck, g_cfg.visCheck,
            g_cfg.drawBox, g_cfg.drawLine, g_cfg.drawName, g_cfg.drawDist);
    fclose(f);
    struct stat st;
    if (stat(path, &st) == 0) g_cfgMtime = st.st_mtime;
}

// ---------------------------------------------------------------- module

static uintptr_t g_base = 0;

bool      g_core_ready   = false;
uintptr_t g_core_base    = 0;
int       g_core_players = 0;
int       g_core_ticks   = 0;

static void resolveBase(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "/freefireth")) {
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

typedef bool (*fn_bool_this)(void *);
typedef int  (*fn_int_this)(void *);
typedef void *(*fn_ptr_this)(void *);
typedef FVec3 (*fn_vec3_this)(void *);
typedef FVec3 (*fn_w2s)(void *, FVec3);
typedef void *(*fn_static_ptr)(void *);
typedef int  (*fn_static_int)(void *);

static fn_bool_this   g_isLocal = nullptr;
static fn_bool_this   g_isVisible = nullptr;
static fn_vec3_this   g_getHeadPos = nullptr;
static fn_vec3_this   g_getHipPos = nullptr;
static fn_vec3_this   g_getAimStart = nullptr;
static fn_vec3_this   g_transformPos = nullptr;
static fn_ptr_this    g_transformParent = nullptr;
static fn_static_ptr  g_getMainCam = nullptr;
static fn_w2s         g_w2s = nullptr;
static fn_static_int  g_screenW = nullptr;
static fn_static_int  g_screenH = nullptr;

// ---------------------------------------------------------------- bone

static FVec3 bonePosition(void *p) {
    switch (g_cfg.bone) {
    case FF_BONE_NECK: {
        void *tf = rd_ptr(p, OFF_Player_HeadTF);
        void *parent = tf ? g_transformParent(tf) : nullptr;
        if (parent) return g_transformPos(parent);
        FVec3 h = g_getHeadPos(p);
        return {h.x, h.y - 0.12f, h.z};
    }
    case FF_BONE_CHEST: {
        FVec3 h = g_getHeadPos(p), hip = g_getHipPos(p);
        return vadd(hip, vmul(vsub(h, hip), 0.55f));
    }
    case FF_BONE_HIP:
        return g_getHipPos(p);
    case FF_BONE_HEAD:
    default:
        return g_getHeadPos(p);
    }
}

static inline bool usable(void *p) {
    if (!p) return false;
    if ((uintptr_t)p & 7) return false;
    void *klass = *(void **)p;              // klass em +0x0
    if (!klass) return false;
    if ((uintptr_t)klass < 0x100000000ULL) return false;
    if ((uintptr_t)klass & 7) return false;
    return true;
}

// ---------------------------------------------------------------- esp snapshot

#define FF_ESP_MAX 64

static FFEspBox g_esp[FF_ESP_MAX];
static int g_espCount = 0;
static os_unfair_lock g_espLock = OS_UNFAIR_LOCK_INIT;

int ff_esp_snapshot(FFEspBox *out, int max) {
    os_unfair_lock_lock(&g_espLock);
    int n = g_espCount < max ? g_espCount : max;
    if (n > 0) memcpy(out, g_esp, (size_t)n * sizeof(FFEspBox));
    os_unfair_lock_unlock(&g_espLock);
    return n;
}

static void espBuild(void *local) {
    if (!g_cfg.esp || !g_w2s || !g_screenW || !g_screenH) return;

    void *cam = g_getMainCam(nullptr);
    if (!cam) return;

    int sw = g_screenW(nullptr);
    int sh = g_screenH(nullptr);
    if (sw < 1 || sh < 1) return;

    float invW = 1.0f / (float)sw;
    float invH = 1.0f / (float)sh;

    int localTeam = rd_i32(local, OFF_Player_TeamIndex);
    FFEspBox tmp[FF_ESP_MAX];
    int n = 0;

    for (int i = 0; i < kMaxPlayers && n < FF_ESP_MAX; i++) {
        void *p = g_players[i].player;
        if (!p || p == local) continue;
        if (g_tick - g_players[i].tick > 600) continue;
        if (!usable(p)) continue;

        bool dead = rd_bool(p, OFF_Entity_IsDead);
        int team = rd_i32(p, OFF_Player_TeamIndex);
        if (dead) continue;
        if (g_cfg.teamCheck && team == localTeam) continue;

        FVec3 head = g_getHeadPos(p);
        FVec3 foot = g_getHipPos(p);
        if (!isfinite(head.x) || !isfinite(head.y) || !isfinite(head.z)) continue;
        if (!isfinite(foot.x) || !isfinite(foot.y) || !isfinite(foot.z)) continue;

        FVec3 hp = g_w2s(cam, head);
        FVec3 fp = g_w2s(cam, foot);
        if (hp.z <= 0.01f || fp.z <= 0.01f) continue;   // atras da camera

        FVec3 eye = g_getHeadPos(local);
        float dist = vlen(vsub(head, eye));
        if (dist > g_cfg.espMaxDist) continue;

        tmp[n].hx = hp.x * invW;
        tmp[n].hy = hp.y * invH;
        tmp[n].fx = fp.x * invW;
        tmp[n].fy = fp.y * invH;
        tmp[n].dist = dist;
        tmp[n].id = rd_i32(p, OFF_Player_PlayerID);
        tmp[n].team = team;
        tmp[n].dead = dead;
        n++;
    }

    os_unfair_lock_lock(&g_espLock);
    g_espCount = n;
    if (n > 0) memcpy(g_esp, tmp, (size_t)n * sizeof(FFEspBox));
    os_unfair_lock_unlock(&g_espLock);
}

// ---------------------------------------------------------------- aimbot

static void aimbot(void *self) {
    if (!g_cfg.aimbot) return;
    if (!rd_ptr(self, OFF_Player_HeadTF)) return;

    FVec3 origin = g_getAimStart(self);
    if (!isfinite(origin.x) || !isfinite(origin.y) || !isfinite(origin.z))
        origin = g_getHeadPos(self);

    FQuat cur = *(FQuat *)((char *)self + OFF_Player_AimRotation);
    FVec3 fwd = forwardFromQuat(cur);
    int localTeam = rd_i32(self, OFF_Player_TeamIndex);

    float cosFov = cosf(g_cfg.fov * 3.14159265f / 180.0f);
    void *best = nullptr;
    FVec3 bestPos{0, 0, 0};
    float bestDot = cosFov;
    float bestDist = 1e9f;

    for (int i = 0; i < kMaxPlayers; i++) {
        void *p = g_players[i].player;
        if (!p || p == self) continue;
        if (g_tick - g_players[i].tick > 900) continue;
        if (!usable(p)) continue;
        if (rd_bool(p, OFF_Entity_IsDead)) continue;
        if (g_cfg.teamCheck && rd_i32(p, OFF_Player_TeamIndex) == localTeam) continue;
        if (g_cfg.visCheck && g_isVisible && !g_isVisible(p)) continue;

        FVec3 pos = bonePosition(p);
        if (!isfinite(pos.x) || !isfinite(pos.y) || !isfinite(pos.z)) continue;

        FVec3 d = vsub(pos, origin);
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

    FVec3 dir = vnorm(vsub(bestPos, origin));
    FQuat want = lookRotation(dir, {0, 1, 0});
    if (g_cfg.smooth > 0.001f && g_cfg.smooth < 0.999f)
        want = nlerp(cur, want, 1.0f - g_cfg.smooth);

    *(FQuat *)((char *)self + OFF_Player_AimRotation) = want;
}

// ---------------------------------------------------------------- hook

static void (*orig_LateUpdate)(void *) = nullptr;

// LateUpdate de um Player nao chama LateUpdate de outro, mas aimbot/esp chamam
// metodos do jogo que podem reentrar em codigo gerenciado. o guarda evita
// recursao se isso acontecer.
static __thread int t_inHook = 0;

static void hook_LateUpdate(void *self) {
    if (t_inHook) return;
    t_inHook = 1;

    if (orig_LateUpdate) orig_LateUpdate(self);

    if (!g_base || !self) { t_inHook = 0; return; }

    g_tick++;
    g_core_ticks = (int)(g_tick & 0x7FFFFFFF);
    if ((g_tick & 0x1FF) == 0) cfgLoad();

    regAdd(self);

    if ((g_tick & 0x3F) == 0) {
        int n = 0;
        for (int i = 0; i < kMaxPlayers; i++) {
            void *p = g_players[i].player;
            if (p && g_tick - g_players[i].tick <= 900 && usable(p)) n++;
        }
        g_core_players = n;
    }

    if (g_isLocal && g_isLocal(self)) {
        aimbot(self);
        espBuild(self);
    }

    t_inHook = 0;
}

// ---------------------------------------------------------------- init

__attribute__((constructor))
static void ffaim_init(void) {
    resolveBase();
    if (!g_base) {
        NSLog(@"[ffaim] freefireth nao encontrado no dyld");
        return;
    }
    g_core_base = g_base;

    cfgLoad();

    g_isLocal         = at<fn_bool_this>(RVA_Player_IsLocalPlayer);
    g_isVisible       = at<fn_bool_this>(RVA_Entity_IsVisible);
    g_getHeadPos      = at<fn_vec3_this>(RVA_Player_GetHeadPosition);
    g_getHipPos       = at<fn_vec3_this>(RVA_Player_GetHipPosition);
    g_getAimStart     = at<fn_vec3_this>(RVA_Player_GetAimStartPostion);
    g_transformPos    = at<fn_vec3_this>(RVA_Transform_GetPosition);
    g_transformParent = at<fn_ptr_this>(RVA_Transform_GetParent);
    g_getMainCam      = at<fn_static_ptr>(RVA_Camera_GetMain);
    g_w2s             = at<fn_w2s>(RVA_Camera_WorldToScreenPoint);
    g_screenW         = at<fn_static_int>(RVA_Screen_GetWidth);
    g_screenH         = at<fn_static_int>(RVA_Screen_GetHeight);

    if (!ff_hook_function((void *)(g_base + RVA_Player_LateUpdate),
                          (void *)hook_LateUpdate,
                          (void **)&orig_LateUpdate)) {
        // hook recusado: o jogo continua rodando normal, so sem aimbot/esp.
        NSLog(@"[ffaim] hook recusado: %s", ff_hook_last_error);
        g_core_ready = false;
        return;
    }

    g_core_ready = true;
    NSLog(@"[ffaim] base=0x%lx aimbot=%d esp=%d fov=%.0f",
          (unsigned long)g_base, g_cfg.aimbot, g_cfg.esp, g_cfg.fov);
}
