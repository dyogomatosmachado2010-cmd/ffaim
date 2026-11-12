// ffaim.h - estado compartilhado entre o core (ffaim.mm) e a UI (ffpanel.mm)
#pragma once
#include <stdint.h>
#include <stdbool.h>

struct FVec3 { float x, y, z; };
struct FQuat { float x, y, z, w; };

enum FFBone { FF_BONE_HEAD = 0, FF_BONE_NECK = 1, FF_BONE_CHEST = 2, FF_BONE_HIP = 3 };

typedef struct {
    bool  aimbot;
    bool  esp;
    bool  teamCheck;
    bool  visCheck;
    bool  drawBox;
    bool  drawLine;
    bool  drawName;
    bool  drawDist;
    int   bone;
    float fov;          // graus
    float smooth;       // 0 = snap, 1 = travado
    float maxDist;      // metros
    float espMaxDist;   // metros
} FFConfig;

// coordenadas normalizadas: 0..1, y pra cima (espaco da tela do Unity)
typedef struct {
    float hx, hy;       // cabeca
    float fx, fy;       // pe / quadril
    float dist;
    int   id;
    int   team;
    bool  dead;
} FFEspBox;

extern FFConfig g_cfg;

// estado do core, pro painel mostrar na tela (sem precisar de log no aparelho)
extern bool      g_core_ready;    // base achada + hook instalado
extern uintptr_t g_core_base;     // base do freefireth em runtime
extern int       g_core_players;  // jogadores no registry agora
extern int       g_core_ticks;    // chamadas de LateUpdate desde o load
extern const char *g_core_mode;   // "inline" | "ptr" | "-"
extern int       g_core_hits;     // quantos ponteiros de metodo foram trocados

#ifdef __cplusplus
extern "C" {
#endif

void ff_config_save(void);
int  ff_esp_snapshot(FFEspBox *out, int max);
void ff_panel_toggle(void);
bool ff_panel_visible(void);

#ifdef __cplusplus
}
#endif
