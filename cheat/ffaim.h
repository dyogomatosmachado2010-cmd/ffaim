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
    bool  allowInline;  // tenta hook inline em __TEXT antes do ponteiro (risco de COW)
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
extern bool      g_core_ready;     // base achada
extern bool      g_core_installed; // metodo do jogo ja trocado agora
extern uintptr_t g_core_base;      // base do freefireth em runtime
extern int       g_core_players;   // jogadores no registry agora
extern int       g_core_ticks;     // chamadas de LateUpdate desde o load
extern const char *g_core_mode;    // "inline" | "ptr" | "-"
extern int       g_core_hits;      // quantos ponteiros de metodo foram trocados
extern char      g_core_error[160];// motivo da ultima falha de instalacao

#ifdef __cplusplus
extern "C" {
#endif

// instala/remove a troca do LateUpdate. nada e escrito no processo do jogo
// antes de ff_core_install(): com aimbot e esp desligados o app roda igual ao
// original, o que mantem login e conexao fora do caminho do mod.
int  ff_core_install(void);   // 1 = instalado, 0 = falhou (motivo em g_core_error)
void ff_core_remove(void);
void ff_core_sync(void);      // instala se aimbot||esp, remove se nenhum

void ff_config_save(void);
int  ff_esp_snapshot(FFEspBox *out, int max);
void ff_panel_toggle(void);
bool ff_panel_visible(void);

// anti-cheat / spoofer (ffac.mm)
extern bool g_ac_patched;              // 1 = os tres CRCs/manifesto foram zerados
extern char g_ac_error[96];            // "ac:off", "ac:2/3", "ac:nao carregado"
int  ff_ac_install(void);              // 1 = AcSDK neutralizado
const char *ff_ac_status(void);        // linha pronta pro painel
const char *ff_spoof_id(void);         // UUID atual (36 chars)
void ff_spoof_roll(void);              // gera e persiste um UUID novo
int  ff_ban_wipe(void);                // keychain AC + defaults + arquivos de ban

#ifdef __cplusplus
}
#endif
