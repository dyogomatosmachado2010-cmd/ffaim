// ffhook.h - hook inline arm64 + troca de metodo ObjC, sem dependencia de substrate
#pragma once
#include <stdbool.h>
#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

// substitui as 4 primeiras instrucoes (16 bytes) do alvo por um salto absoluto.
// devolve false sem tocar no alvo se o prologo tiver instrucao PC-relativa ou se
// a pagina nao puder voltar a ser executavel. nesse caso nada foi escrito.
bool ff_hook_function(void *target, void *replacement, void **trampoline);

// troca a implementacao de um seletor. devolve a IMP anterior em *original.
bool ff_hook_method(Class cls, SEL sel, IMP replacement, IMP *original);

// motivo da ultima falha de ff_hook_function (string estatica, nunca NULL)
extern char ff_hook_last_error[160];

#ifdef __cplusplus
}
#endif
