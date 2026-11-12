// ffhook.h - hook inline arm64 + troca de metodo ObjC, sem dependencia de substrate
#pragma once
#include <stdbool.h>
#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

// substitui as 4 primeiras instrucoes (16 bytes) do alvo por um salto absoluto.
// devolve false (e nao toca em nada) se o prologo tiver instrucao PC-relativa.
bool ff_hook_function(void *target, void *replacement, void **trampoline);

// troca a implementacao de um seletor. devolve a IMP anterior em *original.
bool ff_hook_method(Class cls, SEL sel, IMP replacement, IMP *original);

#ifdef __cplusplus
}
#endif
