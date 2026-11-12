// ffhook.h - hook inline arm64 + troca de metodo ObjC, sem dependencia de substrate
#pragma once
#include <stdbool.h>
#include <stdint.h>
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

// fallback sem memoria executavel: procura, nos segmentos de dados da imagem,
// ponteiros que apontem pro metodo (image_base + rva) e troca pelo replacement.
// e o caminho que funciona em app sideload, onde __TEXT nao pode ser patchado
// mas __DATA e __DATA_CONST continuam gravaveis.
//
// so troca slot que pareca tabela de metodos: os vizinhos tambem apontam pra
// __TEXT. dado comum que por acaso valha o endereco do metodo nao passa nesse
// teste, entao o scan nao consegue mais estragar tabela alheia.
// devolve quantos ponteiros trocou (0 = nao achou).
int ff_patch_method_pointer(uintptr_t image_base, uintptr_t rva, void *replacement);

// desfaz tudo que ff_patch_method_pointer trocou, devolvendo o valor original
// de cada slot. devolve quantos reverteu. chamar antes de desligar o core.
int ff_unpatch_method_pointers(void);

// motivo da ultima falha de ff_hook_function (string estatica, nunca NULL)
extern char ff_hook_last_error[160];

#ifdef __cplusplus
}
#endif
