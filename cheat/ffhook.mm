// ffhook.mm - hook inline arm64 + troca de metodo ObjC, sem linkar contra substrate.
//
// ordem de preferencia:
//   1. MSHookFunction / MSHookMessageEx se o aparelho tiver substrate (dlopen)
//   2. hook inline proprio (copia 16 bytes de prologo pra um trampoline)
//   3. method_setImplementation (so pra ObjC, nao precisa de memoria executavel)
//
// REGRA DE OURO deste arquivo: ou o hook fica inteiro, ou o alvo fica exatamente
// como estava. Nenhum caminho deixa pagina de codigo sem EXECUTE - pagina RW
// executada mata o app na primeira chamada, e e isso que fazia o jogo fechar
// quando entrava na partida.
//
// o passo 2 precisa escrever em pagina de codigo. em TrollStore/sideload isso
// exige a entitlement dynamic-codesigning no binario principal. sem ela o hook
// falha ANTES de escrever qualquer byte, o motivo fica em ff_hook_last_error e o
// jogo segue rodando.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/mman.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <string.h>
#import <stdint.h>
#import <stdio.h>
#import <libkern/OSCacheControl.h>

#include "ffhook.h"

char ff_hook_last_error[160] = "nenhum hook tentado";

static void set_error(const char *why) {
    snprintf(ff_hook_last_error, sizeof(ff_hook_last_error), "%s", why ? why : "?");
}

// ---------------------------------------------------------------- substrate opcional

typedef void (*fn_hook_function)(void *, void *, void **);
typedef void (*fn_hook_message)(Class, SEL, IMP, IMP *);

static fn_hook_function g_subHookFunction = NULL;
static fn_hook_message  g_subHookMessage  = NULL;
static bool             g_subChecked      = false;

static void resolve_substrate(void) {
    if (g_subChecked) return;
    g_subChecked = true;

    const char *paths[] = {
        "libsubstrate.dylib",
        "/var/jb/usr/lib/libsubstrate.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/var/jb/usr/lib/libhooker.dylib",
        NULL,
    };

    void *h = NULL;
    for (int i = 0; paths[i] && !h; i++) h = dlopen(paths[i], RTLD_NOW);
    if (!h) return;

    g_subHookFunction = (fn_hook_function)dlsym(h, "MSHookFunction");
    g_subHookMessage  = (fn_hook_message)dlsym(h, "MSHookMessageEx");
}

// ---------------------------------------------------------------- memoria

#define FF_PAGE 0x1000u

static inline void *page_start(void *addr) {
    return (void *)((uintptr_t)addr & ~(uintptr_t)(FF_PAGE - 1));
}

static inline size_t page_span(void *addr, size_t len) {
    uintptr_t page = (uintptr_t)page_start(addr);
    return (((uintptr_t)addr + len - page) + FF_PAGE - 1) & ~(size_t)(FF_PAGE - 1);
}

// vm_protect e o caminho normal; mprotect e o fallback quando a task nao aceita
// a chamada mach (acontece em alguns aparelhos com AMFI mais rigido).
static bool set_prot(void *addr, size_t len, vm_prot_t prot, int mprot) {
    void  *page = page_start(addr);
    size_t size = page_span(addr, len);

    if (vm_protect(mach_task_self(), (vm_address_t)page, size, false, prot) == KERN_SUCCESS)
        return true;
    return mprotect(page, size, mprot) == 0;
}

// deixa [addr, addr+len) gravavel. VM_PROT_COPY faz copia privada da pagina e
// escapa da checagem de assinatura de codigo.
static bool make_writable(void *addr, size_t len) {
    return set_prot(addr, len,
                    (vm_prot_t)(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY),
                    PROT_READ | PROT_WRITE);
}

static bool make_executable(void *addr, size_t len) {
    return set_prot(addr, len,
                    (vm_prot_t)(VM_PROT_READ | VM_PROT_EXECUTE),
                    PROT_READ | PROT_EXEC);
}

// ---------------------------------------------------------------- inline hook arm64

// instrucoes que quebram se copiadas pra outro endereco
static inline bool pc_relative(uint32_t insn) {
    if ((insn & 0x9F000000u) == 0x90000000u) return true;  // adrp
    if ((insn & 0x9F000000u) == 0x10000000u) return true;  // adr
    if ((insn & 0x7C000000u) == 0x14000000u) return true;  // b / bl
    if ((insn & 0x3B000000u) == 0x18000000u) return true;  // ldr (literal)
    if ((insn & 0x7E000000u) == 0x34000000u) return true;  // cbz / cbnz
    if ((insn & 0xFF000010u) == 0x54000000u) return true;  // b.cond
    if ((insn & 0x7E000000u) == 0x36000000u) return true;  // tbz / tbnz
    return false;
}

// ldr x16, #8 ; br x16 ; .quad dst
static inline void emit_jump(uint32_t *p, const void *dst) {
    p[0] = 0x58000050u;
    p[1] = 0xD61F0200u;
    memcpy(p + 2, &dst, sizeof(void *));
}

// teste de ida e volta: a pagina do alvo aceita ficar gravavel E volta a ser
// executavel? se nao aceitar, nao vale a pena escrever nada - o app morreria na
// primeira chamada da funcao com a pagina em RW.
static bool roundtrip_ok(void *target) {
    if (!make_writable(target, 16)) {
        set_error("__TEXT nao aceita VM_PROT_COPY (sem dynamic-codesigning)");
        return false;
    }
    if (!make_executable(target, 16)) {
        set_error("__TEXT nao volta pra RX depois do COW (sem dynamic-codesigning)");
        return false;
    }
    return true;
}

static bool inline_hook(void *target, void *replacement, void **trampoline) {
    uint32_t *t = (uint32_t *)target;
    for (int i = 0; i < 4; i++) {
        if (pc_relative(t[i])) {
            set_error("prologo do alvo tem instrucao PC-relativa");
            return false;
        }
    }

    // 1. sonda: nada e escrito se a pagina nao puder voltar a ser executavel
    if (!roundtrip_ok(target)) return false;

    // 2. trampoline numa pagina RW; sela pra RX SO DEPOIS de escrever nela
    void *tr = mmap(NULL, FF_PAGE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
    if (tr == MAP_FAILED) {
        set_error("mmap do trampoline falhou");
        return false;
    }

    memcpy(tr, target, 16);                                       // prologo original
    emit_jump((uint32_t *)((uint8_t *)tr + 16), (uint8_t *)target + 16);  // volta pro alvo +16
    sys_icache_invalidate(tr, 32);

    if (!make_executable(tr, FF_PAGE)) {
        munmap(tr, FF_PAGE);
        set_error("trampoline nao aceita PROT_EXEC (sem dynamic-codesigning)");
        return false;
    }

    // 3. patch do alvo
    uint8_t saved[16];
    memcpy(saved, target, 16);

    if (!make_writable(target, 16)) {
        munmap(tr, FF_PAGE);
        set_error("__TEXT ficou nao-gravavel entre a sonda e o patch");
        return false;
    }

    emit_jump(t, replacement);
    sys_icache_invalidate(target, 16);

    // 4. devolve EXECUTE pra pagina do alvo. falhou -> desfaz e sai limpo.
    if (!make_executable(target, 16)) {
        if (make_writable(target, 16)) {
            memcpy(target, saved, 16);
            sys_icache_invalidate(target, 16);
        }
        make_executable(target, 16);
        munmap(tr, FF_PAGE);
        set_error("alvo nao voltou pra RX; patch desfeito");
        return false;
    }

    if (trampoline) *trampoline = tr;
    set_error("ok");
    return true;
}

// ---------------------------------------------------------------- api

bool ff_hook_function(void *target, void *replacement, void **trampoline) {
    if (!target || !replacement) {
        set_error("alvo ou replacement nulo");
        return false;
    }
    if (trampoline) *trampoline = NULL;

    resolve_substrate();

    if (g_subHookFunction) {
        g_subHookFunction(target, replacement, trampoline);
        set_error("ok (substrate)");
        return true;
    }
    return inline_hook(target, replacement, trampoline);
}

bool ff_hook_method(Class cls, SEL sel, IMP replacement, IMP *original) {
    if (!cls || !sel || !replacement) {
        set_error("classe, seletor ou IMP nulo");
        return false;
    }
    resolve_substrate();

    if (g_subHookMessage) {
        g_subHookMessage(cls, sel, replacement, original);
        return true;
    }

    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        set_error("seletor nao existe na classe");
        return false;
    }
    IMP prev = method_setImplementation(m, replacement);
    if (original) *original = prev;
    return true;
}
