// ffhook.mm - hook inline arm64 + troca de metodo ObjC, sem linkar contra substrate.
//
// ordem de preferencia:
//   1. MSHookFunction / MSHookMessageEx se o aparelho tiver substrate (dlopen)
//   2. hook inline proprio (copia 16 bytes de prologo pra um trampoline)
//   3. method_setImplementation (so pra ObjC, nao precisa de memoria executavel)
//
// o passo 2 precisa escrever em pagina de codigo. em TrollStore/sideload isso exige
// a entitlement dynamic-codesigning no binario principal - o tools/inject.py grava
// ela no .entitlements.plist que ele salva. sem ela, o hook falha e o tweak loga
// e sai limpo em vez de quebrar o jogo.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/mman.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <string.h>
#import <stdint.h>
#import <libkern/OSCacheControl.h>

#include "ffhook.h"

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

// deixa [addr, addr+len) gravavel. VM_PROT_COPY faz copia privada da pagina e
// escapa da checagem de assinatura de codigo; mprotect e o fallback.
static bool make_writable(void *addr, size_t len) {
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)0xFFF;
    size_t    size = ((uintptr_t)addr + len - page + 0xFFF) & ~(size_t)0xFFF;

    if (vm_protect(mach_task_self(), (vm_address_t)page, size, false,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS) {
        return true;
    }
    return mprotect((void *)page, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

static bool make_executable(void *addr, size_t len) {
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)0xFFF;
    size_t    size = ((uintptr_t)addr + len - page + 0xFFF) & ~(size_t)0xFFF;

    if (vm_protect(mach_task_self(), (vm_address_t)page, size, false,
                   VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS) {
        return true;
    }
    return mprotect((void *)page, size, PROT_READ | PROT_EXEC) == 0;
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

static void *alloc_exec_page(void) {
    void *p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (!make_executable(p, 0x1000)) {
        munmap(p, 0x1000);
        return NULL;
    }
    return p;
}

static bool inline_hook(void *target, void *replacement, void **trampoline) {
    uint32_t *t = (uint32_t *)target;
    for (int i = 0; i < 4; i++)
        if (pc_relative(t[i])) return false;

    uint8_t *tr = (uint8_t *)alloc_exec_page();
    if (!tr) return false;

    memcpy(tr, target, 16);                                     // prologo original
    emit_jump((uint32_t *)(tr + 16), (uint8_t *)target + 16);   // volta pro alvo +16
    sys_icache_invalidate(tr, 32);

    if (!make_writable(target, 16)) {
        munmap(tr, 0x1000);
        return false;
    }

    emit_jump(t, replacement);
    sys_icache_invalidate(target, 16);

    if (trampoline) *trampoline = tr;
    return true;
}

// ---------------------------------------------------------------- api

bool ff_hook_function(void *target, void *replacement, void **trampoline) {
    if (!target || !replacement) return false;
    resolve_substrate();

    if (g_subHookFunction) {
        g_subHookFunction(target, replacement, trampoline);
        return true;
    }
    return inline_hook(target, replacement, trampoline);
}

bool ff_hook_method(Class cls, SEL sel, IMP replacement, IMP *original) {
    if (!cls || !sel || !replacement) return false;
    resolve_substrate();

    if (g_subHookMessage) {
        g_subHookMessage(cls, sel, replacement, original);
        return true;
    }

    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return false;
    IMP prev = method_setImplementation(m, replacement);
    if (original) *original = prev;
    return true;
}
