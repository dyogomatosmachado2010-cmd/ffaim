// ffac.mm - neutraliza o AcSDK (libac_sdk.dylib) e troca a identidade do aparelho.
//
// O libac_sdk nao espera o jogo chamar nada: o construtor em 0x7F4C chama
// AcSDK_init(path) e o construtor em 0x80C8 sobe a thread do reporter. Dentro
// do AcSDK_init (0x4BE8) as sete checagens rodam e o resultado e' OR-ado em
// __data:0xCAA0; uma thread repete tudo a cada 111 s. Os metodos ObjC +tick e
// +flags sao so thunks pra esses enderecos e ninguem no app os chama, entao
// swizzle de metodo nao serve.
//
// O que funciona e' zerar os dados que as checagens leem, todos em __DATA/__bss
// (gravavel, sem tocar em pagina de codigo, sem mexer na assinatura):
//
//   0xC254  CRC32 esperado de __text do proprio libac_sdk  -> 0 pula a checagem
//   0xC264  CRC32 esperado de __text do executavel         -> 0 pula a checagem
//   0xC274  contagem do manifesto de Data/Managed+config   -> 0 pula a checagem
//   0xCAA0  palavra de flags                               -> 0 limpa o acumulado
//
// As outras tres (sysctl P_TRACED, blocklist do dyld, bundle id) ja' passam num
// aparelho limpo. O access() e' interceptado so' pros caminhos de jailbreak que
// o 0x6A68 testa, entao o check 0x40 tambem fica em zero num aparelho com root.
//
// A IDFV e' trocada por um UUID persistido. O reporter monta o campo "dev" com
// [UIDevice identifierForVendor].UUIDString (0x7D94), entao o servidor passa a
// ver um aparelho novo a cada SPOOFAR.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "ffaim.h"
#include "ffhook.h"

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee)                                \
    __attribute__((used)) static struct {                                      \
        const void *replacement;                                               \
        const void *replacee;                                                  \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) =  \
        { (const void *)(unsigned long)&_replacement,                          \
          (const void *)(unsigned long)&_replacee };
#endif

// ---------------------------------------------------------------- strings

// XOR com chave corrente: nada disso aparece em `strings` no dylib.
// o volatile no load e' obrigatorio: sem ele o clang do -O2 dobra o laco sobre
// o array constante e grava a string DECODIFICADA em __cstring (aconteceu na
// primeira build: `libac_sdk.dylib`, `identifierForVendor` e os caminhos de
// jailbreak sairam em texto claro no binario).
__attribute__((noinline))
static void xd(char *out, const uint8_t *in, size_t n) {
    volatile const uint8_t *v = in;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(v[i] ^ (uint8_t)(0x5B + i * 7));
    out[n] = 0;
}
#define XD(dst, arr) xd((dst), (arr), sizeof(arr))

static const uint8_t k_libac[]  = {0x37,0x0B,0x0B,0x11,0x14,0x21,0xF6,0xE8,0xF8,0xB4,0xC5,0xD1,0xC3,0xDF,0xDF};
static const uint8_t k_idfv[]   = {0x32,0x06,0x0C,0x1E,0x03,0x17,0xE3,0xE5,0xF6,0xE8,0xE7,0xC7,0xDD,0xE0,0xD8,0xAA,0xAF,0xBD,0xAB};
static const uint8_t k_uidev[]  = {0x0E,0x2B,0x2D,0x15,0x01,0x17,0xE6,0xE9};
static const uint8_t k_uidkey[] = {0x3D,0x04,0x47,0x05,0x1E,0x1A};
static const uint8_t k_caches[] = {0x18,0x03,0x0A,0x18,0x12,0x0D};
static const uint8_t k_docs[]   = {0x1F,0x0D,0x0A,0x05,0x1A,0x1B,0xEB,0xF8,0xE0};

// caminhos que o check 0x6A68 passa pro access(); blob NUL-separado.
static const uint8_t k_jb[] = {0x74,0x23,0x19,0x00,0x1B,0x17,0xE6,0xED,0xE7,0xF3,0xCE,0xC6,0xDC,0x99,0xFE,0xBD,0xAF,0xBB,0xB8,0xCE,0x86,0x9E,0x85,0xFC,0x2C,0x4B,0x61,0x68,0x73,0x4F,0x4E,0x55,0x4F,0x2B,0x26,0x3E,0x24,0x71,0x36,0x05,0x1F,0x1F,0xEE,0xA6,0xEE,0xE6,0xED,0xA4,0x84,0xF3,0xC9,0xB0,0xAB,0xA7,0xB6,0xBD,0x97,0x83,0x9E,0x96,0x8C,0x29,0x57,0x71,0x79,0x50,0x48,0x1E,0x56,0x4E,0x35,0x4C,0x7C,0x38,0x08,0x06,0x40,0x14,0x1C,0xF7,0xE3,0x92,0xB6,0xD5,0xD4,0xDC,0x9A,0xCF,0xA1,0xA3,0xBF,0xF7,0xAC,0x95,0x85,0x90,0xFB,0x2D,0x7C,0x63,0x65,0x31,0x47,0x45,0x5D,0x15,0x32,0x3B,0x27,0x56,0x72,0x01,0x1F,0x11,0x56,0xE1,0xF7,0xFA,0x95,0xB3,0xD3,0xD8,0xD8,0xCE,0xDE,0xB2,0xA8,0xFB,0xAD,0x83,0x9B,0xDF,0x9B,0x97,0x67,0x23,0x72,0x6A,0x55,0x28,0x00,0x46,0x4F,0x2D,0x3D,0x33,0x2D,0x05,0x48,0x18,0x14,0x0E,0xAC,0xE6,0xF8,0xFA,0xB0,0xC5,0xD4,0xD0,0xD2,0xA3,0xC9,0xFF,0x9B,0xB7,0x87,0x9E,0x92,0x88,0x78,0x27,0x42,0x79,0x7F,0x4D,0x47,0x57,0x6A,0x35,0x25,0x3D,0x21,0x2E,0x02,0x1E,0x14,0x57,0x32,0xE9,0xEF,0xFD,0xF7,0xC7,0xFA,0xC5,0xD5,0xCD,0xB1,0xBE,0xB2,0xAE,0x84,0xC6,0x8B,0x8F,0x91,0x6D,0x69,0x12,0x36,0x55,0x54,0x5C,0x1A,0x50,0x2A,0x28,0x7E,0x34,0x36,0x04,0x1E,0x01,0x19,0xF1,0xFD,0xE2,0xF6,0xEA,0xC0,0x82,0xD7,0xC3,0xAD,0xA1,0xAD,0xD6,0xF2,0x91,0x98,0x80,0xD6,0x6C,0x6E,0x6C,0x3A,0x70,0x4A,0x48,0x59,0x57,0x50,0x2D,0x28,0x26,0x75,0x06,0x10,0x1C,0x1E,0x1C,0x85,0xA3,0xE6,0xE9,0xD3,0x87,0xC3,0xDF,0xDF,0xEB,0xA7,0xBB,0xBB,0x8A,0x86,0x87,0x99,0x9E,0x71,0x6F,0x70,0x73,0x31,0x42,0x54,0x58,0x52,0x20,0x49,0x7F,0x21,0x3F,0x17,0x43,0x19,0x18,0x81,0xA7,0xFF,0xE4,0xF4,0xD2,0xCA,0xC6,0xDC,0xEF,0xAD,0xAC,0xA1,0xB9,0x90,0x9E,0xAE,0x99,0x9C,0x06,0x0D};

// ---------------------------------------------------------------- estado

bool g_ac_patched = false;
char g_ac_error[96] = "ac:?";

static uintptr_t g_ac_base = 0;
static int       g_ac_parts = 0;

// ---------------------------------------------------------------- access()

static int (*orig_access)(const char *, int) = NULL;
static char g_jb[sizeof(k_jb) + 1];
static bool g_jb_ready = false;

static bool jb_blocked(const char *p) {
    if (!p) return false;
    if (!g_jb_ready) { XD(g_jb, k_jb); g_jb_ready = true; }
    for (const char *s = g_jb; *s; s += strlen(s) + 1)
        if (strcmp(p, s) == 0) return true;
    return false;
}

static int ff_access(const char *path, int mode) {
    if (jb_blocked(path)) return -1;
    if (!orig_access) orig_access = (int (*)(const char *, int))dlsym(RTLD_DEFAULT, "access");
    if (!orig_access) return -1;
    return orig_access(path, mode);
}

DYLD_INTERPOSE(ff_access, access)

// ---------------------------------------------------------------- usleep

// a thread do watchdog (0x4CC8) faz: usleep(0x6A6CFC0) -> 7 checagens -> OR em
// 0xCAA0 -> volta pro usleep. Zerar as flags na entrada do usleep significa
// zerar logo depois de cada rajada de checagens: a janela em que 0xCAA0 fica
// diferente de zero cai de 111 s para alguns microssegundos.
static int (*orig_usleep)(useconds_t) = NULL;

static void ac_clear(void) {
    if (!g_ac_base) return;
    volatile uint32_t *base = (volatile uint32_t *)g_ac_base;
    if (g_ac_patched) {
        base[0xC254 / 4] = 0;
        base[0xC264 / 4] = 0;
        base[0xC274 / 4] = 0;
    }
    base[0xCAA0 / 4] = 0;
}

static int ff_usleep(useconds_t us) {
    bool long_sleep = (us >= 60000000u);   // so' o watchdog chega aqui
    if (long_sleep) ac_clear();
    if (!orig_usleep)
        orig_usleep = (int (*)(useconds_t))dlsym(RTLD_DEFAULT, "usleep");
    int r = orig_usleep ? orig_usleep(us) : -1;
    if (long_sleep) ac_clear();            // quem acorda e reporta ve zero
    return r;
}

DYLD_INTERPOSE(ff_usleep, usleep)

// ---------------------------------------------------------------- AcSDK

static uintptr_t ac_find(void) {
    char want[24];
    XD(want, k_libac);
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        const char *b = strrchr(nm, '/');
        b = b ? b + 1 : nm;
        if (strcmp(b, want) == 0)
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// so' zera se o valor for o esperado; dylib diferente nao e' tocado as cegas.
static bool ac_zero(uintptr_t base, uint32_t off, uint32_t expect) {
    volatile uint32_t *p = (volatile uint32_t *)(base + off);
    if (*p != expect) return false;
    *p = 0;
    return true;
}

int ff_ac_install(void) {
    if (g_ac_base) {
        // reaplica o que a thread de 111 s pode ter restaurado
        if (g_ac_patched) {
            *(volatile uint32_t *)(g_ac_base + 0xC254) = 0;
            *(volatile uint32_t *)(g_ac_base + 0xC264) = 0;
            *(volatile uint32_t *)(g_ac_base + 0xC274) = 0;
        }
        *(volatile uint32_t *)(g_ac_base + 0xCAA0) = 0;
        return g_ac_patched;
    }

    uintptr_t b = ac_find();
    if (!b) {
        snprintf(g_ac_error, sizeof(g_ac_error), "%s", "ac:nao carregado");
        return 0;
    }

    g_ac_base = b;
    int n = 0;
    if (ac_zero(b, 0xC254, 0xE836EF99)) n++;   // CRC do proprio libac_sdk
    if (ac_zero(b, 0xC264, 0x48861145)) n++;   // CRC do __text do executavel
    if (ac_zero(b, 0xC274, 0x00000002)) n++;   // contagem do manifesto
    *(volatile uint32_t *)(b + 0xCAA0) = 0;    // flags acumuladas

    g_ac_parts   = n;
    g_ac_patched = (n == 3);
    if (g_ac_patched) snprintf(g_ac_error, sizeof(g_ac_error), "%s", "ac:off");
    else              snprintf(g_ac_error, sizeof(g_ac_error), "ac:%d/3", n);
    return g_ac_patched;
}

const char *ff_ac_status(void) { return g_ac_error; }

// ---------------------------------------------------------------- spoofer

static NSString *spoof_key(void) {
    char k[16];
    XD(k, k_uidkey);
    return [NSString stringWithUTF8String:k];
}

static NSString *spoof_get(void) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *s = [d stringForKey:spoof_key()];
    if (s.length != 36) {
        s = [[NSUUID UUID] UUIDString];
        [d setObject:s forKey:spoof_key()];
        [d synchronize];
    }
    return s;
}

void ff_spoof_roll(void) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setObject:[[NSUUID UUID] UUIDString] forKey:spoof_key()];
    [d synchronize];
}

const char *ff_spoof_id(void) {
    static char buf[40];
    NSString *s = spoof_get();
    snprintf(buf, sizeof(buf), "%s", s.UTF8String ?: "-");
    return buf;
}

static NSUUID *(*orig_idfv)(id, SEL) = NULL;

static NSUUID *ff_idfv(id self, SEL _cmd) {
    NSString *s = spoof_get();
    if (s.length == 36) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:s];
        if (u) return u;
    }
    return orig_idfv ? orig_idfv(self, _cmd) : nil;
}

static void idfv_install(void) {
    char cn[16], sn[24];
    XD(cn, k_uidev);
    XD(sn, k_idfv);
    Class c = objc_getClass(cn);
    SEL s = sel_registerName(sn);
    if (c && s) ff_hook_method(c, s, (IMP)ff_idfv, (IMP *)&orig_idfv);
}

// ---------------------------------------------------------------- ban wipe

// o libac_sdk nao importa Security.framework: os itens "ffpp-ac-v2/enc" e
// "/mac" sao chaves de cifra no proprio binario, nao servicos de keychain. quem
// grava identidade no keychain e' o jogo. entao a limpeza e' por atributo:
// varre os generic passwords do app e apaga so' os que cheiram a device/ban.
static int wipe_keychain(void) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:              (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecReturnAttributes:   @YES,
        (__bridge id)kSecMatchLimit:         (__bridge id)kSecMatchLimitAll,
    };
    CFTypeRef res = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
    if (st != errSecSuccess || !res) {
        if (res) CFRelease(res);
        return 0;
    }

    NSArray *items = (__bridge_transfer NSArray *)res;
    NSArray *needles = @[@"ffpp", @"anticheat", @"ac_sdk", @"banned",
                         @"banhistory", @"deviceid", @"device_id", @"device-id"];
    int n = 0;
    for (NSDictionary *it in items) {
        NSString *svc  = it[(__bridge id)kSecAttrService] ?: @"";
        NSString *acct = it[(__bridge id)kSecAttrAccount] ?: @"";
        NSString *both = [[NSString stringWithFormat:@"%@ %@", svc, acct] lowercaseString];
        BOOL hit = NO;
        for (NSString *nd in needles)
            if ([both containsString:nd]) { hit = YES; break; }
        if (!hit) continue;

        NSMutableDictionary *dq = [@{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        } mutableCopy];
        if (svc.length)  dq[(__bridge id)kSecAttrService] = svc;
        if (acct.length) dq[(__bridge id)kSecAttrAccount] = acct;
        if (SecItemDelete((__bridge CFDictionaryRef)dq) == errSecSuccess) n++;
    }
    return n;
}

// "banner" e "bandwidth" nao sao ban. casa prefixo/sufixo com separador.
static bool name_ban(NSString *low) {
    if ([low containsString:@"banner"]) return false;
    if ([low isEqualToString:@"ban"]) return true;
    if ([low containsString:@"anticheat"] || [low containsString:@"ac_sdk"] ||
        [low containsString:@"ffpp"] || [low containsString:@"acflag"] ||
        [low containsString:@"ac_flag"])
        return true;
    static const char *pats[] = {
        "_ban", ".ban", "ban_", "banned", "banuntil", "banexpire",
        "banhistory", "banreason", "baninfo", "banstatus", "banlist",
        "/ban", "ban.",
    };
    for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++)
        if ([low containsString:[NSString stringWithUTF8String:pats[i]]]) return true;
    return false;
}

static bool ban_key(NSString *k) { return name_ban(k.lowercaseString); }

static int wipe_defaults(void) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [d dictionaryRepresentation];
    int n = 0;
    for (NSString *k in all.allKeys) {
        if (ban_key(k)) { [d removeObjectForKey:k]; n++; }
    }
    [d synchronize];
    return n;
}

static int wipe_dir(NSString *root) {
    if (!root) return 0;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:root isDirectory:&isDir] || !isDir) return 0;

    NSMutableArray *kill = [NSMutableArray array];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:root];
    int seen = 0;
    for (NSString *rel in en) {
        if (++seen > 2000 || kill.count >= 64) break;
        if (name_ban(rel.lowercaseString))
            [kill addObject:[root stringByAppendingPathComponent:rel]];
    }

    int n = 0;
    for (NSString *p in kill)
        if ([fm removeItemAtPath:p error:nil]) n++;
    return n;
}

int ff_ban_wipe(void) {
    int n = 0;
    n += wipe_keychain();
    n += wipe_defaults();

    NSString *home = NSHomeDirectory();
    char c1[8], c2[12];
    XD(c1, k_caches);
    XD(c2, k_docs);
    n += wipe_dir([home stringByAppendingPathComponent:[NSString stringWithUTF8String:c1]]);
    n += wipe_dir([home stringByAppendingPathComponent:[NSString stringWithUTF8String:c2]]);

    // o libac_sdk nao persiste nada (so' le arquivos), mas o jogo guarda
    // device id no keychain/defaults. zera as flags em memoria junto.
    if (g_ac_base) *(volatile uint32_t *)(g_ac_base + 0xCAA0) = 0;
    return n;
}

// ---------------------------------------------------------------- init

__attribute__((constructor))
static void ffac_init(void) {
    // resolve o access real antes de qualquer chamada interposta
    orig_access = (int (*)(const char *, int))dlsym(RTLD_DEFAULT, "access");

    idfv_install();

    if (!ff_ac_install()) {
        // o libac_sdk pode ser carregado depois do nosso LC em algumas builds;
        // tenta por 10 s antes de desistir.
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            for (int i = 0; i < 100 && !g_ac_base; i++) {
                usleep(100000);
                ff_ac_install();
            }
        });
    }

    // guarda: a thread do AC reescreve 0xCAA0 a cada 111 s; rezerar e' barato.
    // fonte fica em variavel estatica: sob ARC uma local seria liberada no fim
    // do construtor e o timer nunca dispararia.
    static dispatch_source_t guard = nil;
    guard = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(guard,
        dispatch_time(DISPATCH_TIME_NOW, 2ull * NSEC_PER_SEC),
        2ull * NSEC_PER_SEC, 500ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(guard, ^{
        if (g_ac_base) ff_ac_install();
    });
    dispatch_resume(guard);
}
