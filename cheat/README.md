# ffaim — painel flutuante + ESP + aimbot, e bypass do anti-cheat no arquivo

Alvo: `com.privateproject.ff2018.v128` (FreeFire iOS 1.28.0), arm64/arm64e, il2cpp sem símbolos.
Todos os endereços vêm de `dump.cs` / `offsets_ff.txt` (metadata v23 + binário), não de chute.

```
cheat/
  ff_offsets.h   constantes (RVA, offsets de campo, tamanhos)
  ffaim.h        estado compartilhado core <-> UI
  ffaim.mm       core: hook LateUpdate, registro de Players, aimbot, snapshot do ESP
  ffpanel.mm     UIKit: janela overlay, painel, desenho do ESP, gesto 3 dedos x3
  ffaim.cfg      config persistida
  Makefile       Theos (.deb)
  build_dylib.sh compila ffaim.dylib pra injetar no .app (sem jailbreak)
  INSTALL.md     tutorial: compilar no PC e instalar no iPhone
  aimbot.mm      versão anterior (só aimbot por arquivo de config) — não entra no build
tools/
  ffpatch.py     bypass do anti-cheat no libac_sdk.dylib
  inject.py      injeta dylibs no .app e monta o .ipa (roda no Windows)
  ac_*.py        recon do anti-cheat (tipos, dylib, disasm, mapa de strings/imports)
.github/workflows/build.yml   compila .deb + dylib no GitHub Actions
```

## Painel

Janela `UIWindow` própria em `UIWindowLevelAlert + 100`, com `hitTest:` que devolve `nil` fora do
painel — o jogo continua recebendo toque normalmente, só a área do painel captura.

- **Aimbot** on/off
- **ESP** on/off
- **FOV** slider 5°–180°
- **Smooth** slider 0–100 % (0 = snap, 100 = travado)
- **Head / Neck / Chest / Hip** segmentado
- **Team check** on/off
- arrastar pela barra de título, `–` minimiza pra 38 pt de altura

**Gesto:** 3 dedos, 3 toques. Detectado no `-[UIApplication sendEvent:]` (swizzle), não por
`UIGestureRecognizer` nem no `-[UIWindow sendEvent:]`. Regras: exatamente
3 dedos simultâneos, cada toque < 600 ms, deslocamento < 45 pt, intervalo entre toques < 550 ms.
O painel faz fade/scale ao abrir e fechar.

O hook fica no `UIApplication` porque a overlay devolve `nil` no `hitTest:` fora do painel — o
toque que atravessa nunca chegaria no `sendEvent:` da nossa janela. O `UIApplication` vê todos os
eventos antes do roteamento por janela, e o jogo continua recebendo tudo normalmente.

## ESP

Projeção real do jogo, não estimativa:

1. no `LateUpdate` do player local, `Camera::get_main()` (`0x124D8B0`) pega a câmera;
2. `Camera::WorldToScreenPoint` (`0x124D434`) projeta `GetHeadPosition` (`0x158`) e
   `GetHipPosition` (`0x160`);
3. normaliza por `Screen::get_width/height` (`0x129C094` / `0x129C0EC`) — 0..1, y pra cima;
4. grava o snapshot sob `os_unfair_lock`;
5. a `CADisplayLink` na main thread copia e desenha (caixa, linha até a base, `#PlayerID`, `XXm`).

O `drawRect:` nunca chama il2cpp — só lê o snapshot. Sem chamada de engine fora da thread do jogo.

## Offsets usados

| coisa | RVA / offset |
|---|---|
| `Player::LateUpdate` | `0x9093E4` |
| `Player::IsLocalPlayer` | `0x8EA308` |
| `Player::GetHeadPosition` | `0x9291B4` |
| `Player::GetHipPosition` | `0x922B84` |
| `Player::get_AimStartPostion` | `0x927208` |
| `Camera::get_main` / `WorldToScreenPoint` | `0x124D8B0` / `0x124D434` |
| `Camera::get_pixelHeight` | `0x124D060` |
| `Screen::get_width` / `get_height` | `0x129C094` / `0x129C0EC` |
| `AttackableEntity::IsVisible` | `0x75F0D4` |
| `Transform::get_position` / `get_parent` | `0x12B0914` / `0x12B123C` |
| `Player.AimRotation` (Quaternion) | `0x114` |
| `Player.HeadTF` / `HipTF` / `WeaponMountTF` | `0x158` / `0x160` / `0x150` |
| `Player.TeamIndex` / `UserID` / `PlayerID` | `0x74` / `0x68` / `0x70` |
| `AttackableEntity.IsDead` | `0x44` |

Mira = escrever `Quaternion.LookRotation(dir, up)` em `Player+0x114`. É o quaternion que
`GetCameraTrackableEntityAimRotation` (`0x9296A8`) devolve direto, então a câmera acompanha.
Origem do vetor é `get_AimStartPostion` (boca do cano), não o centro da cabeça.
`neck` = `HeadTF->parent`; `chest` = `hip + (head - hip) * 0.55`.

## Bypass — o anti-cheat está no arquivo, e é aqui que ele morre

O jogo carrega `@rpath/libac_sdk.dylib` (LC_LOAD_DYLIB, rpath `@executable_path/Frameworks`) —
`Frameworks/libac_sdk.dylib`, 70 KB. Ele é o AC inteiro: não é Unity, não é C#, é ObjC/C puro
com 5 funções exportadas (`AcSDK_init`, `AcSDK_tick`, `AcSDK_flags`, `AcSDK_set_session`,
`AcSDK_get_report`) e a classe `ACAntiCheat`.

### Anatomia

`AcSDK_init` / `AcSDK_tick` / `AcSDK_get_report` chamam as mesmas 7 checagens e vão empilhando
bits em `__data:0xCAA0`. `AcSDK_flags()` só faz `ldr w0, [0xCAA0]`. O `get_report` monta
`{"v":2,"plat":"ios","ts":...,"dev":"...","flags":%u}` e posta em `ffpp-ac-v2/enc` / `ffpp-ac-v2/mac`.

| RVA | função | o que detecta | retorno "limpo" |
|---|---|---|---|
| `0x5438` | `dbg_ptrace` | `sysctl(KERN_PROC_PID)` → `p_flag & P_TRACED` (debugger) | 0 |
| `0x54E0` | `dyld_images` | 27 nomes de imagem: substrate, substitute, frida, cycript, libhooker, ellekit, tweakinject, rocketbootstrap, shadowhook, blackjack, pspawn, dobby, fishhook, libkrw, sandy, gum-js, linjector, xposed, lsposed, riru, zygisk, magiskhide, il2cppdumper… | 0 |
| `0x503C` | `self_crc` | `crc32(__TEXT.__text)` do **próprio dylib** contra `0xE836EF99` em `__data:0xC254` (`dladdr` + `getsectbynamefromheader_64` + CRC-32 poly `0xEDB88320`) | 1 |
| `0x63DC` | `bundle_paths` | sonda de caminhos `bundlePath + "/" + nome` | 1 |
| `0x6BD0` | `dyld_filetype` | varredura de imagens do dyld por `filetype` | 1 |
| `0x6990` | `bundle_id` | `CFBundleIdentifier == com.privateproject.ff2018` | 1 |
| `0x6A68` | `jb_paths` | `access()` em Cydia/Sileo/Zebra, /bin/bash, sshd, apt, /var/jb, MobileSubstrate, libsubstrate, libhooker, libjailbreak, /private/jbtest_ac | 0 |

O `__const` (`__data:0xC258`) está **desarmado** (0) — só o `__text` é conferido.

### O patch

`tools/ffpatch.py --apply` grava 2 instruções por função: `mov w0,#N; ret`
(`00 00 80 52 C0 03 5F D6` / `20 00 80 52 C0 03 5F D6`).

```
0x05438 dbg_ptrace     -> mov w0,#0; ret
0x054E0 dyld_images    -> mov w0,#0; ret
0x063DC bundle_paths   -> mov w0,#1; ret
0x06BD0 dyld_filetype  -> mov w0,#1; ret
0x06990 bundle_id      -> mov w0,#1; ret
0x06A68 jb_paths       -> mov w0,#0; ret
crc    : 0xE836EF99 -> 0x3C1F7529   (regravado em __data:0xC254)
```

O `self_crc` **não é desligado** no modo padrão. O CRC é recalculado sobre o `__text` já
modificado e regravado no slot — a checagem continua rodando, continua comparando e continua
passando. Do lado do servidor chega `"flags":0` com o relatório bem formado, não um cliente mudo.

```
python tools/ffpatch.py --info      # tabela + CRC
python tools/ffpatch.py --apply     # modo A (recomendado)
python tools/ffpatch.py --apply --full   # mata o self_crc também
python tools/ffpatch.py --verify
python tools/ffpatch.py --restore   # volta do .orig
```

O script falha fechado: confere tamanho (`70312`), magic, os 8 bytes originais de cada site e o
CRC de estoque antes de escrever. Outro IPA → recusa.

### Por que o binário principal fica intocado

- nenhuma byte do `freefireth` é alterada;
- o dylib só faz hash de **si mesmo**, nunca do executável — não existe hash do jogo no relatório;
- `CFBundleIdentifier`, `Info.plist`, `_CodeSignature` do app ficam como estão;
- o `@rpath/libac_sdk.dylib` continua sendo o mesmo arquivo, só com 6 funções de 2 instruções.

Depois do patch a assinatura do dylib quebra. **Reassine, senão o app não abre:**

```sh
ldid -S Frameworks/libac_sdk.dylib
# ou, no Mac:
codesign -f -s - --preserve-metadata=entitlements Frameworks/libac_sdk.dylib
```

E o `.ipa`/`.app` inteiro depois de instalar o tweak (Sideloadly / TrollStore / AltStore fazem
isso na hora de empacotar).

## Build

Theos + toolchain iOS:

```sh
cd cheat
make clean package
# packages/com.privateproject.ff2018.v128.ffaim_*.deb
```

Sem Theos, como dylib solta (rota sem jailbreak):

```sh
./build_dylib.sh          # gera ffaim.dylib + libsubstrate.dylib
python tools/inject.py --app <freefireth.app> \
    --dylib cheat/ffaim.dylib --dylib cheat/libsubstrate.dylib \
    --out FreeFire_ffaim.ipa
```

Tutorial completo de compilação e instalação (WSL, GitHub Actions, TrollStore, Sideloadly,
jailbreak): **[INSTALL.md](INSTALL.md)**.

## Config

`/var/mobile/ffaim.cfg` (rootless `/var/jb/var/mobile/ffaim.cfg`). O painel grava aí quando você
mexe nos controles; o jogo lê no boot e recarrega quando o mtime muda.

`fov`, `maxdist`, `espdist`, `smooth`, `bone` (`head|neck|chest|hip`), `teamcheck`, `vischeck`,
`box`, `line`, `name`, `dist`, `aimbot`, `esp`.

## Notas

- **Não compilei nem rodei nada aqui.** Sem clang/Theos nessa máquina. O código é arm64/arm64e e
  depende de `substrate.h`; o primeiro build é no seu Theos.
- O patch do `libac_sdk.dylib` **foi aplicado e verificado** neste IPA extraído
  (`--verify` → `integridade: OK`); os offsets das 7 checagens foram lidos do desassembly, não
  inferidos.
- Offsets são deste build (`1.28.0`, `Assembly-CSharp 0.86.0.518`, metadata v23). Outro IPA,
  outro dump — e o `ffpatch.py` recusa por tamanho/bytes.
- Se a mira voltar em veículo/paraquedas, o jogo reescreve `0x114` depois do `LateUpdate`:
  hooka `Player::UpdateAiming` (`0x9269AC`) e reescreve no fim.
- `aimbot.mm` é a versão anterior (só config, sem UI). Ficou no diretório como referência; o
  build usa `ffaim.mm` + `ffpanel.mm`.
- O `g_tick` avança a cada `LateUpdate` de qualquer player (não por frame). Com ~50 players na
  sala, `900` ticks ≈ 18 frames de validade no registro. Se a sala for grande e o ESP piscar,
  suba os limites de `600`/`900` em `ffaim.mm`.
- Ponteiro de `Player` em Unity é objeto gerenciado: o registro expira por tick justamente pra
  não ler instância reciclada. Não aumente demais esses limites.
