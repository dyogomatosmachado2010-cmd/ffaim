# Instalação — do PC (Windows) até o iPhone

Quatro coisas separadas, na ordem:

```
1. compilar  ffaim.dylib / .deb     -> WSL, GitHub Actions ou Mac
2. patch do AC no libac_sdk.dylib   -> já aplicado aqui (tools/ffpatch.py)
3. montar o .ipa com o dylib dentro -> tools/inject.py (roda no Windows)
4. instalar no iPhone               -> TrollStore / Sideloadly / jailbreak
```

O ponto 1 é o único que o Windows puro não faz: o Theos precisa de clang + SDK do iOS.
Duas saídas que funcionam de verdade — **A (GitHub Actions, recomendado)** e **B (WSL2)**.
O resto roda no Windows normal.

---

## A. Compilar no GitHub Actions (não instala nada no PC)

Roda num Mac da nuvem, de graça, e devolve `.deb` + `ffaim.dylib` prontos.

**A.1** Crie um repositório no GitHub (privado serve).

**A.2** Suba a pasta do projeto. O jeito mais rápido, no PowerShell:

```powershell
cd C:\Users\user\Desktop\DUMPER
git init
git add cheat tools .github
git commit -m "ffaim"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/ffaim.git
git push -u origin main
```

Sem git instalado: use o GitHub Desktop → *Add local repository* → *Publish*.

**A.3** No GitHub, aba **Actions** → workflow **build-ffaim** → **Run workflow**.

O `.github/workflows/build.yml` já faz tudo:

- clona `theos` + `theos/sdks`;
- `make clean package` → `cheat/packages/*.deb` (rota jailbreak);
- `cheat/build_dylib.sh` → `ffaim.dylib` + `libsubstrate.dylib` (rota sem jailbreak).

**A.4** Quando ficar verde, abra o run → **Artifacts** → baixe `ffaim-build.zip`.
Dentro: `ffaim.dylib`, `libsubstrate.dylib`, `*.deb`.

**A.5** Extraia em `C:\Users\user\Desktop\DUMPER\cheat\`. Vá para a seção **3**.

Se o build quebrar, o log do step mostra a linha exata do clang. As causas comuns estão na
tabela de problemas no fim.

---

## B. Compilar no PC via WSL2 + Theos

Theos em Linux é oficialmente suportado. É WSL2, não emulação — compila de verdade.

**B.1** Instale o WSL2 (PowerShell como admin):

```powershell
wsl --install -d Ubuntu
```

Reinicie, abra o Ubuntu, crie usuário e senha.

**B.2** Dependências:

```bash
sudo apt update
sudo apt install -y git make curl unzip dpkg-dev fakeroot libssl-dev libplist-utils
```

**B.3** Theos (instalador oficial — já traz toolchain e SDKs):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
```

Confirme que existe `~/theos/toolchain/linux/iphone/bin/clang++` e pelo menos uma pasta
`~/theos/sdks/iPhoneOS*.sdk`. Se faltar SDK:

```bash
git clone --depth 1 https://github.com/theos/sdks.git ~/theos/sdks
```

**B.4** Build. Compile numa pasta do Linux (em `/mnt/c` o Theos fica lento e reclama de permissão):

```bash
mkdir -p ~/ff && cp -r /mnt/c/Users/user/Desktop/DUMPER/cheat ~/ff/
cd ~/ff/cheat
export THEOS=~/theos
make clean package
./build_dylib.sh
```

**B.5** Copie o resultado de volta pro Windows:

```bash
cp ~/ff/cheat/ffaim.dylib ~/ff/cheat/libsubstrate.dylib /mnt/c/Users/user/Desktop/DUMPER/cheat/
cp ~/ff/cheat/packages/*.deb /mnt/c/Users/user/Desktop/DUMPER/cheat/ 2>/dev/null || true
```

Pronto — os arquivos estão na pasta `cheat\` do Windows.

**B.6 (opcional) `ldid` no WSL**, pra assinar sem Mac:

```bash
sudo apt install -y ldid
```

---

## C. Mac (se tiver)

```bash
xcode-select --install
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
cd cheat && make clean package && ./build_dylib.sh
```

---

## 3. Montar o .ipa no Windows

O `.app` já está extraído e com o AC patchado:

```
C:\Users\user\AppData\Local\Temp\ff_ipa\Payload\freefireth.app
```

Se o `TEMP` foi limpo, extraia de novo e patche:

```powershell
cd C:\Users\user\Desktop\DUMPER
mkdir "$env:TEMP\ff_ipa" -Force
tar -xf "FreeFire(IOS).ipa" -C "$env:TEMP\ff_ipa"
python tools\ffpatch.py --apply
python tools\ffpatch.py --verify
```

Agora injeta o tweak e monta o IPA:

```powershell
cd C:\Users\user\Desktop\DUMPER
python tools\inject.py `
  --app "$env:TEMP\ff_ipa\Payload\freefireth.app" `
  --dylib cheat\ffaim.dylib `
  --dylib cheat\libsubstrate.dylib `
  --out FreeFire_ffaim.ipa
```

O `inject.py` faz, sem toolchain nenhuma:

1. copia o `.app` pra uma pasta de trabalho (o original não é tocado);
2. copia os dylibs pra `Frameworks/`;
3. adiciona `LC_LOAD_DYLIB @executable_path/Frameworks/<nome>` no binário principal
   (o header tem 0x54F8 bytes livres — cada LC usa ~72);
4. zera o `LC_CODE_SIGNATURE`, apaga `_CodeSignature` e **salva os entitlements originais**
   em `FreeFire_ffaim.ipa.entitlements.plist`;
5. zipa `Payload/freefireth.app/...` → `FreeFire_ffaim.ipa`.

Saída esperada:

```
binario: freefireth (60430752 bytes)
injeta:
  copia ffaim.dylib -> Frameworks/ffaim.dylib
  LC_LOAD_DYLIB @executable_path/Frameworks/ffaim.dylib (72 bytes)
  copia libsubstrate.dylib -> Frameworks/libsubstrate.dylib
  LC_LOAD_DYLIB @executable_path/Frameworks/libsubstrate.dylib (78 bytes)
assinatura removida: LC_CODE_SIGNATURE 0x382FA90/0x171F10
entitlements salvos: ...\FreeFire_ffaim.ipa.entitlements.plist
ok: ...\FreeFire_ffaim.ipa
```

Se você trocar o nome do dylib, o `LC_LOAD_DYLIB` acompanha — os dois têm que bater, senão o
dyld aborta na abertura com `Library not loaded`.

---

## 4. Instalar no iPhone

### 4.1 TrollStore — melhor caminho (iOS 14.0–16.6.1, 17.0)

Não precisa de Apple ID, não expira, mantém os entitlements.

1. Mande o `FreeFire_ffaim.ipa` pro iPhone (AirDrop, iCloud, cabo).
2. Abra o **TrollStore** → `+` → escolha o `.ipa` → **Install**.
3. TrollStore assina o app e os dylibs aninhados na hora.

Se o app abrir e fechar na hora, o problema é assinatura de dylib aninhado — reinstale pelo
TrollStore (não por Filza) e veja o `Console`/`idevicesyslog` filtrando `ffaim`.

### 4.2 Sideloadly / AltStore — qualquer iOS, expira em 7 dias

1. Instale o **Sideloadly** no PC (`sideloadly.io`) e o **iTunes** (drivers da Apple).
2. Conecte o iPhone, arraste o `.ipa` pro Sideloadly.
3. Apple ID + senha de app (appleid.apple.com → *Senhas de app*).
4. **Start**. O Sideloadly reassina com o seu certificado e injeta entitlements padrão.

Free Apple ID: 7 dias, 3 apps. Conta paga: 1 ano.

### 4.3 Jailbreak — `.deb`

Dopamine (15–16), palera1n (checkm8), unc0ver (≤14.8), rootless ou rootful.

```sh
scp cheat/packages/*.deb root@IP_DO_IPHONE:/tmp/
ssh root@IP_DO_IPHONE 'dpkg -i /tmp/*.deb'
# rootless:
ssh root@IP_DO_IPHONE 'dpkg -i /tmp/*.deb && killall -9 freefireth 2>/dev/null || true'
```

Ou copie o `.deb` pro iPhone e instale pelo Sileo/Zebra.

Nessa rota o `.ipa` **não** precisa do `inject.py` — mas o app instalado **precisa** do AC
patchado. Se você instalou o IPA de outra fonte:

```sh
ldid -S /var/containers/Bundle/Application/*/freefireth.app/Frameworks/libac_sdk.dylib
```

E o patch em si (`ffpatch.py`) roda no PC sobre o `.app` extraído, ou no iPhone via Python
(`python3 ffpatch.py --in <caminho>`), se você tiver `python3` no aparelho.

### 4.4 Assinatura manual (jailbreak, sem dpkg)

```sh
unzip -o FreeFire_ffaim.ipa -d ipa_build
cd ipa_build/Payload
ldid -S"../../FreeFire_ffaim.ipa.entitlements.plist" freefireth
ldid -S freefireth.app/Frameworks/ffaim.dylib
ldid -S freefireth.app/Frameworks/libsubstrate.dylib
ldid -S freefireth.app/Frameworks/libac_sdk.dylib
```

`ldid -S` sem arquivo de entitlements assina sem eles — o app abre, mas login por Game Center /
keychain pode falhar. Use o `.entitlements.plist` que o `inject.py` salvou.

---

## 5. Ordem final (checklist)

```
[ ] ffaim.dylib + libsubstrate.dylib compilados        (A ou B ou C)
[ ] tools\ffpatch.py --verify  -> integridade: OK
[ ] tools\inject.py -> FreeFire_ffaim.ipa + entitlements.plist
[ ] instalar (TrollStore / Sideloadly / dpkg)
[ ] abrir o jogo -> 3 dedos, 3 toques -> painel aparece
[ ] ligar ESP -> caixas nos inimigos
[ ] ligar Aimbot -> mira puxa pro osso escolhido
```

---

## 6. Problemas comuns

| sintoma | causa | correção |
|---|---|---|
| `Library not loaded: @executable_path/Frameworks/ffaim.dylib` | dylib não copiado ou nome diferente do LC | confira `Frameworks/` e o `LC_LOAD_DYLIB` (`python tools/inject.py` imprime) |
| app abre e fecha em 1 s | dylib aninhado sem assinatura | `ldid -S` em cada dylib, ou reinstale pelo TrollStore |
| `make: *** No rule to make target` | `THEOS` não exportado | `export THEOS=~/theos` |
| `clang: error: invalid iOS deployment version` | SDK mais velho que `13.0` | clone `theos/sdks` (tem 16.5+) |
| `ld: framework not found UIKit` | SDK do iOS ausente | `git clone https://github.com/theos/sdks ~/theos/sdks` |
| painel não abre, jogo normal | gesto não pegou | toque com **3 dedos ao mesmo tempo**, 3 vezes, < 550 ms entre eles, sem arrastar |
| painel abre mas ESP vazio | `Camera::get_main` nulo ou snapshot velho | veja `NSLog` `[ffaim] base=` no Console; sem base o hook não instalou |
| mira volta sozinha | jogo reescreve `0x114` depois do `LateUpdate` | hooka `Player::UpdateAiming` `0x9269AC` (ver README) |
| conta banida / flag no servidor | `libac_sdk.dylib` não patchado | `python tools/ffpatch.py --apply` e `--verify` |
| `entitlements.plist` não gerado | IPA já sem assinatura | assine com `ldid -S` puro; login pode limitar |

---

## 7. O que cada arquivo faz

| arquivo | roda onde | função |
|---|---|---|
| `cheat/ffaim.mm` | iOS (in-game) | hook, aimbot, snapshot do ESP |
| `cheat/ffpanel.mm` | iOS (in-game) | janela, painel, desenho, gesto |
| `cheat/Makefile` | WSL/Actions/Mac | `.deb` |
| `cheat/build_dylib.sh` | WSL/Actions/Mac | `ffaim.dylib` pra injetar |
| `tools/ffpatch.py` | PC | neutraliza as 7 checagens do AC + regrava o CRC |
| `tools/inject.py` | PC | injeta dylibs no `.app` e monta o `.ipa` |
| `.github/workflows/build.yml` | GitHub | compila tudo na nuvem |

## 8. Nota sobre este IPA

O `Info.plist` diz `com.privateproject.ff2018.v128`, mas os entitlements originais trazem
`application-identifier = 98573T3W6L.com.dts.freefireth` — é um repack com bundle id trocado.
É justamente esse id que a checagem `bundle_id` do AC (`0x6990`) confere contra
`com.privateproject.ff2018`, e por isso ela foi patchada pra retornar 1.

O binário está **descriptografado** (`cryptid 0`), então reassinar com `ldid`/TrollStore funciona;
não precisa de `dumpdecrypted` nem de FairPlay.

Não compilei nem rodei o tweak nesta máquina — sem clang/Theos aqui. O patch do AC e o
`inject.py` esses foram executados e verificados neste IPA.
