#!/bin/sh
# build_dylib.sh - compila ffaim.dylib pra injetar no .app (rota sem jailbreak)
#
# funciona em Linux/WSL (toolchain do Theos) e em macOS (Xcode).
# o .deb do `make package` continua sendo a rota com jailbreak.
#
#   ARCH=arm64        (default; o binario do jogo e arm64)
#   ARCH=arm64e       (se o app for arm64e)
#
# nao linka contra substrate: ffhook.mm resolve substrate em runtime via dlopen
# e, se nao existir, usa hook inline proprio. o dylib roda em jailbreak e em
# TrollStore/sideload sem depender de nada instalado.
set -eu

cd "$(dirname "$0")"
THEOS=${THEOS:-$HOME/theos}
ARCH=${ARCH:-arm64}

# ---- clang ----
CXX=""
for c in "$THEOS/toolchain/linux/iphone/bin/clang++" \
         "$THEOS/toolchain/linux/iphonesign/bin/clang++"; do
    [ -x "$c" ] && CXX="$c" && break
done
if [ -z "$CXX" ]; then
    if command -v xcrun >/dev/null 2>&1; then
        CXX="$(xcrun -f clang++)"
    else
        CXX=clang++
    fi
fi

# ---- linker do toolchain (Linux precisa apontar o ld64) ----
LD64=""
[ -x "$THEOS/toolchain/linux/iphone/bin/ld64" ] && LD64="-fuse-ld=$THEOS/toolchain/linux/iphone/bin/ld64"

# ---- SDK ----
SDK=""
for d in "$THEOS"/sdks/iPhoneOS*.sdk; do
    [ -d "$d" ] && SDK="$d"
done
if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
    SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
fi
[ -n "$SDK" ] || { echo "sem SDK do iOS: rode o install-theos ou clone o theos/sdks"; exit 1; }

echo "clang : $CXX"
echo "sdk   : $SDK"
echo "arch  : $ARCH"

"$CXX" $LD64 \
    -target "$ARCH-apple-ios13.0" \
    -isysroot "$SDK" \
    -fobjc-arc -O2 -std=c++17 -fvisibility=hidden \
    -ffunction-sections -fdata-sections -Wno-deprecated-declarations \
    -dynamiclib \
    -framework UIKit -framework QuartzCore -framework CoreGraphics \
    -framework Foundation -framework Security \
    ffaim.mm ffpanel.mm ffhook.mm ffac.mm \
    -Wl,-x -Wl,-dead_strip \
    -install_name @executable_path/Frameworks/ffaim.dylib \
    -o ffaim.dylib

# ---- assinatura ad-hoc (obrigatoria: Mach-O sem assinatura quebra o install) ----
LDID=""
for c in "$THEOS/toolchain/linux/iphone/bin/ldid" "$THEOS/toolchain/linux/iphone/bin/ldid2"; do
    [ -x "$c" ] && LDID="$c" && break
done
if [ -z "$LDID" ] && command -v ldid >/dev/null 2>&1; then
    LDID="$(command -v ldid)"
fi

if [ -n "$LDID" ]; then
    "$LDID" -S ffaim.dylib
    echo "assinado: $LDID -S ffaim.dylib"
else
    echo "AVISO: sem ldid no toolchain - o inject.py assina no PC (tools/ldid.py)"
fi

echo ""
echo "gerado: $(pwd)/ffaim.dylib"
echo ""
echo "agora, no PC:"
echo "  python tools/inject.py --app <freefireth.app> \\"
echo "      --dylib cheat/ffaim.dylib --out FreeFire_ffaim.ipa"
