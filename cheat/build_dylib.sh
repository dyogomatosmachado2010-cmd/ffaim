#!/bin/sh
# build_dylib.sh - compila ffaim.dylib pra injetar no .app (rota sem jailbreak)
#
# funciona em Linux/WSL (toolchain do Theos) e em macOS (Xcode).
# o .deb do `make package` continua sendo a rota com jailbreak.
#
#   ARCH=arm64        (default; o binario do jogo e arm64)
#   ARCH=arm64e       (se o app for arm64e)
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

# ---- libsubstrate (vai junto no Frameworks/) ----
[ -f "$THEOS/lib/libsubstrate.dylib" ] || { echo "falta $THEOS/lib/libsubstrate.dylib"; exit 1; }

echo "clang : $CXX"
echo "sdk   : $SDK"
echo "arch  : $ARCH"

"$CXX" $LD64 \
    -target "$ARCH-apple-ios13.0" \
    -isysroot "$SDK" \
    -fobjc-arc -O2 -std=c++17 -fvisibility=hidden \
    -dynamiclib \
    -framework UIKit -framework QuartzCore -framework Foundation \
    -L"$THEOS/lib" -lsubstrate \
    ffaim.mm ffpanel.mm \
    -install_name @executable_path/Frameworks/ffaim.dylib \
    -o ffaim.dylib

cp "$THEOS/lib/libsubstrate.dylib" ./libsubstrate.dylib

echo ""
echo "gerado: $(pwd)/ffaim.dylib"
echo "        $(pwd)/libsubstrate.dylib"
echo ""
echo "agora, no PC:"
echo "  python tools/inject.py --app <freefireth.app> \\"
echo "      --dylib cheat/ffaim.dylib --dylib cheat/libsubstrate.dylib \\"
echo "      --out FreeFire_ffaim.ipa"
