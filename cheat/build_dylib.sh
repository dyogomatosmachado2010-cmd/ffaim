#!/bin/sh
# build_dylib.sh - compila ffaim.dylib pra injetar no .app (rota sem jailbreak)
#
# funciona em macOS (Xcode), WSL/Linux (toolchain do Theos).
# o .deb do `make package` continua sendo a rota com jailbreak.
set -eu

cd "$(dirname "$0")"
THEOS=${THEOS:-$HOME/theos}

# ---- clang ----
if [ -x "$THEOS/toolchain/linux/iphone/bin/clang++" ]; then
    CXX="$THEOS/toolchain/linux/iphone/bin/clang++"
elif [ -x "$THEOS/toolchain/linux/iphonesign/bin/clang++" ]; then
    CXX="$THEOS/toolchain/linux/iphonesign/bin/clang++"
elif command -v xcrun >/dev/null 2>&1; then
    CXX="$(xcrun -f clang++)"
else
    CXX=clang++
fi

# ---- SDK ----
SDK=""
for d in "$THEOS"/sdks/iPhoneOS*.sdk; do
    [ -d "$d" ] && SDK="$d"
done
if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
    SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
fi
[ -n "$SDK" ] || { echo "sem SDK do iOS: rode 'make' uma vez ou clone o theos/sdks"; exit 1; }

echo "clang : $CXX"
echo "sdk   : $SDK"

# libsubstrate pra linkar (o mesmo arquivo tem que ir junto no Frameworks/)
SUB="-L$THEOS/lib -lsubstrate"
[ -f "$THEOS/lib/libsubstrate.dylib" ] || { echo "falta $THEOS/lib/libsubstrate.dylib"; exit 1; }

"$CXX" \
    -arch arm64 -arch arm64e \
    -isysroot "$SDK" -miphoneos-version-min=13.0 \
    -fobjc-arc -O2 -std=c++17 -fvisibility=hidden \
    -dynamiclib \
    -framework UIKit -framework QuartzCore -framework Foundation \
    $SUB \
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
