TARGET = iphone:clang:latest:13.0
ARCHS = arm64
DEBUG = 0
FINALPACKAGE = 1
INSTALL_TARGET_PROCESSES = freefireth

TWEAK_NAME = ffaim
ffaim_FILES = ffaim.mm ffpanel.mm ffhook.mm ffac.mm
ffaim_FRAMEWORKS = UIKit QuartzCore CoreGraphics Foundation Security
ffaim_CFLAGS = -fobjc-arc -O2 -std=c++17 -fvisibility=hidden -ffunction-sections -fdata-sections -Wno-unused-function -Wno-unused-variable -Wno-deprecated-declarations
ffaim_LDFLAGS = -Wl,-x -Wl,-dead_strip

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
