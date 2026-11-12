TARGET = iphone:clang:latest:13.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = freefireth

TWEAK_NAME = ffaim
ffaim_FILES = ffaim.mm ffpanel.mm
ffaim_FRAMEWORKS = UIKit QuartzCore Foundation
ffaim_CFLAGS = -fobjc-arc -O2 -std=c++17 -Wno-unused-function -Wno-unused-variable
ffaim_LIBRARIES = substrate

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
