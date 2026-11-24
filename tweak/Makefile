TARGET := iphone:clang:16.5:16.5
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = gate
gate_FILES = gate.m
gate_FRAMEWORKS = UIKit Foundation Security
gate_CFLAGS = -fobjc-arc -fmodules -Wno-deprecated-declarations
gate_LDFLAGS = -undefined dynamic_lookup

include $(THEOS_MAKE_PATH)/library.mk
