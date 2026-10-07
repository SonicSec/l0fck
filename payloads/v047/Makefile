# l0fck on-device V-047 payload build
#
# Usage:
#   make                    # build for connected host (macosx for lab, iphoneos for device)
#   make SDK=iphoneos       # cross-compile iOS arm64 app bundle
#   make SDK=macosx         # macOS lab binary + app bundle
#   make clean

SDK ?= macosx
PAYLOAD_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
L0FCK_ROOT := $(abspath $(PAYLOAD_DIR)/../..)

APP_NAME := v047_payload
APP_BUNDLE := $(APP_NAME).app
BINARY := $(APP_BUNDLE)/$(APP_NAME)
BUILD_DIR := $(PAYLOAD_DIR)/build

ifeq ($(SDK),iphoneos)
  CC := xcrun -sdk iphoneos clang
  TARGET_FLAGS := -arch arm64 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path)
  DEPLOY_TARGET := -miphoneos-version-min=18.0
else
  CC := xcrun -sdk macosx clang
  TARGET_FLAGS := -arch arm64 -isysroot $(shell xcrun --sdk macosx --show-sdk-path)
  DEPLOY_TARGET := -mmacosx-version-min=15.0
endif

CFLAGS := -Wall -Wextra -O2 -std=c11 -fobjc-arc $(TARGET_FLAGS) $(DEPLOY_TARGET)
FRAMEWORKS := -framework Foundation -framework IOKit -framework CoreFoundation

.PHONY: all clean bundle

all: bundle

bundle: $(BUILD_DIR)/$(BINARY)
	@echo "[+] Built $(BUILD_DIR)/$(APP_BUNDLE) (SDK=$(SDK))"

$(BUILD_DIR)/$(APP_BUNDLE):
	mkdir -p $(BUILD_DIR)/$(APP_BUNDLE)
	cp $(PAYLOAD_DIR)/Info.plist $(BUILD_DIR)/$(APP_BUNDLE)/

$(BUILD_DIR)/$(BINARY): $(PAYLOAD_DIR)/v047_payload.m $(PAYLOAD_DIR)/v047_result.h | $(BUILD_DIR)/$(APP_BUNDLE)
	$(CC) $(CFLAGS) $(FRAMEWORKS) \
		-I$(PAYLOAD_DIR) \
		-I$(L0FCK_ROOT)/include \
		-o $(BUILD_DIR)/$(BINARY) \
		$(PAYLOAD_DIR)/v047_payload.m

clean:
	rm -rf $(BUILD_DIR)
