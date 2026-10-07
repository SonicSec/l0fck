# l0fck AppleAVE2 (CVE-2026-84607) on-device payload
#
# Strictly targets iOS (iphoneos SDK, arm64/arm64e)
# No macOS host testing or kernel execution.

SDK ?= iphoneos
PAYLOAD_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
L0FCK_ROOT := $(abspath $(PAYLOAD_DIR)/../..)

APP_NAME := appleave2_payload
APP_BUNDLE := $(APP_NAME).app
BINARY := $(APP_BUNDLE)/$(APP_NAME)
BUILD_DIR := $(PAYLOAD_DIR)/build

CC := xcrun --sdk iphoneos clang
SDK_PATH := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
TARGET_FLAGS := -arch arm64 -arch arm64e -isysroot $(SDK_PATH)
DEPLOY_TARGET := -miphoneos-version-min=17.0

CFLAGS := -Wall -Wextra -O2 -std=c11 -fobjc-arc $(TARGET_FLAGS) $(DEPLOY_TARGET)
FRAMEWORKS := -framework Foundation -framework IOKit -framework CoreFoundation

.PHONY: all clean bundle check-sdk

all: check-sdk bundle

check-sdk:
	@if [ -z "$(SDK_PATH)" ]; then \
		echo "[-] Error: iphoneos SDK not found. Install Xcode with iOS support to build on-device payload."; \
		exit 1; \
	fi

bundle: $(BUILD_DIR)/$(BINARY)
	@echo "[+] Built $(BUILD_DIR)/$(APP_BUNDLE) (SDK=$(SDK))"

$(BUILD_DIR)/$(APP_BUNDLE):
	mkdir -p $(BUILD_DIR)/$(APP_BUNDLE)
	cp $(PAYLOAD_DIR)/Info.plist $(BUILD_DIR)/$(APP_BUNDLE)/

$(BUILD_DIR)/$(BINARY): $(PAYLOAD_DIR)/appleave2_payload.m $(PAYLOAD_DIR)/appleave2_core.c \
		$(PAYLOAD_DIR)/appleave2_core.h $(PAYLOAD_DIR)/appleave2_result.h | $(BUILD_DIR)/$(APP_BUNDLE)
	$(CC) $(CFLAGS) $(FRAMEWORKS) \
		-I$(PAYLOAD_DIR) \
		-I$(L0FCK_ROOT)/include \
		-o $(BUILD_DIR)/$(BINARY) \
		$(PAYLOAD_DIR)/appleave2_core.c \
		$(PAYLOAD_DIR)/appleave2_payload.m
	@if which codesign >/dev/null 2>&1; then \
		codesign -s - --force --entitlements $(PAYLOAD_DIR)/entitlements.plist $(BUILD_DIR)/$(BINARY); \
	fi

clean:
	rm -rf $(BUILD_DIR)
