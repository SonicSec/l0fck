#include "l0fck.h"
#include "core/target.h"
#include "core/log.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t cpid;
    const char *name;
} chip_info_entry_t;

static const chip_info_entry_t CHIP_TABLE[] = {
    { 0x8140, "Apple A18 Pro (T8140)" },
    { 0x8130, "Apple A17 Pro (T8130)" },
    { 0x8120, "Apple A16 Bionic (T8120)" },
    { 0x8110, "Apple A15 Bionic (T8110)" },
    { 0x8101, "Apple A14 Bionic (T8101)" },
    { 0x8030, "Apple A13 Bionic (T8030)" },
    { 0x8020, "Apple A12 Bionic (T8020)" },
    { 0x8015, "Apple A11 Bionic (T8015)" },
    { 0x8010, "Apple A10 Fusion (T8010)" },
    { 0x8000, "Apple A9 (S8000)" },
    { 0x8003, "Apple A9 (S8003)" },
    { 0x7000, "Apple A8 (T7000)" },
    { 0x7001, "Apple A8X (T7001)" },
    { 0x8960, "Apple A7 (S5L8960X)" },
    { 0x0022, "Apple Port DFU Subsystem (0x0022)" }
};
#define CHIP_TABLE_SIZE (sizeof(CHIP_TABLE) / sizeof(CHIP_TABLE[0]))

typedef struct {
    const char *product_type;
    const char *marketing_name;
} product_info_entry_t;

static const product_info_entry_t PRODUCT_TABLE[] = {
    { "iPhone17,1", "iPhone 16 Pro" },
    { "iPhone17,2", "iPhone 16 Pro Max" },
    { "iPhone17,3", "iPhone 16" },
    { "iPhone17,4", "iPhone 16 Plus" },
    { "iPhone16,1", "iPhone 15 Pro" },
    { "iPhone16,2", "iPhone 15 Pro Max" },
    { "iPhone15,2", "iPhone 14 Pro" },
    { "iPhone15,3", "iPhone 14 Pro Max" },
    { "iPhone14,2", "iPhone 13 Pro" },
    { "iPhone14,3", "iPhone 13 Pro Max" }
};
#define PRODUCT_TABLE_SIZE (sizeof(PRODUCT_TABLE) / sizeof(PRODUCT_TABLE[0]))

const char *target_cpid_to_name(uint32_t cpid)
{
    for (size_t i = 0; i < CHIP_TABLE_SIZE; i++) {
        if (CHIP_TABLE[i].cpid == cpid) {
            return CHIP_TABLE[i].name;
        }
    }
    return "Unknown Apple Silicon SoC";
}

const char *target_product_to_marketing(const char *product_type)
{
    if (!product_type || !*product_type) return "Unknown iPhone";
    for (size_t i = 0; i < PRODUCT_TABLE_SIZE; i++) {
        if (strcmp(PRODUCT_TABLE[i].product_type, product_type) == 0) {
            return PRODUCT_TABLE[i].marketing_name;
        }
    }
    return product_type;
}

bool target_is_a18_pro(uint32_t cpid, const char *product_type)
{
    if (cpid == TARGET_CPID) return true;
    if (product_type && (strcmp(product_type, TARGET_MODEL_1) == 0 ||
                         strcmp(product_type, TARGET_MODEL_2) == 0)) {
        return true;
    }
    return false;
}

bool target_is_ios_26_6_1(const char *product_version, const char *build_version)
{
    if (product_version && strcmp(product_version, TARGET_OS_VERSION) == 0) return true;
    if (build_version && strcmp(build_version, TARGET_BUILD_VERSION) == 0) return true;
    return false;
}

target_validation_status_t target_validate_device(const void *dev_ptr)
{
    const l0fck_device_t *dev = (const l0fck_device_t *)dev_ptr;
    if (!dev) return TARGET_ERR_NOT_DETECTED;

    if (dev->cpid != 0 && dev->cpid != TARGET_CPID) {
        return TARGET_ERR_WRONG_SOC;
    }

    if (dev->product_type[0] != '\0') {
        if (strcmp(dev->product_type, TARGET_MODEL_1) != 0 &&
            strcmp(dev->product_type, TARGET_MODEL_2) != 0) {
            return TARGET_ERR_WRONG_SOC;
        }
    }

    if (dev->product_version[0] != '\0') {
        if (strcmp(dev->product_version, TARGET_OS_VERSION) != 0) {
            return TARGET_ERR_WRONG_OS;
        }
    }

    if (dev->build_version[0] != '\0') {
        if (strcmp(dev->build_version, TARGET_BUILD_VERSION) != 0) {
            return TARGET_ERR_WRONG_BUILD;
        }
    }

    if (dev->cpid == 0 && dev->product_type[0] == '\0') {
        return TARGET_ERR_NOT_DETECTED;
    }

    return TARGET_VALID;
}

void target_print_device_diagnostics(const void *dev_ptr)
{
    const l0fck_device_t *dev = (const l0fck_device_t *)dev_ptr;
    if (!dev) return;

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "======================== DEVICE DIAGNOSTICS ========================" ANSI_COLOR_RESET "\n");
    printf("  " ANSI_COLOR_BOLD "Device Name:         " ANSI_COLOR_RESET "%s\n", dev->device_name[0] ? dev->device_name : "(pre-setup)");
    printf("  " ANSI_COLOR_BOLD "Model Identifier:    " ANSI_COLOR_RESET "%s (%s)\n",
           dev->product_type[0] ? dev->product_type : "N/A",
           target_product_to_marketing(dev->product_type));
    printf("  " ANSI_COLOR_BOLD "Hardware Model:      " ANSI_COLOR_RESET "%s\n", dev->hardware_model[0] ? dev->hardware_model : "N/A");
    printf("  " ANSI_COLOR_BOLD "Installed OS:        " ANSI_COLOR_RESET "%s (Build %s)\n",
           dev->product_version[0] ? dev->product_version : "N/A",
           dev->build_version[0] ? dev->build_version : "N/A");
    printf("  " ANSI_COLOR_BOLD "SoC Architecture:    " ANSI_COLOR_RESET "CPID: 0x%04X [%s]\n",
           dev->cpid, target_cpid_to_name(dev->cpid));
    printf("  " ANSI_COLOR_BOLD "Unique Device ID:    " ANSI_COLOR_RESET "%s\n", dev->udid[0] ? dev->udid : "N/A");
    printf("  " ANSI_COLOR_BOLD "Serial Number:       " ANSI_COLOR_RESET "%s\n", dev->serial_number[0] ? dev->serial_number : "N/A");
    if (dev->ecid) {
        printf("  " ANSI_COLOR_BOLD "ECID:                " ANSI_COLOR_RESET "0x%016llX\n", (unsigned long long)dev->ecid);
    }
    printf("  " ANSI_COLOR_BOLD "Activation State:    " ANSI_COLOR_RESET "%s%s%s\n",
           strcmp(dev->activation_state, "Activated") == 0 ? ANSI_COLOR_GREEN : ANSI_COLOR_YELLOW,
           dev->activation_state[0] ? dev->activation_state : "Unactivated",
           ANSI_COLOR_RESET);
    if (dev->wifi_address[0]) {
        printf("  " ANSI_COLOR_BOLD "Wi-Fi MAC:           " ANSI_COLOR_RESET "%s\n", dev->wifi_address);
    }
    if (dev->bluetooth_address[0]) {
        printf("  " ANSI_COLOR_BOLD "Bluetooth MAC:       " ANSI_COLOR_RESET "%s\n", dev->bluetooth_address);
    }

    target_validation_status_t st = target_validate_device(dev);
    printf("  " ANSI_COLOR_BOLD "Target Compatibility:" ANSI_COLOR_RESET " ");
    if (st == TARGET_VALID) {
        printf(ANSI_COLOR_GREEN ANSI_COLOR_BOLD "STRICT TARGET MATCH [iPhone 16 Pro / A18 Pro / iOS 26.6.1]" ANSI_COLOR_RESET "\n");
    } else if (st == TARGET_ERR_WRONG_SOC) {
        printf(ANSI_COLOR_RED ANSI_COLOR_BOLD "MISMATCH (SoC is %s, expected A18 Pro CPID 0x8140)" ANSI_COLOR_RESET "\n",
               target_cpid_to_name(dev->cpid));
    } else if (st == TARGET_ERR_WRONG_OS || st == TARGET_ERR_WRONG_BUILD) {
        printf(ANSI_COLOR_YELLOW ANSI_COLOR_BOLD "MISMATCH (OS %s-%s, expected iOS 26.6.1-23G83)" ANSI_COLOR_RESET "\n",
               dev->product_version, dev->build_version);
    } else {
        printf(ANSI_COLOR_YELLOW "UNVALIDATED / PARTIAL DETECTION" ANSI_COLOR_RESET "\n");
    }
    printf(ANSI_COLOR_CYAN "====================================================================" ANSI_COLOR_RESET "\n\n");
}

void target_print_banner(void)
{
    printf(ANSI_COLOR_CYAN ANSI_COLOR_BOLD);
    printf("  _   ___   __      _    \n");
    printf(" | | / _ \\ / _| ___| | __\n");
    printf(" | || | | | |_ / __| |/ /\n");
    printf(" | || |_| |  _| (__|   < \n");
    printf(" |_(_)___/|_|  \\___|_|\\_\\\n");
    printf(" iPhone 16 Pro / A18 Pro / iOS 26.6.1 Security Research Suite\n");
    printf(" Version %s [%s]\n", L0FCK_VERSION, L0FCK_CODENAME);
    printf(ANSI_COLOR_RESET "\n");
}
