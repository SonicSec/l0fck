#ifndef CORE_TARGET_H
#define CORE_TARGET_H

#include <stdint.h>
#include <stdbool.h>

typedef struct l0fck_device_s l0fck_device_t;

typedef enum {
    TARGET_VALID = 0,
    TARGET_WARN_NON_PRO_A18,
    TARGET_ERR_WRONG_SOC,
    TARGET_ERR_WRONG_OS,
    TARGET_ERR_WRONG_BUILD,
    TARGET_ERR_NOT_DETECTED
} target_validation_status_t;

const char *target_cpid_to_name(uint32_t cpid);
const char *target_product_to_marketing(const char *product_type);
bool target_is_a18_pro(uint32_t cpid, const char *product_type);
bool target_is_ios_26_6_1(const char *product_version, const char *build_version);
target_validation_status_t target_validate_device(const void *dev_ptr);
void target_print_device_diagnostics(const void *dev_ptr);
void target_print_banner(void);

#endif /* CORE_TARGET_H */
