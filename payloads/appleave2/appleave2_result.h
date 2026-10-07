#ifndef APPLEAVE2_RESULT_H
#define APPLEAVE2_RESULT_H

#include <stdint.h>
#include <stdbool.h>

#define L0FCK_DEVICE_AVE2_RESULT "/var/mobile/Media/.l0fck/appleave2_result.plist"
#define L0FCK_AFC_AVE2_RESULT_PATH "/.l0fck/appleave2_result.plist"
#define L0FCK_AVE2_APP_BUNDLE "appleave2_payload.app"
#define L0FCK_AVE2_MEDIA_SUBDIR ".l0fck"

#define AVE_KEY_DRIVER_OPEN     "driver_open"
#define AVE_KEY_CLIENT_TYPE     "client_type"
#define AVE_KEY_RACE_ATTEMPTS   "race_attempts"
#define AVE_KEY_DESYNC_DETECTED "desync_detected"
#define AVE_KEY_CORRUPTED_PTR   "corrupted_ptr"
#define AVE_KEY_KBASE           "kbase"
#define AVE_KEY_KRW_READY       "krw_ready"
#define AVE_KEY_ERROR_CODE      "error_code"
#define AVE_KEY_ERROR_MESSAGE   "error_message"

typedef struct {
    bool driver_open;
    uint32_t client_type;
    uint32_t race_attempts;
    bool desync_detected;
    uint64_t corrupted_ptr;
    uint64_t kbase;
    bool krw_ready;
    int32_t error_code;
    char error_message[256];
    bool valid;
} appleave2_result_t;

typedef appleave2_result_t appleave2_device_result_t;

#endif /* APPLEAVE2_RESULT_H */
