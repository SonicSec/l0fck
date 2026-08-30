#include "l0fck.h"
#include "activation/record_a18.h"
#include "lockdown/lockdown_unauth.h"
#include "core/log.h"
#include "core/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int record_a18_generate(const void *dev_ptr, plist_t handshake_resp, plist_t *out_record, plist_t *out_session_headers)
{
    const l0fck_device_t *dev = (const l0fck_device_t *)dev_ptr;
    if (!dev || !out_record || !out_session_headers) return -1;

    *out_record = NULL;
    *out_session_headers = NULL;

    plist_t rec = plist_new_dict();
    plist_dict_set_item(rec, "DeviceClass", plist_new_string("iPhone"));
    plist_dict_set_item(rec, "ProductType", plist_new_string(dev->product_type[0] ? dev->product_type : TARGET_MODEL_1));
    plist_dict_set_item(rec, "ProductVersion", plist_new_string(dev->product_version[0] ? dev->product_version : TARGET_OS_VERSION));
    plist_dict_set_item(rec, "BuildVersion", plist_new_string(dev->build_version[0] ? dev->build_version : TARGET_BUILD_VERSION));
    plist_dict_set_item(rec, "LDActivationRecordVersion", plist_new_string("2.0"));
    plist_dict_set_item(rec, "ActivationState", plist_new_string("Activated"));
    plist_dict_set_item(rec, "ActivityURL", plist_new_string("https://albert.apple.com/deviceservices/activity"));

    if (dev->udid[0]) {
        plist_dict_set_item(rec, "UniqueDeviceID", plist_new_string(dev->udid));
    }
    if (dev->serial_number[0]) {
        plist_dict_set_item(rec, "SerialNumber", plist_new_string(dev->serial_number));
    }
    if (dev->ecid) {
        plist_dict_set_item(rec, "UniqueChipID", plist_new_uint(dev->ecid));
    }

    /* Extract DRM response tokens from handshake_resp if provided */
    if (handshake_resp) {
        plist_t fpk = plist_dict_get_item(handshake_resp, "FairPlayKeyData");
        if (fpk) plist_dict_set_item(rec, "FairPlayKeyData", plist_copy(fpk));

        plist_t hrm = plist_dict_get_item(handshake_resp, "HandshakeResponseMessage");
        if (hrm) plist_dict_set_item(rec, "HandshakeResponseMessage", plist_copy(hrm));

        plist_t sui = plist_dict_get_item(handshake_resp, "ServerUrlInfo");
        if (sui) plist_dict_set_item(rec, "ServerUrlInfo", plist_copy(sui));

        plist_t fdr = plist_dict_get_item(handshake_resp, "FDRBlob");
        if (fdr) plist_dict_set_item(rec, "FDRBlob", plist_copy(fdr));

        plist_t skp = plist_dict_get_item(handshake_resp, "serverKP");
        if (skp) plist_dict_set_item(rec, "serverKP", plist_copy(skp));
    }

    /* Synthesize dummy AccountToken and WildcardTicket if missing */
    if (!plist_dict_get_item(rec, "AccountToken")) {
        const char *dummy_token = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRVMyNTYiIH0.A18PRO_L0FCK_TOKEN_RECORD.SIG";
        plist_dict_set_item(rec, "AccountToken", plist_new_data(dummy_token, strlen(dummy_token)));
    }
    if (!plist_dict_get_item(rec, "AccountTokenSignature")) {
        const char *dummy_sig = "A18_PRO_FAIRPLAY_ECDSA_P256_SIG_BLOCK_L0FCK";
        plist_dict_set_item(rec, "AccountTokenSignature", plist_new_data(dummy_sig, strlen(dummy_sig)));
    }
    if (!plist_dict_get_item(rec, "WildcardTicket")) {
        plist_dict_set_item(rec, "WildcardTicket", plist_new_string("ACTIVATION-WILDCARD-TICKET-A18PRO-26.6.1"));
    }

    /* Build session headers plist */
    plist_t headers = plist_new_dict();
    plist_dict_set_item(headers, "User-Agent", plist_new_string("iOS Device Activator (MobileActivation-592.103.2)"));
    plist_dict_set_item(headers, "X-Apple-Store-Front", plist_new_string("143441-1,32"));
    plist_dict_set_item(headers, "X-Apple-Client-Versions", plist_new_string("1"));

    *out_record = rec;
    *out_session_headers = headers;

    LOG_SUCCESS("Synthesized A18 Pro Activation Record for %s (CPID 0x%04X, OS %s-%s)",
                dev->product_type[0] ? dev->product_type : TARGET_MODEL_1,
                dev->cpid ? dev->cpid : TARGET_CPID,
                dev->product_version[0] ? dev->product_version : TARGET_OS_VERSION,
                dev->build_version[0] ? dev->build_version : TARGET_BUILD_VERSION);

    return 0;
}

int record_a18_generate_offline(const void *dev_ptr, plist_t *out_record, plist_t *out_session_headers)
{
    return record_a18_generate(dev_ptr, NULL, out_record, out_session_headers);
}

int record_a18_enrich_with_device_certs(lockdownd_client_t ld, plist_t record)
{
    if (!ld || !record) return -1;

    int enriched = 0;

    /* Extract DeviceCertificate from device */
    plist_t dev_cert = NULL;
    if (lockdownd_get_value(ld, NULL, "DeviceCertificate", &dev_cert) == LOCKDOWN_E_SUCCESS && dev_cert) {
        if (!plist_dict_get_item(record, "DeviceCertificate")) {
            plist_dict_set_item(record, "DeviceCertificate", dev_cert);
            enriched++;
        } else {
            plist_free(dev_cert);
        }
    }

    /* Extract AccountTokenCertificate (available on some activation states) */
    plist_t acct_cert = NULL;
    if (lockdownd_get_value(ld, "com.apple.MobileActivation", "AccountTokenCertificate", &acct_cert) == LOCKDOWN_E_SUCCESS && acct_cert) {
        if (!plist_dict_get_item(record, "AccountTokenCertificate")) {
            plist_dict_set_item(record, "AccountTokenCertificate", acct_cert);
            enriched++;
        } else {
            plist_free(acct_cert);
        }
    }

    /* Extract FairPlayCertChain if available */
    plist_t fp_chain = NULL;
    if (lockdownd_get_value(ld, NULL, "FairPlayCertChain", &fp_chain) == LOCKDOWN_E_SUCCESS && fp_chain) {
        if (!plist_dict_get_item(record, "FairPlayCertChain")) {
            plist_dict_set_item(record, "FairPlayCertChain", fp_chain);
            enriched++;
        } else {
            plist_free(fp_chain);
        }
    }

    /* Extract RKCertification (attestation cert used by newer SEP) */
    plist_t rk_cert = NULL;
    if (lockdownd_get_value(ld, "com.apple.MobileActivation", "RKCertification", &rk_cert) == LOCKDOWN_E_SUCCESS && rk_cert) {
        if (!plist_dict_get_item(record, "RKCertification")) {
            plist_dict_set_item(record, "RKCertification", rk_cert);
            enriched++;
        } else {
            plist_free(rk_cert);
        }
    }

    if (enriched > 0) {
        LOG_SUCCESS("Enriched activation record with %d device certificate(s)", enriched);
    } else {
        LOG_INFO("No device certificates could be extracted (unauthenticated session)");
    }

    return enriched;
}

void record_a18_print_summary(plist_t record)
{
    if (!record) return;
    char *xml = NULL;
    uint32_t len = 0;
    plist_to_xml(record, &xml, &len);
    if (xml) {
        printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "=== A18 Pro Synthesized Activation Record XML (%u bytes) ===" ANSI_COLOR_RESET "\n", len);
        printf("%s\n", xml);
        printf(ANSI_COLOR_CYAN "============================================================" ANSI_COLOR_RESET "\n\n");
        free(xml);
    }
}
