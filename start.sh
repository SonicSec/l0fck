#!/usr/bin/env bash
#
# start.sh - Interactive Terminal Interface for l0fck
# iPhone 16 Pro / A18 Pro / iOS 26.6.1 Dedicated Security Research Suite
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Color Codes
CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
MAGENTA="\033[1;35m"
BOLD="\033[1m"
RESET="\033[0m"

# ---------------------------------------------------------------------------
# Banner & UI helpers
# ---------------------------------------------------------------------------

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  _   ___   __      _    "
    echo " | | / _ \\ / _| ___| | __"
    echo " | || | | | |_ / __| |/ /"
    echo " | || |_| |  _| (__|   < "
    echo " |_(_)___/|_|  \\___|_|\\_\\"
    echo " iPhone 16 Pro / A18 Pro / iOS 26.6.1 Security Research Suite"
    echo " Version 1.0.0 [A18Pro-Titan]"
    echo -e "${RESET}"
    echo -e "${BOLD}Target Hardware:${RESET}  Apple A18 Pro (CPID 0x8140, iPhone17,1 / iPhone17,2)"
    echo -e "${BOLD}Target Firmware:${RESET}  iOS 26.6.1 (Build 23G83)"
    echo "----------------------------------------------------------------------"
}

prompt_yes_no() {
    local prompt="$1"
    local answer
    echo -ne "${YELLOW}${prompt} [Y/n]: ${RESET}"
    read -r answer
    [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
}

press_enter() {
    echo ""
    echo -e "${YELLOW}Press [Enter] to return to the menu...${RESET}"
    read -r
}

show_confirmation() {
    local opt_num="$1"
    local title="$2"
    local command_preview="$3"
    local device_state="$4"
    local risk_label="$5"
    local doc_fn="$6"
    local art_fn="$7"

    print_banner
    echo -e "${CYAN}${BOLD}SELECTED OPTION${RESET}"
    echo -e "  ${opt_num}. ${title}"
    echo ""
    echo -e "${BOLD}COMMAND${RESET}"
    echo -e "  ${command_preview}"
    echo ""
    echo -e "${BOLD}DEVICE STATE${RESET}"
    echo -e "  ${device_state}"
    echo ""
    echo -e "${BOLD}RISK${RESET}"
    echo -e "  ${risk_label}"
    echo ""
    echo -e "${BOLD}DOCUMENTATION${RESET}"
    if declare -f "$doc_fn" > /dev/null 2>&1; then
        "$doc_fn"
    fi
    echo ""
    echo -e "${CYAN}${BOLD}FLOW${RESET}"
    if declare -f "$art_fn" > /dev/null 2>&1; then
        echo -e "${CYAN}"
        "$art_fn"
        echo -e "${RESET}"
    fi
    echo ""
}

run_confirmed() {
    local opt_num="$1"
    local title="$2"
    local command_preview="$3"
    local device_state="$4"
    local risk_label="$5"
    local doc_fn="$6"
    local art_fn="$7"
    shift 7

    show_confirmation "$opt_num" "$title" "$command_preview" "$device_state" "$risk_label" "$doc_fn" "$art_fn"

    if prompt_yes_no "Proceed?"; then
        "$@"
        press_enter
    else
        echo -e "${YELLOW}Cancelled. Returning to menu.${RESET}"
        sleep 1
    fi
}

# ---------------------------------------------------------------------------
# Documentation blocks (from PLAN/docs_for_plan_8_v2.md)
# ---------------------------------------------------------------------------

print_doc_generic_readonly() {
    cat <<'EOF'
Read-only diagnostic action. Inspects device state without modifying
activation, filesystem, or lockdown configuration.
EOF
}

print_doc_generic_write() {
    cat <<'EOF'
Writes to device state, preferences, or lockdown configuration.
Ensure the device is USB-connected and in a reachable boot state.
EOF
}

print_doc_preboard_race() {
    cat <<'EOF'
VUL 23 TOCTOU race between preboardservice_v2 disruption and
mobileactivationd activation handling. Targets Setup Assistant /
pre-activation state. Known limitation: SEP-backed cryptographic
validation may still reject the activation record.
EOF
}

print_doc_albert_tls() {
    cat <<'EOF'
Albert DRM handshake and TLS pinning bypass for local research.
Use with captive portal to inspect or redirect activation traffic.
Hooks tls-error signals in WebKitGTK-based clients.
EOF
}

print_doc_neo_chain() {
    cat <<'EOF'
Neo-Chain pivots from timing-based TOCTOU to kernel exploitation
leveraging A18 Pro's missing MTE. Stages: kernel R/W (V-047 or MCC),
AMFI/CoreTrust bypass (trust_cache_rt), SEP/NVRAM, persistence, verify.
Blocked stages fall back per awaiting_offsets.txt.
EOF
}

print_doc_bypass_full() {
    cat <<'EOF'
Full 5-stage activation bypass chain: AFC staging, online activation
or VUL 23 race fallback, crash triage, Darwin notification burst,
and live SpringBoard transition. Does not require kernel exploitation.
EOF
}

print_doc_sovereign() {
    cat <<'EOF'
Sovereign-Chain hybrid security degradation: Stage 1 applies dual-vector
memory pressure (NECP wired-memory spray + IOSurface allocation) to degrade
priority-40 security daemons (secinitd, cryptexd). Stage 2 stages AI
guardrail preference overrides via AFC. Stage 3 runs the full 5-stage
activation bypass chain (AFC staging, online/VUL 23 race, triage,
notifications, SpringBoard transition). Userspace-only; no kernel exploit.
EOF
}

print_doc_sovereign_lite() {
    cat <<'EOF'
Sovereign-Lite: high-reliability state manipulation without the full
activation bypass chain. Shares Stages 1-2 with Sovereign-Chain (NECP/
IOSurface memory pressure + AI guardrail AFC overrides), then pivots to
lockdown flag injection (PurpleBuddy/hactivation bypass keys), a 14-event
Darwin setup-dismissal notification burst, and a diagnostics-relay respring.
Skips online activation, VUL 23 race, and crash triage. Userspace-only.
EOF
}

print_doc_self_test() {
    cat <<'EOF'
Host-only embedded unit test suite (12 tests). Validates parsers,
synthesizers, and lifecycle helpers without a connected device:
Port DFU serial parser, Base64 codec, A18 target gating, activation
record synthesizer, DNS/HTTP captive parsers, mobileconfig generator,
root CA PEM, .IPS crash triage parser, PurpleBuddy/SpringBoard plist
synthesizers, session manager init, and SetupAssistant/iTunes plists.
EOF
}

print_doc_test_kernel_exploit() {
    cat <<'EOF'
Isolated kernel R/W primitive test (not the full Neo-Chain). Tries
V-047 AppleJPEGDriver OOB write (startDecoderExt, IOSurface heap groom,
NECP PGZ spray) first; falls back to AppleMCCUserClientV2 testMode
(selectors 0x12/0x7/0x8/0x10). On success, probes kread64 against
allproc using iOS 26.6.1 T8140 offsets. Host orchestration only;
live IOKit exploitation requires an on-device payload.
EOF
}

print_doc_test_amfi_bypass() {
    cat <<'EOF'
Isolated AMFI/CoreTrust bypass test (not the full Neo-Chain). Obtains
kernel R/W (V-047, then MCC fallback), walks allproc for process
enumeration (struct_size 0x750, p_name +0x4d8), attempts AMFI HSP
disable (blocked if unresolved), then tests trust_cache_rt injection
and CoreTrust cs_blob validation patch. proc.p_flag fastPathSign paths
remain blocked per awaiting_offsets.txt.
EOF
}

print_doc_captive() {
    cat <<'EOF'
Local DNS/HTTP/TLS captive portal for WebSheet research. Intercepts
activation-related traffic. Privileged ports (53/80/443) require sudo.
EOF
}

# ---------------------------------------------------------------------------
# ASCII art blocks
# ---------------------------------------------------------------------------

print_art_generic() {
    cat <<'EOF'
  host (l0fck)  --->  USB/lockdown  --->  device services
EOF
}

print_art_preboard_race() {
    cat <<'EOF'
thread A: preboard fault  ----\
                               +--> timing window --> activation submit
thread B: activation request --/
EOF
}

print_art_albert_tls() {
    cat <<'EOF'
Albert traffic
      |
      v
+-------------+      TLS failure event      +----------------+
| WebKit/GTLS | --------------------------> | local override |
+-------------+                             +-------+--------+
                                                   |
                                                   v
                                           controlled test endpoint
EOF
}

print_art_neo_chain() {
    cat <<'EOF'
+---------------------------------------------------------------------+
|                        NEO-CHAIN EXECUTION FLOW                     |
+---------------------------------------------------------------------+
|  STAGE 0: RECON (A18 Pro, MTE absent)                               |
|  STAGE 1: KERNEL R/W (V-047 OOB or MCC testMode)                  |
|  STAGE 2: AMFI / CoreTrust (CVMServer + trust_cache_rt)             |
|  STAGE 3: SEP / MobileActivation (NVRAM via PMAP)                   |
|  STAGE 4: PERSISTENCE (AFC staging, IOMFB blocked)                  |
|  STAGE 5: CLEANUP (respring, verify)                                |
+---------------------------------------------------------------------+
EOF
}

print_art_bypass_full() {
    cat <<'EOF'
Stage 1-2: AFC staging + activation (online or VUL 23 race)
Stage 3:   Crash triage & telemetry
Stage 4:   Darwin setup dismissal notifications
Stage 5:   Live SpringBoard home screen transition
EOF
}

print_art_sovereign() {
    cat <<'EOF'
+---------------------------------------------------------------------+
|                   SOVEREIGN-CHAIN EXECUTION FLOW                    |
+---------------------------------------------------------------------+
|  STAGE 1: DUAL-VECTOR MEMORY PRESSURE                               |
|    NECP wired-memory spray + IOSurface allocation                   |
|    -> degrade secinitd / cryptexd (priority-40 daemons)             |
|                                                                     |
|  STAGE 2: AI GUARDRAIL BYPASS                                       |
|    AFC preference overrides (disableToolBoxAllowList, etc.)         |
|                                                                     |
|  STAGE 3: FULL 5-STAGE BYPASS CHAIN                                 |
|    AFC staging -> activation/VUL 23 race -> triage ->              |
|    Darwin notifications -> SpringBoard home screen transition       |
+---------------------------------------------------------------------+
EOF
}

print_art_sovereign_lite() {
    cat <<'EOF'
+---------------------------------------------------------------------+
|                   SOVEREIGN-LITE EXECUTION FLOW                     |
+---------------------------------------------------------------------+
|  STAGE 1: DUAL-VECTOR MEMORY PRESSURE                               |
|    NECP wired-memory spray + IOSurface allocation                   |
|    -> degrade secinitd / cryptexd (priority-40 daemons)             |
|                                                                     |
|  STAGE 2: AI GUARDRAIL BYPASS                                       |
|    AFC preference overrides (disableToolBoxAllowList, etc.)         |
|                                                                     |
|  STAGE 3: DEEP LOCKDOWN FLAG INJECTION                              |
|    PurpleBuddy & hactivation bypass keys via lockdownd              |
|                                                                     |
|  STAGE 4: SETUP DISMISSAL NOTIFICATION BURST                        |
|    14 Darwin notifications -> SpringBoard / Setup.app handoff       |
|                                                                     |
|  STAGE 5: UI REFRESH (RESPRING)                                     |
|    diagnostics_relay respring -> Home Screen transition              |
+---------------------------------------------------------------------+
EOF
}

print_art_self_test() {
    cat <<'EOF'
./l0fck --test  (host only, no USB device)
        |
        +-- Parsers: Port DFU serial, DNS query, HTTP request, .IPS
        +-- Codecs:  Base64 encode/decode
        +-- Synth:   A18 activation record, PurpleBuddy/SpringBoard
        |            SetupAssistant/iTunes plists, mobileconfig, CA PEM
        +-- Gating:  A18 Pro / iOS 26.6.1 target validator
        +-- Lifecycle: session manager struct init
EOF
}

print_art_test_kernel_exploit() {
    cat <<'EOF'
Primary (V-047):
userspace app
     |
     v
+-------------------+   malformed decoder req   +----------------+
| IOKit connection  | ------------------------> | AppleJPEGDriver |
+-------------------+                           +-------+--------+
                                                        |
                                                        v
                                               kernel heap overwrite
                                                        |
                                                        v
                                               kread64(allproc) probe

Fallback (MCC):
+-----------+  sel 0x12/0x7/0x8/0x10  +----------------------+
| l0fck host| ----------------------> | AppleMCCUserClientV2 |
+-----------+                         +----------+-----------+
                                                |
                                                v
                                    test data stream / kernel mem map
EOF
}

print_art_test_amfi_bypass() {
    cat <<'EOF'
kernel R/W (V-047 or MCC)
        |
        +--> allproc walk (struct_size 0x750, p_name +0x4d8)
        |         |
        |         v
        |    process enumeration
        |
        +--> trust_cache_rt injection (0xfffffff007cdab20)
        |         |
        |         v
        |    cdhash accepted by AMFI/CoreTrust
        |
        +--> AMFI HSP disable (blocked: proc.p_flag unresolved)
        |
        +--> CoreTrust cs_blob validation patch (data-only)
EOF
}

# ---------------------------------------------------------------------------
# Dependency & build
# ---------------------------------------------------------------------------

check_dependencies() {
    echo -e "${CYAN}[*] Validating build dependencies via pkg-config...${RESET}"
    DEPS=("libimobiledevice-1.0" "libirecovery-1.0" "libusb-1.0" "libplist-2.0" "openssl" "libcurl")
    MISSING=0
    for dep in "${DEPS[@]}"; do
        if ! pkg-config --exists "$dep" 2>/dev/null; then
            echo -e "${RED}[!] Missing dependency: $dep${RESET}"
            MISSING=1
        fi
    done

    if [ $MISSING -eq 1 ]; then
        echo -e "${YELLOW}[*] On macOS, run: brew install libimobiledevice libirecovery libusb libplist openssl curl pkg-config${RESET}"
        exit 1
    fi
}

ensure_built() {
    if [ ! -f "$SCRIPT_DIR/l0fck" ]; then
        echo -e "${YELLOW}[*] l0fck binary not found. Building from source...${RESET}"
        make
        echo -e "${GREEN}[+] Build complete!${RESET}"
        sleep 1
    fi
}

# ---------------------------------------------------------------------------
# Section menus
# ---------------------------------------------------------------------------

menu_device_discovery() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}Device Discovery${RESET}"
        echo ""
        echo -e "${BOLD}1.${RESET}  Detect Device & Hardware Compatibility Check"
        echo -e "${BOLD}2.${RESET}  Port DFU Mode Analysis (PID 05ac:f014)"
        echo -e "${BOLD}3.${RESET}  Scan All USB Apple Devices Across Modes"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-3, B, 0]: "
        read -r choice

        case "$choice" in
            1) run_confirmed "1" "Detect Device & Hardware Compatibility" \
                "./l0fck --detect" \
                "ON or DFU, USB-connected" \
                "${GREEN}Safe / read-only${RESET}" \
                print_doc_generic_readonly print_art_generic \
                ./l0fck --detect ;;
            2) run_confirmed "2" "Port DFU Mode Analysis" \
                "./l0fck --port-dfu" \
                "Port DFU mode (PID 05ac:f014)" \
                "${GREEN}Safe / read-only${RESET}" \
                print_doc_generic_readonly print_art_generic \
                ./l0fck --port-dfu ;;
            3) run_confirmed "3" "Scan All USB Apple Devices" \
                "./l0fck --usb-scan" \
                "Any USB-connected Apple device" \
                "${GREEN}Safe / read-only${RESET}" \
                print_doc_generic_readonly print_art_generic \
                ./l0fck --usb-scan ;;
            [Bb]) return ;;
            0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
            *) echo -e "\n${RED}Invalid selection.${RESET}"; sleep 1 ;;
        esac
    done
}

menu_lockdown_afc() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}Lockdown / AFC${RESET}"
        echo ""
        echo -e "${BOLD}1.${RESET}  Audit Unauthenticated Lockdown Services (Vuln #02)"
        echo -e "${BOLD}2.${RESET}  Browse /var/mobile/Media/ Partition via AFC"
        echo -e "${BOLD}3.${RESET}  Inject Persistent PurpleBuddy & Bypass Flags"
        echo -e "${BOLD}4.${RESET}  Verify Lockdownd Configuration Flags"
        echo -e "${BOLD}5.${RESET}  Stream Live Device Syslog"
        echo -e "${BOLD}6.${RESET}  Reboot Device Safely via Diagnostics Relay"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-6, B, 0]: "
        read -r choice

        case "$choice" in
            1) run_confirmed "1" "Audit Unauthenticated Lockdown Services" \
                "./l0fck --probe-services -v" \
                "ON, USB-connected, lockdown reachable" \
                "${GREEN}Safe / read-only${RESET}" \
                print_doc_generic_readonly print_art_generic \
                ./l0fck --probe-services -v ;;
            2)
                print_banner
                echo -n "Enter remote path on /var/mobile/Media/ [/]: "
                read -r afc_path
                if [ -z "$afc_path" ]; then afc_path="/"; fi
                run_confirmed "2" "Browse AFC Media Partition" \
                    "./l0fck --afc-ls ${afc_path}" \
                    "ON, USB-connected, AFC accessible" \
                    "${GREEN}Safe / read-only${RESET}" \
                    print_doc_generic_readonly print_art_generic \
                    ./l0fck --afc-ls "$afc_path" ;;
            3) run_confirmed "3" "Inject PurpleBuddy & Bypass Flags" \
                "./l0fck --inject-flags" \
                "ON, USB-connected, lockdown reachable" \
                "${YELLOW}Caution: writes lockdown flags${RESET}" \
                print_doc_generic_write print_art_generic \
                ./l0fck --inject-flags ;;
            4) run_confirmed "4" "Verify Lockdownd Configuration Flags" \
                "./l0fck --verify-flags" \
                "ON, USB-connected, lockdown reachable" \
                "${GREEN}Safe / read-only${RESET}" \
                print_doc_generic_readonly print_art_generic \
                ./l0fck --verify-flags ;;
            5)
                print_banner
                echo -n "Enter stream duration in seconds [10]: "
                read -r dur
                if [ -z "$dur" ]; then dur=10; fi
                run_confirmed "5" "Stream Live Device Syslog" \
                    "./l0fck --syslog ${dur}" \
                    "ON, USB-connected, lockdown reachable" \
                    "${GREEN}Safe / read-only${RESET}" \
                    print_doc_generic_readonly print_art_generic \
                    ./l0fck --syslog "$dur" ;;
            6) run_confirmed "6" "Reboot Device Safely" \
                "./l0fck --reboot" \
                "ON, USB-connected, lockdown reachable" \
                "${YELLOW}Caution: device reboot${RESET}" \
                print_doc_generic_write print_art_generic \
                ./l0fck --reboot ;;
            [Bb]) return ;;
            0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
            *) echo -e "\n${RED}Invalid selection.${RESET}"; sleep 1 ;;
        esac
    done
}

menu_activation_albert() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}Activation / Albert${RESET}"
        echo ""
        echo -e "${BOLD}1.${RESET}  Albert DRM Handshake & IngestBody Inspection Probe"
        echo -e "${BOLD}2.${RESET}  Execute Full 5-Stage Online Albert Activation"
        echo -e "${BOLD}3.${RESET}  Execute VUL 23 TOCTOU Race Activation"
        echo -e "${BOLD}4.${RESET}  Deactivate Device Activation State"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-4, B, 0]: "
        read -r choice

        case "$choice" in
            1) run_confirmed "1" "Albert DRM Handshake Probe" \
                "./l0fck --probe-albert" \
                "ON, USB-connected, activation state available" \
                "${GREEN}Safe / read-only${RESET}" \
                print_doc_albert_tls print_art_albert_tls \
                ./l0fck --probe-albert ;;
            2) run_confirmed "2" "Full Online Albert Activation" \
                "./l0fck --activate-online" \
                "ON, USB-connected, network available" \
                "${YELLOW}Caution: modifies activation state${RESET}" \
                print_doc_albert_tls print_art_albert_tls \
                ./l0fck --activate-online ;;
            3) run_confirmed "3" "VUL 23 TOCTOU Race Activation" \
                "./l0fck --activate-race" \
                "ON, Setup Assistant / pre-activation state" \
                "${YELLOW}Caution: race exploit, may crash services${RESET}" \
                print_doc_preboard_race print_art_preboard_race \
                ./l0fck --activate-race ;;
            4) run_confirmed "4" "Deactivate Device" \
                "./l0fck --deactivate" \
                "ON, USB-connected, lockdown reachable" \
                "${RED}Danger: removes activation${RESET}" \
                print_doc_generic_write print_art_generic \
                ./l0fck --deactivate ;;
            [Bb]) return ;;
            0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
            *) echo -e "\n${RED}Invalid selection.${RESET}"; sleep 1 ;;
        esac
    done
}

menu_preboard() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}Preboard / Setup Assistant${RESET}"
        echo ""
        echo -e "${BOLD}1.${RESET}  Run Preboard Service Crash PoC (Vulnerability #23)"
        echo -e "${BOLD}2.${RESET}  Auto-Triage Preboard Crash & Fetch .IPS Dump"
        echo -e "${BOLD}3.${RESET}  Stage Disk Preferences to Media Partition (AFC)"
        echo -e "${BOLD}4.${RESET}  Execute Weaponized Preboard Exploit"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-4, B, 0]: "
        read -r choice

        case "$choice" in
            1) run_confirmed "1" "Preboard Service Crash PoC" \
                "./l0fck --crash-preboard" \
                "ON, Setup Assistant / pre-activation state" \
                "${YELLOW}Caution: crashes preboardservice_v2${RESET}" \
                print_doc_preboard_race print_art_preboard_race \
                ./l0fck --crash-preboard ;;
            2) run_confirmed "2" "Auto-Triage Preboard Crash" \
                "./l0fck --triage-crash" \
                "ON, after preboard crash" \
                "${GREEN}Safe / read-only (fetches crash report)${RESET}" \
                print_doc_preboard_race print_art_preboard_race \
                ./l0fck --triage-crash ;;
            3) run_confirmed "3" "Stage Disk Preferences to AFC" \
                "./l0fck --stage-bypass" \
                "ON, USB-connected, AFC accessible" \
                "${YELLOW}Caution: writes preference plists${RESET}" \
                print_doc_preboard_race print_art_preboard_race \
                ./l0fck --stage-bypass ;;
            4) run_confirmed "4" "Weaponized Preboard Exploit" \
                "./l0fck --exploit-preboard" \
                "ON, Setup Assistant / pre-activation state" \
                "${RED}Danger: privilege escalation attempt${RESET}" \
                print_doc_preboard_race print_art_preboard_race \
                ./l0fck --exploit-preboard ;;
            [Bb]) return ;;
            0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
            *) echo -e "\n${RED}Invalid selection.${RESET}"; sleep 1 ;;
        esac
    done
}

menu_captive_portal() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}Captive Portal${RESET}"
        echo ""
        echo -e "${BOLD}1.${RESET}  Launch Captive Portal (user ports: 8080/5353/8443)"
        echo -e "${BOLD}2.${RESET}  Launch Captive Portal (privileged ports: 80/53/443) [sudo]"
        echo -e "${BOLD}3.${RESET}  Export Research .mobileconfig Profile"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-3, B, 0]: "
        read -r choice

        case "$choice" in
            1)
                print_banner
                echo -n "Enter HTTP server port [8080]: "
                read -r c_port
                if [ -z "$c_port" ]; then c_port=8080; fi
                echo -n "Enter DNS responder port [5353]: "
                read -r d_port
                if [ -z "$d_port" ]; then d_port=5353; fi
                echo -n "Open host admin dashboard in browser? (Y/n): "
                read -r open_dash
                local cmd="./l0fck --captive-server ${c_port} --captive-dns-port ${d_port}"
                run_confirmed "1" "Captive Portal (user ports)" \
                    "$cmd" \
                    "ON device on same network; host listening" \
                    "${YELLOW}Caution: long-running, network interception${RESET}" \
                    print_doc_captive print_art_albert_tls \
                    bash -c "
                        if [[ ! '${open_dash:-}' =~ ^[Nn]$ ]]; then
                            (sleep 1 && open 'http://localhost:${c_port}/admin') &
                        fi
                        ./l0fck --captive-server '${c_port}' --captive-dns-port '${d_port}'
                    " ;;
            2) run_confirmed "2" "Captive Portal (privileged ports)" \
                "sudo ./l0fck --captive-server 80 --captive-dns-port 53 --captive-tls-port 443" \
                "ON device on same network; requires sudo" \
                "${RED}Danger: privileged ports, network interception${RESET}" \
                print_doc_captive print_art_albert_tls \
                sudo ./l0fck --captive-server 80 --captive-dns-port 53 --captive-tls-port 443 ;;
            3)
                print_banner
                echo -n "Enter export file path [research.mobileconfig]: "
                read -r prof_path
                if [ -z "$prof_path" ]; then prof_path="research.mobileconfig"; fi
                run_confirmed "3" "Export Research .mobileconfig Profile" \
                    "./l0fck --export-profile ${prof_path}" \
                    "Host only (no device required)" \
                    "${GREEN}Safe / writes local file only${RESET}" \
                    print_doc_captive print_art_albert_tls \
                    ./l0fck --export-profile "$prof_path" ;;
            [Bb]) return ;;
            0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
            *) echo -e "\n${RED}Invalid selection.${RESET}"; sleep 1 ;;
        esac
    done
}

menu_advanced_chains() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}Advanced Chains${RESET}"
        echo ""
        echo -e "${BOLD}1.${RESET}  ${GREEN}${BOLD}Full 5-Stage Activation Bypass Chain${RESET}"
        echo -e "${BOLD}2.${RESET}  ${MAGENTA}${BOLD}Automated USB Bypass Watcher (Persistent)${RESET}"
        echo -e "${BOLD}3.${RESET}  ${CYAN}${BOLD}Sovereign-Chain (Hybrid Security Degradation)${RESET}"
        echo -e "${BOLD}4.${RESET}  ${CYAN}${BOLD}Sovereign-Lite (Injection + Notification)${RESET}"
        echo -e "${BOLD}5.${RESET}  ${CYAN}${BOLD}Neo-Chain (Kernel Exploitation Bypass)${RESET}"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-5, B, 0]: "
        read -r choice

        case "$choice" in
            1) run_confirmed "1" "Full 5-Stage Activation Bypass Chain" \
                "./l0fck --bypass-full" \
                "ON, USB-connected, lockdown reachable, setup/activation state" \
                "${YELLOW}Caution: full bypass chain, modifies device state${RESET}" \
                print_doc_bypass_full print_art_bypass_full \
                ./l0fck --bypass-full ;;
            2) run_confirmed "2" "Automated USB Bypass Watcher" \
                "./l0fck --bypass-watch" \
                "USB monitoring; auto-triggers on device connect" \
                "${MAGENTA}Caution: persistent watcher, auto-runs bypass${RESET}" \
                print_doc_bypass_full print_art_bypass_full \
                ./l0fck --bypass-watch ;;
            3) run_confirmed "3" "Sovereign-Chain Security Degradation" \
                "./l0fck --sovereign" \
                "ON, USB-connected, setup/activation state" \
                "${YELLOW}Caution: memory pressure + bypass chain${RESET}" \
                print_doc_sovereign print_art_sovereign \
                ./l0fck --sovereign ;;
            4) run_confirmed "4" "Sovereign-Lite Bypass" \
                "./l0fck --sovereign-lite" \
                "ON, USB-connected, lockdown reachable, setup/activation state" \
                "${YELLOW}Caution: memory pressure, flag injection, respring${RESET}" \
                print_doc_sovereign_lite print_art_sovereign_lite \
                ./l0fck --sovereign-lite ;;
            5) run_confirmed "5" "Neo-Chain Kernel Exploitation Bypass" \
                "./l0fck --neo-chain" \
                "ON, USB-connected, A18 Pro, iOS 26.6.1" \
                "${RED}Danger: kernel exploit chain${RESET}" \
                print_doc_neo_chain print_art_neo_chain \
                ./l0fck --neo-chain ;;
            [Bb]) return ;;
            0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
            *) echo -e "\n${RED}Invalid selection.${RESET}"; sleep 1 ;;
        esac
    done
}

menu_diagnostics() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}Diagnostics${RESET}"
        echo ""
        echo -e "${BOLD}1.${RESET}  Run Embedded Self-Tests (12/12 Verification)"
        echo -e "${BOLD}2.${RESET}  Test Kernel Exploit Primitive (V-047 / MCC)"
        echo -e "${BOLD}3.${RESET}  Test AMFI / CoreTrust Bypass"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-3, B, 0]: "
        read -r choice

        case "$choice" in
            1) run_confirmed "1" "Embedded Self-Tests" \
                "./l0fck --test" \
                "Host only (no device required)" \
                "${GREEN}Safe / read-only${RESET}" \
                print_doc_self_test print_art_self_test \
                ./l0fck --test ;;
            2) run_confirmed "2" "Test Kernel Exploit Primitive" \
                "./l0fck --test-kernel-exploit" \
                "Host orchestration; live IOKit needs on-device payload" \
                "${YELLOW}Caution: kernel exploit primitive test${RESET}" \
                print_doc_test_kernel_exploit print_art_test_kernel_exploit \
                ./l0fck --test-kernel-exploit ;;
            3) run_confirmed "3" "Test AMFI / CoreTrust Bypass" \
                "./l0fck --test-amfi-bypass" \
                "Host orchestration; requires kernel R/W primitive first" \
                "${YELLOW}Caution: AMFI/CoreTrust bypass test${RESET}" \
                print_doc_test_amfi_bypass print_art_test_amfi_bypass \
                ./l0fck --test-amfi-bypass ;;
            [Bb]) return ;;
            0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
            *) echo -e "\n${RED}Invalid selection.${RESET}"; sleep 1 ;;
        esac
    done
}

print_main_menu() {
    print_banner
    echo -e "${CYAN}${BOLD}Main Menu${RESET}"
    echo ""
    echo -e "${BOLD}1.${RESET}  Device Discovery"
    echo -e "${BOLD}2.${RESET}  Lockdown / AFC"
    echo -e "${BOLD}3.${RESET}  Activation / Albert"
    echo -e "${BOLD}4.${RESET}  Preboard / Setup Assistant"
    echo -e "${BOLD}5.${RESET}  Captive Portal"
    echo -e "${BOLD}6.${RESET}  Advanced Chains"
    echo -e "${BOLD}7.${RESET}  Diagnostics"
    echo ""
    echo -e "${BOLD}0.${RESET}  Exit"
    echo "----------------------------------------------------------------------"
    echo -n "Select a section [1-7, 0]: "
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

check_dependencies
ensure_built

while true; do
    print_main_menu
    read -r section

    case "$section" in
        1) menu_device_discovery ;;
        2) menu_lockdown_afc ;;
        3) menu_activation_albert ;;
        4) menu_preboard ;;
        5) menu_captive_portal ;;
        6) menu_advanced_chains ;;
        7) menu_diagnostics ;;
        0) echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"; exit 0 ;;
        *) echo -e "\n${RED}Invalid selection. Try again.${RESET}"; sleep 1 ;;
    esac
done
