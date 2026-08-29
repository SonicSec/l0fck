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

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  _   ___   __      _    "
    echo " | | / _ \ / _| ___| | __"
    echo " | || | | | |_ / __| |/ /"
    echo " | || |_| |  _| (__|   < "
    echo " |_(_)___/|_|  \___|_|\_\\"
    echo " iPhone 16 Pro / A18 Pro / iOS 26.6.1 Security Research Suite"
    echo " Version 1.0.0 [A18Pro-Titan]"
    echo -e "${RESET}"
    echo -e "${BOLD}Target Hardware:${RESET}  Apple A18 Pro (CPID 0x8140, iPhone17,1 / iPhone17,2)"
    echo -e "${BOLD}Target Firmware:${RESET}  iOS 26.6.1 (Build 23G83)"
    echo "----------------------------------------------------------------------"
}

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

press_enter() {
    echo ""
    echo -e "${YELLOW}Press [Enter] to return to the main menu...${RESET}"
    read -r
}

check_dependencies
ensure_built

while true; do
    print_banner
    echo -e "${BOLD}1.${RESET}  Detect Device & Run Hardware Compatibility Check"
    echo -e "${BOLD}2.${RESET}  Port DFU Mode Analysis (PID 05ac:f014 / SDOM / SYSI / CPID 0x8140)"
    echo -e "${BOLD}3.${RESET}  Scan All USB Apple Devices Across Modes"
    echo ""
    echo -e "${BOLD}4.${RESET}  Audit Unauthenticated Lockdown Services (Vulnerability #02)"
    echo -e "${BOLD}5.${RESET}  Browse /var/mobile/Media/ Partition via AFC"
    echo -e "${BOLD}6.${RESET}  Inject Persistent PurpleBuddy & Bypass Flags"
    echo -e "${BOLD}7.${RESET}  Verify Lockdownd Configuration Flags"
    echo -e "${BOLD}8.${RESET}  Stream Live Device Syslog"
    echo -e "${BOLD}9.${RESET}  Reboot Device Safely via Diagnostics Relay"
    echo ""
    echo -e "${BOLD}10.${RESET} Albert DRM Handshake & IngestBody Inspection Probe"
    echo -e "${BOLD}11.${RESET} Execute Full 5-Stage Online Albert Activation"
    echo -e "${BOLD}12.${RESET} Execute VUL 23 TOCTOU Race Activation (Offline SEP Bypass)"
    echo -e "${BOLD}13.${RESET} Deactivate Device Activation State"
    echo ""
    echo -e "${BOLD}14.${RESET} Run Preboard Service Crash PoC (Vulnerability #23)"
    echo -e "${BOLD}15.${RESET} Auto-Triage Preboard Crash & Fetch .IPS Dump"
    echo -e "${BOLD}16.${RESET} Stage Disk Preferences to Media Partition (AFC)"
    echo -e "${BOLD}17.${RESET} Execute Weaponized Preboard Exploit & Privilege Escalation"
    echo -e "${BOLD}18.${RESET} ${GREEN}${BOLD}🚀 RUN FULL 5-STAGE ACTIVATION BYPASS CHAIN (Complete Unlock)${RESET}"
    echo -e "${BOLD}19.${RESET} ${MAGENTA}${BOLD}Start Automated USB Bypass Watcher (Persistent Mode)${RESET}"
    echo ""
    echo -e "${BOLD}20.${RESET} Start Local DNS/HTTP Captive Portal & WebSheet Server"
    echo -e "${BOLD}21.${RESET} Run Embedded Self-Tests (12/12 Verification)"
    echo ""
    echo -e "${BOLD}0.${RESET}  Exit"
    echo "----------------------------------------------------------------------"
    echo -n "Select an option [0-21]: "
    read -r choice

    case "$choice" in
        1)
            print_banner
            ./l0fck --detect
            press_enter
            ;;
        2)
            print_banner
            ./l0fck --port-dfu
            press_enter
            ;;
        3)
            print_banner
            ./l0fck --usb-scan
            press_enter
            ;;
        4)
            print_banner
            ./l0fck --probe-services -v
            press_enter
            ;;
        5)
            print_banner
            echo -n "Enter remote path on /var/mobile/Media/ [/]: "
            read -r afc_path
            if [ -z "$afc_path" ]; then afc_path="/"; fi
            ./l0fck --afc-ls "$afc_path"
            press_enter
            ;;
        6)
            print_banner
            ./l0fck --inject-flags
            press_enter
            ;;
        7)
            print_banner
            ./l0fck --verify-flags
            press_enter
            ;;
        8)
            print_banner
            echo -n "Enter stream duration in seconds [10]: "
            read -r dur
            if [ -z "$dur" ]; then dur=10; fi
            ./l0fck --syslog "$dur"
            press_enter
            ;;
        9)
            print_banner
            echo -e "${YELLOW}Are you sure you want to reboot the device? (y/N): ${RESET}"
            read -r conf
            if [[ "$conf" =~ ^[Yy]$ ]]; then
                ./l0fck --reboot
            else
                echo "Aborted."
            fi
            press_enter
            ;;
        10)
            print_banner
            ./l0fck --probe-albert
            press_enter
            ;;
        11)
            print_banner
            echo -e "${YELLOW}Initiating full online activation sequence...${RESET}"
            ./l0fck --activate-online
            press_enter
            ;;
        12)
            print_banner
            echo -e "${YELLOW}Executing VUL 23 TOCTOU Race Activation (Offline SEP Bypass)...${RESET}"
            ./l0fck --activate-race
            press_enter
            ;;
        13)
            print_banner
            ./l0fck --deactivate
            press_enter
            ;;
        14)
            print_banner
            ./l0fck --crash-preboard
            press_enter
            ;;
        15)
            print_banner
            ./l0fck --triage-crash
            press_enter
            ;;
        16)
            print_banner
            ./l0fck --stage-bypass
            press_enter
            ;;
        17)
            print_banner
            ./l0fck --exploit-preboard
            press_enter
            ;;
        18)
            print_banner
            echo -e "${CYAN}${BOLD}Launching complete 5-stage activation bypass chain...${RESET}"
            ./l0fck --bypass-full
            press_enter
            ;;
        19)
            print_banner
            ./l0fck --bypass-watch
            press_enter
            ;;
        20)
            print_banner
            echo -e "${CYAN}${BOLD}=== Local DNS / HTTP / TLS Captive Portal & WebSheet Engine ===${RESET}"
            echo -e "1. Launch standard user-space ports (HTTP: 8080, DNS: 5353, TLS: 8443)"
            echo -e "2. Launch standard root ports (HTTP: 80, DNS: 53, TLS: 443) [Requires sudo]"
            echo -e "3. Export Research .mobileconfig Profile"
            echo -n "Select option [1-3, default 1]: "
            read -r cap_opt
            if [ -z "$cap_opt" ]; then cap_opt=1; fi

            if [ "$cap_opt" = "3" ]; then
                echo -n "Enter export file path [research.mobileconfig]: "
                read -r prof_path
                if [ -z "$prof_path" ]; then prof_path="research.mobileconfig"; fi
                ./l0fck --export-profile "$prof_path"
            elif [ "$cap_opt" = "2" ]; then
                echo -e "${YELLOW}[*] Launching with sudo on privileged ports 80, 53, 443...${RESET}"
                sudo ./l0fck --captive-server 80 --captive-dns-port 53 --captive-tls-port 443
            else
                echo -n "Enter HTTP server port [8080]: "
                read -r c_port
                if [ -z "$c_port" ]; then c_port=8080; fi
                echo -n "Enter DNS responder port [5353]: "
                read -r d_port
                if [ -z "$d_port" ]; then d_port=5353; fi
                echo -n "Open host admin dashboard in browser? (Y/n): "
                read -r open_dash
                if [[ "$open_dash" =~ ^[Nn]$ ]]; then
                    :
                else
                    (sleep 1 && open "http://localhost:${c_port}/admin") &
                fi
                ./l0fck --captive-server "$c_port" --captive-dns-port "$d_port"
            fi
            press_enter
            ;;
        21)
            print_banner
            ./l0fck --test
            press_enter
            ;;
        0)
            echo -e "\n${CYAN}Exiting l0fck. Goodbye!${RESET}\n"
            exit 0
            ;;
        *)
            echo -e "\n${RED}Invalid selection. Try again.${RESET}"
            sleep 1
            ;;
    esac
done
