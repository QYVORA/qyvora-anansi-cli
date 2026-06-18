#!/usr/bin/env bash

# ANANSI CLI Installer
# QYVORA OffSec - Ghana

set -euo pipefail

# Colors
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
DIM='\033[90m'
NC='\033[0m' # No Color

# Banner
clear 2>/dev/null || true
echo -e "${CYAN}             ;                  &              "
echo -e "            ;;                    ;&            "
echo -e "           ;;;                    ;;;           "
echo -e "      ;    ;;;                    ;;;    ;      "
echo -e "      ;;;  ;;;        ;   ;;      ;;;   ;;;     "
echo -e "      ;;;;  ;;;;   ;;; && ;;;   ;;;;   ;;;;     "
echo -e "       ;;;;   ;;;; ;;;;;;;;;; ;;;;    ;;;;      "
echo -e "        ;;;;;;;;; ;;;;;;;;;;;;;;;; ;;;;;;;;;    "
echo -e "            &;;;;;;;;;;;;\$x;;;;;;;;;;;;         "
echo -e "           ;;;;;;;;;;&&&+++&&&;;;;;;;;;;;       "
echo -e "      ;;;;;;;;;  ;;;&&+&&&&&+&&;;;  ;;;;;;;;;;  "
echo -e "      ;;;&    ;; ;;;&+&&&&&&&+&&;;; ;;    &;;;  "
echo -e "      ;;;   ;;;;  ;;;&&+&&&&&&+&;;; ;;;;   ;;;  "
echo -e "      ;;;   ;;;   ;;;;&&++&++++&&;;  ;;;   ;;;  "
echo -e "       ;;   ;;;    ;;;;;;;;;;;&&&&;  ;;;   ;;   "
echo -e "       ;;   ;;;      ;;;;;;;;;;;;;;  ;;;   ;;   "
echo -e "        ;   ;;;        ;;;;;;;;;;    ;;;   ;    "
echo -e "            &;;           ;;;;       ;;&        "
echo -e "              ;;           ;;       ;;;          "
echo -e "                ;                 ;             ${NC}"
echo -e ""
echo -e "  ${WHITE}ANANSI CLI Installer${NC}"
echo -e "  ${CYAN}QYVORA OffSec — Accra, Ghana${NC}"
echo -e "  ${DIM}----------------------------------------${NC}"
echo -e ""

# Internet connection warning
echo -e "  ${YELLOW}[!] IMPORTANT:${NC} Please ensure you are connected to the Internet."
echo -e "      The installer will download required Go dependencies to build the binary."
echo -e ""

# Steps definition
step_verify_system() {
    echo -e "  ${CYAN}[1/5]${NC} Verifying system requirements & dependencies..."
    
    # 1. Check internet connection
    if ! curl -s --connect-timeout 5 https://google.com >/dev/null; then
        echo -e "  ${RED}[!] Error: No internet connection detected. Please connect and try again.${NC}"
        exit 1
    fi
    echo -e "      ${DIM}- Internet connection detected [OK]${NC}"

    # 2. Check if Go is installed
    if ! command -v go >/dev/null 2>&1; then
        echo -e "  ${RED}[!] Error: Go (Golang) is not installed.${NC}"
        echo -e "      Please install Go 1.22+ (https://go.dev/doc/install) and run this script again."
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo -e "      ${DIM}- Go version $GO_VERSION detected [OK]${NC}"
    echo -e "  ${GREEN}[SUCCESS]${NC} System checks passed."
    echo -e ""
}

step_download_deps() {
    echo -e "  ${CYAN}[2/5]${NC} Downloading Go module dependencies..."
    if go mod tidy; then
        echo -e "  ${GREEN}[SUCCESS]${NC} Dependencies downloaded and synced."
    else
        echo -e "  ${RED}[!] Error: Failed to resolve Go dependencies.${NC}"
        exit 1
    fi
    echo -e ""
}

step_compile() {
    echo -e "  ${CYAN}[3/5]${NC} Compiling ANANSI CLI binary..."
    # Build with ldflags to strip debugging information and shrink binary size
    if go build -ldflags="-s -w" -o anansi main.go; then
        echo -e "  ${GREEN}[SUCCESS]${NC} Binary compiled successfully (./anansi)."
    else
        echo -e "  ${RED}[!] Error: Compilation failed.${NC}"
        exit 1
    fi
    echo -e ""
}

step_install_binary() {
    echo -e "  ${CYAN}[4/5]${NC} Installing binary to your system PATH..."
    
    INSTALL_DIR="/usr/local/bin"
    
    # Check if we can write to /usr/local/bin
    if [ -w "$INSTALL_DIR" ]; then
        cp anansi "$INSTALL_DIR/anansi"
        echo -e "      ${DIM}- Installed to $INSTALL_DIR/anansi${NC}"
    else
        # Try with non-interactive sudo if not writeable
        echo -e "      ${DIM}- Copying to $INSTALL_DIR (attempting non-interactive sudo)...${NC}"
        if sudo -n cp anansi "$INSTALL_DIR/anansi" 2>/dev/null; then
            echo -e "      ${DIM}- Installed to $INSTALL_DIR/anansi (using sudo)${NC}"
        else
            # Fallback to local user bin if sudo fails
            USER_BIN="$HOME/.local/bin"
            echo -e "      ${YELLOW}[!] Sudo copy failed. Attempting installation to $USER_BIN...${NC}"
            mkdir -p "$USER_BIN"
            cp anansi "$USER_BIN/anansi"
            echo -e "      ${DIM}- Installed to $USER_BIN/anansi${NC}"
            
            # Check if USER_BIN is in PATH
            if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
                echo -e "      ${YELLOW}[!] Warning: $USER_BIN is not in your \$PATH.${NC}"
                echo -e "          Please add it to your shell configuration (e.g. ~/.bashrc or ~/.zshrc):"
                echo -e "          ${WHITE}export PATH=\"\$PATH:\$HOME/.local/bin\"${NC}"
            fi
        fi
    fi
    
    echo -e "  ${GREEN}[SUCCESS]${NC} Installation complete."
    echo -e ""
}

step_verify_install() {
    echo -e "  ${CYAN}[5/5]${NC} Verifying terminal installation..."
    
    # Clear shell paths cache
    hash -r 2>/dev/null || true
    
    if command -v anansi >/dev/null 2>&1; then
        echo -e "  ${GREEN}[SUCCESS]${NC} 'anansi' command is now globally available!"
        echo -e ""
        echo -e "  ${WHITE}You can run it using:${NC}"
        echo -e "      ${CYAN}anansi [target]${NC}"
        echo -e ""
    else
        # If the parent shell is ZSH, prompt user to run rehash
        if [[ "${SHELL:-}" == */zsh ]]; then
            echo -e "  ${YELLOW}[!] Note: If the command is not recognized, refresh your shell using:${NC}"
            echo -e "      ${CYAN}rehash${NC}"
            echo -e ""
        fi
        echo -e "  ${YELLOW}[!] Warning: 'anansi' command was not found in your current path.${NC}"
        echo -e "      Try starting a new terminal session or run the binary locally:"
        echo -e "      ${CYAN}./anansi --help${NC}"
        echo -e ""
    fi
}

# Run phases
step_verify_system
step_download_deps
step_compile
step_install_binary
step_verify_install
