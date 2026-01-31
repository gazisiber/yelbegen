#!/bin/bash
# Yelbegen Installer
# Usage: curl -sL https://gazisiber.org/yelbegen | bash

set -e

REPO_URL="https://github.com/gazisiber/yelbegen.git"
INSTALL_DIR="$HOME/.yelbegen"
BIN_NAME="yelbegen"

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "██╗   ██╗███████╗██╗     ██████╗ ███████╗ ██████╗ ███████╗███╗   ██╗"
echo "╚██╗ ██╔╝██╔════╝██║     ██╔══██╗██╔════╝██╔════╝ ██╔════╝████╗  ██║"
echo " ╚████╔╝ █████╗  ██║     ██████╔╝█████╗  ██║  ███╗█████╗  ██╔██╗ ██║"
echo "  ╚██╔╝  ██╔══╝  ██║     ██╔══██╗██╔══╝  ██║   ██║██╔══╝  ██║╚██╗██║"
echo "   ██║   ███████╗███████╗██████╔╝███████╗╚██████╔╝███████╗██║ ╚████║"
echo "   ╚═╝   ╚══════╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝"
echo -e "${NC}"
echo -e "${BLUE}=== Yelbegen Installer ===${NC}"
echo

# 1. Check Dependencies
echo -e "${BLUE}[+] Checking dependencies...${NC}"
MISSING_DEPS=0

check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[!] Missing dependency: $1${NC}"
        MISSING_DEPS=1
    else
        echo -e "${GREEN}[✓] Found $1${NC}"
    fi
}

check_cmd git
check_cmd python3
check_cmd pip3

if [ $MISSING_DEPS -eq 1 ]; then
    echo -e "${RED}[!] Please install missing dependencies and try again.${NC}"
    echo "    Ubuntu/Debian: sudo apt update && sudo apt install -y git python3 python3-pip"
    exit 1
fi

# Check for pipx (Optional but recommended)
USE_PIPX=0
if command -v pipx &> /dev/null; then
    echo -e "${GREEN}[✓] Found pipx (Recommended installation method)${NC}"
    USE_PIPX=1
else
    echo -e "${YELLOW}[!] pipx not found. Falling back to pip user install.${NC}"
fi

# 2. Clone Repository
echo -e "${BLUE}[+] Preparing installation directory...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}    Removing existing directory: $INSTALL_DIR${NC}"
    rm -rf "$INSTALL_DIR"
fi

echo -e "${BLUE}[+] Cloning repository...${NC}"
git clone -q "$REPO_URL" "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 3. Install
echo -e "${BLUE}[+] Installing Yelbegen...${NC}"

if [ $USE_PIPX -eq 1 ]; then
    # Uninstall if previously installed via pipx to ensure clean state
    pipx uninstall "$BIN_NAME" &>/dev/null || true
    pipx install . --force
else
    # Pip user install
    # Check for break-system-packages support (PEP 668)
    PIP_ARGS="--user"
    if pip3 install --help | grep -q "break-system-packages"; then
        PIP_ARGS="$PIP_ARGS --break-system-packages"
    fi
    
    # Uninstall previous version if exists
    pip3 uninstall -y "$BIN_NAME" $PIP_ARGS &>/dev/null || true
    
    echo "    Running: pip3 install . $PIP_ARGS"
    pip3 install . $PIP_ARGS
fi

# 4. Man Pages
echo -e "${BLUE}[+] Installing manual pages...${NC}"
MAN_SRC="docs/yelbegen.1"
MAN_DEST="/usr/local/share/man/man1"
MAN_DEST_SYS="/usr/share/man/man1"

if [ -f "$MAN_SRC" ]; then
    # Try installing man page. Use sudo if available and needed.
    install_man() {
        DEST="$1"
        DIR=$(dirname "$DEST")
        if [ -w "$DIR" ]; then
             cp "$MAN_SRC" "$DEST"
             echo -e "${GREEN}[✓] Man page installed to $DEST${NC}"
             mandb -q &>/dev/null || true
             return 0
        elif command -v sudo &>/dev/null; then
             echo -e "${YELLOW}    Requesting sudo permission to install man pages...${NC}"
             if sudo cp "$MAN_SRC" "$DEST"; then
                 echo -e "${GREEN}[✓] Man page installed to $DEST${NC}"
                 sudo mandb -q &>/dev/null || true
                 return 0
             fi
        fi
        return 1
    }

    # Try local first, then system
    install_man "$MAN_DEST/yelbegen.1" || install_man "$MAN_DEST_SYS/yelbegen.1" || echo -e "${YELLOW}[!] Could not install man pages (permission denied or sudo failed).${NC}"
else
    echo -e "${YELLOW}[!] Man page source not found, skipping.${NC}"
fi

# 5. Verify
echo -e "${BLUE}[+] Verifying installation...${NC}"

if command -v "$BIN_NAME" &> /dev/null; then
    VERSION=$("$BIN_NAME" --version 2>/dev/null || echo "Installed")
    echo -e "${GREEN}SUCCESS! Yelbegen is installed.${NC}"
    echo -e "Version: $VERSION"
    echo
    echo -e "Run '${YELLOW}yelbegen --help${NC}' to get started."
else
    echo -e "${RED}[!] Installation completed, but '$BIN_NAME' is not in your PATH.${NC}"
    if [ $USE_PIPX -eq 1 ]; then
        echo "    Run 'pipx ensurepath' to fix this."
    else
        echo "    Make sure ~/.local/bin is in your PATH."
        echo "    Add 'export PATH=\$HOME/.local/bin:\$PATH' to your ~/.bashrc or ~/.zshrc."
    fi
fi
