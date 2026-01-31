#!/bin/bash
# Yelbegen - Clean Reinstall Script (PEP 668 Compatible)

set -e

echo "=== Yelbegen Clean Reinstall Script ==="
echo

# Navigate to project directory
cd /home/godfry/Desktop/Github/yelbegen/yelbegen-main

echo "[1/7] Checking installation method..."
if command -v pipx &> /dev/null; then
    INSTALL_METHOD="pipx"
    echo "Using pipx (recommended)"
elif [ "$1" == "--system" ]; then
    INSTALL_METHOD="pip-system"
    echo "Using pip with --break-system-packages (user requested)"
else
    echo "ERROR: pipx not found!"
    echo ""
    echo "Options:"
    echo "  1. Install pipx (RECOMMENDED):"
    echo "     sudo apt install pipx"
    echo "     pipx ensurepath"
    echo ""
    echo "  2. Use system pip (NOT RECOMMENDED):"
    echo "     ./reinstall.sh --system"
    echo ""
    exit 1
fi

echo "[2/7] Uninstalling existing yelbegen..."
if [ "$INSTALL_METHOD" == "pipx" ]; then
    pipx uninstall yelbegen 2>/dev/null || echo "Not installed yet"
else
    sudo pip3 uninstall yelbegen -y --break-system-packages 2>/dev/null || echo "Not installed yet"
fi

echo "[3/7] Cleaning build artifacts..."
rm -rf build/ dist/ *.egg-info
rm -rf yelbegen/__pycache__ yelbegen/*/__pycache__ yelbegen/*/*/__pycache__
find . -type f -name '*.pyc' -delete
find . -type d -name '__pycache__' -delete

echo "[4/7] Removing old man pages..."
sudo rm -f /usr/share/man/man1/yelbegen.1
sudo rm -f /usr/share/man/man1/yelbegen.1.gz
sudo rm -f /usr/local/share/man/man1/yelbegen.1
sudo rm -f /usr/local/share/man/man1/yelbegen.1.gz

echo "[5/7] Installing yelbegen..."
if [ "$INSTALL_METHOD" == "pipx" ]; then
    pipx install -e . --force
else
    sudo pip3 install -e . --break-system-packages
fi

echo "[6/7] Installing man page..."
sudo cp docs/yelbegen.1 /usr/share/man/man1/
sudo mandb -q

echo "[7/7] Verifying installation..."
which yelbegen
yelbegen --help | head -5

echo
echo "✓ Installation complete!"
echo
echo "Test commands:"
echo "  man yelbegen            # View manual"
echo "  yelbegen google.com     # Basic scan"
echo "  yelbegen -f google.com  # Full scan"
echo "  yelbegen -a google.com  # API scan (requires keys)"
echo "  yelbegen -la            # List API keys"
echo
