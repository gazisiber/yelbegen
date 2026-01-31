#!/usr/bin/env bash

echo "Yelbegen Installation Script"
echo ""
echo "Installing Yelbegen ..."
echo ""

cd "$(dirname "$0")"

pip install --break-system-packages --user --force-reinstall .

echo ""
echo "Installation complete!"
echo ""
echo "Run 'yelbegen' from anywhere to start the tool"
echo ""
