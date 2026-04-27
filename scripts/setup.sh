#!/bin/bash
# NFC Access Control Lab — Environment Setup
# Run this once to set up your dev environment

set -e
echo "[NFC Lab] Setting up development environment..."

# Check Python
python3 --version || { echo "[ERROR] Python 3 required"; exit 1; }

# Install Python dependencies for attack tools
pip3 install nfcpy scapy pyserial --break-system-packages 2>/dev/null || \
pip3 install nfcpy scapy pyserial

# Check Node.js for dashboard
node --version || echo "[WARN] Node.js not found — dashboard won't run"

# Install dashboard dependencies
if command -v node &> /dev/null; then
  echo "[*] Installing dashboard dependencies..."
  cd dashboard/backend && npm install && cd ../..
  cd dashboard/frontend && npm install && cd ../..
fi

# Install PlatformIO for firmware
pip3 install platformio --break-system-packages 2>/dev/null || \
pip3 install platformio

echo "[NFC Lab] Setup complete"
echo ""
echo "Next steps:"
echo "  1. Wire hardware per docs/runbooks/HARDWARE_SETUP.md"
echo "  2. Flash firmware: cd firmware/core && pio run --target upload"
echo "  3. Run dashboard: cd dashboard/backend && npm run dev"
