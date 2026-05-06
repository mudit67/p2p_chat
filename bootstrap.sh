#!/bin/bash
# E2EE LAN UDP Chat Bootstrap
set -e

echo "=== E2EE LAN UDP Chat Setup ==="
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Error: uv not found. Install with:"
    echo "curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo "✓ uv package manager detected"
echo ""

# Install dependencies
echo "Installing dependencies..."
uv pip install PyNaCl blake3 msgpack textual --system
echo "✓ Dependencies installed"
echo ""

# Create directories
echo "Creating project directories..."
mkdir -p keys logs
echo "✓ Directories created"
echo ""

# Generate keys
echo "Generating user keypairs..."
python3 -m src.encrypt.keygen alice bob charlie
echo "✓ User keys generated"
echo ""

echo "==================================="
echo "   SETUP COMPLETE - READY TO USE   "
echo "==================================="
echo ""
echo "Run LAN peers in separate terminals:"
echo ""
echo "  Terminal 1: python3 -m src.encrypt.client alice udp 9001"
echo "  Terminal 2: python3 -m src.encrypt.client bob udp 9002"
echo "  Terminal 3: python3 -m src.encrypt.client charlie udp 9003"
echo ""
echo "Commands:"
echo "  • /to <peer8> <message> to target one peer"
echo "  • Type message + Enter/Click Send"
echo "  • Press 'L' to verify log chain"
echo "  • Ctrl+C to exit client"
echo ""
echo "==================================="
echo ""
