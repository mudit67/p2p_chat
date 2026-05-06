#!/bin/bash
# E2EE TUI Chat Bootstrap
set -e

echo "=== E2EE Chat System Setup ==="
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

# Generate TLS certs
echo "Generating TLS certificates..."
if [ ! -f key.pem ] || [ ! -f cert.pem ]; then
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
        -days 365 -nodes -subj "/CN=localhost" -batch 2>/dev/null
    echo "✓ TLS certificates generated"
else
    echo "✓ TLS certificates already exist"
fi
echo ""

# Create directories
echo "Creating project directories..."
mkdir -p keys logs
echo "✓ Directories created"
echo ""

# Generate keys
echo "Generating user keypairs..."
python setup.py alice
python setup.py bob
echo "✓ User keys generated"
echo ""

# Check if port 8888 is already in use
echo "Checking for existing server..."
EXISTING_PID=$(lsof -ti:8888 2>/dev/null || true)
if [ ! -z "$EXISTING_PID" ]; then
    echo "⚠ Port 8888 already in use by PID: $EXISTING_PID"
    echo "Killing existing process..."
    kill -9 $EXISTING_PID 2>/dev/null || true
    sleep 1
    echo "✓ Cleaned up existing server"
fi
echo ""

# Start relay server
echo "Starting relay server..."
python -m src.encrypt.server &
SERVER_PID=$!
sleep 2  # Wait for bind

# Check if server started successfully
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "✗ Server failed to start"
    echo "Check if port 8888 is still in use: lsof -i:8888"
    exit 1
fi

echo "✓ Server started (PID: $SERVER_PID)"
echo ""

echo "==================================="
echo "   SETUP COMPLETE - READY TO USE   "
echo "==================================="
echo ""
echo "Run clients in separate terminals:"
echo ""
echo "  Terminal 1: python -m src.encrypt.client alice"
echo "  Terminal 2: python -m src.encrypt.client bob"
echo ""
echo "Commands:"
echo "  • Type message + Enter/Click Send"
echo "  • Press 'L' to verify log chain"
echo "  • Ctrl+C to exit client"
echo ""
echo "Stop server:"
echo "  kill $SERVER_PID"
echo ""
echo "==================================="
echo ""

# Keep script running
echo "Press Ctrl+C to stop server and exit..."
wait $SERVER_PID
