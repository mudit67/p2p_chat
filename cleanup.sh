#!/bin/bash
# Cleanup script - Stop all E2EE chat servers

echo "=== E2EE Chat Cleanup ==="
echo ""

# Find and kill processes on port 8888
PIDS=$(lsof -ti:8888 2>/dev/null || true)

if [ -z "$PIDS" ]; then
    echo "✓ No servers running on port 8888"
else
    echo "Found server processes: $PIDS"
    for PID in $PIDS; do
        echo "Killing process $PID..."
        kill -9 $PID 2>/dev/null || true
    done
    sleep 1
    echo "✓ All servers stopped"
fi

echo ""
echo "Port 8888 is now free"
