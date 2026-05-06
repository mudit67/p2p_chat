#!/bin/bash
# Cleanup script - Stop LAN chat clients / old relay server

echo "=== E2EE LAN Chat Cleanup ==="
echo ""

for PORT in 8888 9001 9002 9003 9999; do
    PIDS=$(lsof -ti:$PORT 2>/dev/null || true)
    if [ ! -z "$PIDS" ]; then
        echo "Port $PORT -> stopping: $PIDS"
        for PID in $PIDS; do
            kill -9 $PID 2>/dev/null || true
        done
    fi
done

echo "✓ Cleanup complete"
