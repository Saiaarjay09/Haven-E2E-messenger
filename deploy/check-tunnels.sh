#!/bin/bash
# Prints the current public URLs for the three Haven services, and whether
# each of the six launchd jobs (3 services + 3 tunnels) is running.
# Only meaningful on a Mac set up per WEB_DEPLOYMENT.md's launchd option.

LOG_DIR="$HOME/Library/Logs/Haven"

echo "=== launchd job status ==="
launchctl list | grep com.haven || echo "(none running — did you load the plists in ~/Library/LaunchAgents/?)"

echo
echo "=== current public URLs ==="
for name in static accounts relay; do
    url=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' "$LOG_DIR/tunnel-$name.log" 2>/dev/null | tail -1)
    case "$name" in
        static)   label="Web app (open this)      " ;;
        accounts) label="Accounts server URL       " ;;
        relay)    label="Relay WebSocket URL       "; url="${url/https:/wss:}" ;;
    esac
    echo "$label: ${url:-not found yet}"
done
