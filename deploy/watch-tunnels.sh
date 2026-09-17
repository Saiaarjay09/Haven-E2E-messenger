#!/bin/bash
# Cloudflare quick tunnels can be evicted server-side at any time (no
# fixed schedule observed — anywhere from hours to a couple of days).
# When that happens, the local cloudflared process does NOT exit or
# crash; it just retries forever logging "Unauthorized: Tunnel not
# found", so launchd's own KeepAlive/crash-restart never notices
# anything is wrong. This script is the thing that actually notices:
# run periodically via com.haven.tunnel-watchdog.plist, it checks
# whether each tunnel's current public URL is actually reachable, and
# force-restarts (launchctl kickstart -k) any tunnel that isn't, so it
# re-establishes a fresh connection (and a new URL) on its own within
# one check interval instead of staying down until a human notices.
#
# This does NOT solve the underlying "the URL changes every time this
# happens" problem — quick tunnels have no permanent-URL option, only a
# named tunnel on a real domain does (see WEB_DEPLOYMENT.md Option C).
# It only bounds how long an outage lasts.

LOG_DIR="$HOME/Library/Logs/Haven"
UID_NUM=$(id -u)

check_and_restart() {
    local name="$1"
    local url
    url=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' "$LOG_DIR/tunnel-$name.log" 2>/dev/null | tail -1)
    if [ -z "$url" ]; then
        echo "$(date -Iseconds) $name: no URL found in log yet, skipping"
        return
    fi
    # Deliberately no -f: an HTTP-level error status (e.g. the relay's
    # WebSocket-only endpoint answering a plain GET with a 4xx) still
    # means the tunnel itself is up and reachable. Only an actual
    # transport failure (DNS/connect/TLS/timeout - what a dead,
    # evicted tunnel produces) should count as down.
    if ! curl -s --max-time 8 -o /dev/null "$url"; then
        echo "$(date -Iseconds) $name: $url unreachable, restarting tunnel-$name"
        launchctl kickstart -k "gui/$UID_NUM/com.haven.tunnel-$name"
    fi
}

check_and_restart static
check_and_restart accounts
check_and_restart relay
