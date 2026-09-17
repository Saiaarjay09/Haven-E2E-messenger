#!/bin/bash
# Cloudflare quick tunnel URLs change every time a tunnel restarts
# (crash, reboot, or a Cloudflare-side eviction the watchdog script
# recovers from). Re-sending a fresh link to everyone by hand each time
# doesn't scale, so this publishes the current URLs to CURRENT_LINKS.md
# in the repo instead — one stable page (the file's GitHub URL) that
# always reflects reality, checked and updated every 2 minutes by
# com.haven.publish-urls, but only actually committed+pushed when a URL
# genuinely changed.

REPO_DIR="/Users/saideep/Developer/haven"
LOG_DIR="$HOME/Library/Logs/Haven"
LINKS_FILE="$REPO_DIR/CURRENT_LINKS.md"

cd "$REPO_DIR" || exit 1

get_url() {
    grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' "$LOG_DIR/tunnel-$1.log" 2>/dev/null | tail -1
}

static_url=$(get_url static)
accounts_url=$(get_url accounts)
relay_url=$(get_url relay)
relay_wss_url="${relay_url/https:/wss:}"

if [ -z "$static_url" ] || [ -z "$accounts_url" ] || [ -z "$relay_url" ]; then
    echo "$(date -Iseconds) publish-urls: one or more URLs not found yet, skipping"
    exit 0
fi

# Compare against what's already committed, not a timestamp (which would
# always differ and cause a commit every single cycle).
current_static=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' "$LINKS_FILE" 2>/dev/null | sed -n '1p')
current_accounts=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' "$LINKS_FILE" 2>/dev/null | sed -n '2p')
current_relay=$(grep -o 'wss://[a-zA-Z0-9.-]*\.trycloudflare\.com' "$LINKS_FILE" 2>/dev/null | sed -n '1p')

if [ "$static_url" = "$current_static" ] && [ "$accounts_url" = "$current_accounts" ] && [ "$relay_wss_url" = "$current_relay" ]; then
    exit 0
fi

cat > "$LINKS_FILE" <<EOF
# Current Haven links

Auto-updated by \`deploy/publish-urls.sh\` whenever the tunnel URLs
change (checked every 2 minutes). **Don't edit this file by hand** —
it will be overwritten on the next automatic update. See
[WEB_DEPLOYMENT.md](WEB_DEPLOYMENT.md) for what these mean.

Last updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

- **Open the app:** $static_url
- **Accounts server URL:** $accounts_url
- **Relay WebSocket URL:** $relay_wss_url
EOF

git add "$LINKS_FILE"
git commit -m "Update current tunnel links" >/tmp/haven-publish-urls.log 2>&1
git push >>/tmp/haven-publish-urls.log 2>&1
echo "$(date -Iseconds) publish-urls: links changed, committed and pushed"
