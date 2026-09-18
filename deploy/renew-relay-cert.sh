#!/usr/bin/env bash
# Renews the relay's own TLS cert (see WEB_DEPLOYMENT.md's "relay
# terminates its own TLS" section for why the relay needs this at all,
# rather than relying on Tailscale Funnel to terminate TLS for it) and
# restarts the relay service only when the cert actually changed —
# `tailscale cert` is idempotent and safe to run on every tick, it just
# won't reissue a still-valid cert.
set -euo pipefail

# Adjust these if your setup differs from the default Haven layout.
# TAILSCALE must be a full path: launchd jobs run with a minimal PATH
# that doesn't include Homebrew's/tailscale's own install location.
DOMAIN="haven.taila6d3cb.ts.net"
CERT_DIR="$HOME/Library/Application Support/Haven/tls"
TAILSCALE="/usr/local/bin/tailscale"

mkdir -p "$CERT_DIR"
old_hash=""
[ -f "$CERT_DIR/haven.crt" ] && old_hash=$(shasum -a 256 "$CERT_DIR/haven.crt" | awk '{print $1}')

"$TAILSCALE" cert --cert-file="$CERT_DIR/haven.crt" --key-file="$CERT_DIR/haven.key" "$DOMAIN"

new_hash=$(shasum -a 256 "$CERT_DIR/haven.crt" | awk '{print $1}')
if [ "$old_hash" != "$new_hash" ]; then
  echo "$(date): cert renewed, restarting com.haven.relay"
  launchctl kickstart -k "gui/$(id -u)/com.haven.relay"
fi
