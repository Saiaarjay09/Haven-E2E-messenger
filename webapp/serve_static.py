"""Static file server for the hosted web client (webapp/static/), with
the security headers Python's stock `http.server` doesn't set at all.
Drop-in replacement for `python3 -m http.server` — same CLI shape
(positional port, --bind, --directory) — see deploy/com.haven.static.plist.

Run: python3 -m webapp.serve_static 8899 --bind 127.0.0.1 --directory webapp/static
"""

from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Deployment-specific — see WEB_DEPLOYMENT.md. Self-hosting this on a
# different domain? Update CSP_CONNECT_HOST to match, or the accounts
# API / relay WebSocket calls this page makes will be blocked by its
# own Content-Security-Policy below. The trailing `:*` on each entry
# matches any port on that host (accounts and relay live on different
# ports of the same Tailscale Funnel hostname — see CURRENT_LINKS.md).
CSP_CONNECT_HOST = "haven.taila6d3cb.ts.net"

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob: https://*.giphy.com; "
    "media-src 'self' blob:; "
    f"connect-src 'self' https://{CSP_CONNECT_HOST}:* wss://{CSP_CONNECT_HOST}:* "
    "http://localhost:8000 ws://localhost:8444 https://*.giphy.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'"
)


class SecureHandler(SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # Unlike the accounts API's own headers, THIS origin is what
        # actually calls getUserMedia for calls (calls.js/groupcalls.js)
        # — allow camera/mic for same-origin use, but still deny any
        # other site from framing/embedding this page to try to use them.
        self.send_header("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
        super().end_headers()

    # SimpleHTTPRequestHandler logs every request to stderr by default;
    # matches what launchd already captures for the other two services
    # (see their StandardErrorPath), so left as the base class default.


def main() -> None:
    parser = argparse.ArgumentParser(description="Haven static file server with security headers")
    parser.add_argument("port", type=int, nargs="?", default=8899)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--directory", default=".")
    args = parser.parse_args()

    def handler_factory(*a, **kw):
        return SecureHandler(*a, directory=args.directory, **kw)

    with ThreadingHTTPServer((args.bind, args.port), handler_factory) as httpd:
        print(f"[haven-static] serving {args.directory} on {args.bind}:{args.port} with security headers")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
