# Current Haven links

- **Open the app:** https://saiaarjay09.github.io/Haven-E2E-messenger/

That's a GitHub Pages site (see
[.github/workflows/pages.yml](.github/workflows/pages.yml)) serving
the exact same client as the Tailscale-hosted copy below, just from
GitHub's own infrastructure instead of relying on
`webapp/serve_static.py` being up — so the app loads even if that one
process is briefly down. It still talks to the backend URLs below,
which have NOT moved: GitHub Pages is static-only and can't run
Python, so the accounts service and relay still have to be running
somewhere reachable (currently: the same Mac as always) for sign-up,
login, and messaging to actually work. The old
`https://haven.taila6d3cb.ts.net` static site still works too — both
are just different front doors to the same backend.

These backend URLs are permanent — tied to a Tailscale Funnel
hostname, not a short-lived tunnel, so unlike this file's earlier
history they should never need to change. See
[WEB_DEPLOYMENT.md](WEB_DEPLOYMENT.md) for how this is set up.

- **Accounts server URL:** https://haven.taila6d3cb.ts.net:8443
- **Relay WebSocket URL:** wss://haven.taila6d3cb.ts.net:10000
