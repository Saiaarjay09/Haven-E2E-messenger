# How Haven's code works

This is a technical tour of the repository: the overall architecture,
then what every individual file does. `README.md` is the pitch and
quick-start; `ROADMAP.md` is the phase-by-phase history and known
tradeoffs; `Instructions_and_Link.md` is the end-user setup guide. This
document is the one to read to understand the *code* — how a message
actually gets from your keyboard to your friend's screen, and which
file is responsible for which part of that.

## The big picture

Haven exists in two parallel forms that speak the **same wire
protocol**, so a desktop user and a web user can message each other
directly:

1. **The desktop app** (`haven/` + `main.py`) — a local Python/Tkinter
   application. Everything happens on your machine: your identity key
   is generated locally, encrypted with your password locally, and
   never sent anywhere. There is no account server; two instances on
   the same Wi-Fi find each other via a UDP broadcast, and anyone
   further away is reached through a relay server (self-hosted by
   whoever you're talking to, or a shared one).

2. **The hosted web app** (`webapp/`) — a browser client (plain
   HTML/CSS/JS, no build step, no framework) plus two small Python
   services: an accounts server (for sign-up/login/password reset,
   since a website needs *some* way to find "your" identity key again
   on a different device) and a reuse of the same relay server the
   desktop app uses. The browser generates and encrypts your identity
   key exactly the way the desktop app does — the crypto in
   `webapp/static/js/crypto.js` is a byte-for-byte JavaScript port of
   `haven/crypto.py`, verified against it with shared test vectors —
   but a website's code is delivered fresh by a server on every page
   load, which is a fundamentally different trust model than a native
   app you install once. `webapp/README.md` explains that tradeoff in
   full; it's real and worth reading if you're deciding how much to
   trust this for something sensitive.

Both forms share the same core idea for every message:

- Two people each have a long-term **identity key** (X25519). The
  first time they connect, they run a **3-DH handshake** (a simplified
  X3DH, since — unlike Signal's async design — both sides are online
  at handshake time): each side also generates a one-time **ephemeral
  key**, and the shared secret mixes identity and ephemeral keys
  together in both directions. That gives mutual authentication (you
  know who you're really talking to) and forward secrecy for the
  handshake itself.
- From that shared secret, each direction gets its own **symmetric
  ratchet** — a one-way hash chain (the "chain" half of Signal's
  Double Ratchet, without the periodic DH re-keying step, which is
  tracked in `ROADMAP.md` as a future upgrade). Every message advances
  the chain and derives a fresh key, so a compromised key today can't
  decrypt yesterday's messages.
- Messages themselves are AES-256-GCM (authenticated encryption —
  tampering or a wrong key is detected, not silently accepted).
- A relay server (self-hosted, direct-LAN or WebSocket) only ever sees
  *who* is sending to *whom* and opaque ciphertext — never plaintext,
  never a private key.

## Repository layout

```
haven/            desktop app + the shared crypto/protocol core
webapp/           hosted accounts service + the browser client
  static/         the actual website (HTML/CSS/JS, no build step)
    js/           one file per feature area, loaded as plain <script> tags
deploy/           launchd/systemd units and shell scripts for running
                  the hosted deployment as background services
test_*.py         headless smoke tests, one per phase, at the repo root
main.py           desktop app entry point
*.md              docs — see the top of each for what it covers
```

---

## `haven/` — the desktop app and the shared protocol core

### `haven/crypto.py`
The cryptographic heart of the whole project, and the **reference
implementation** everything else (including the browser's JS) is
checked against. Defines: X25519 key generation (`KeyPair`), the 3-DH
handshake (`compute_shared_root_key`), the per-direction symmetric
ratchet (`RatchetSession` — HMAC-based chain-key derivation,
AES-256-GCM message encryption), password/recovery-phrase key
derivation (`derive_split_keys`, built on scrypt then HKDF — the same
split-key pattern the accounts service relies on), an authenticated
encryption helper for local storage (`encrypt_authenticated` /
`decrypt_authenticated`), and a deliberately *unauthenticated*
CTR-mode cipher used only for backup files (a wrong password there
should silently produce garbage, not a clean "wrong password" error —
see the module docstring for why that matters against offline
brute-forcing). Also computes the human-readable **safety number**
(`fingerprint`) two people compare out-of-band to detect a
man-in-the-middle.

### `haven/identity.py`
Local accounts for the desktop app. "Signing in" means decrypting your
own identity key file on disk with your password — there is no server
involved at all here. Handles account creation, password-based
unlock, the per-account data directory (`~/.haven/<username>/`), and
wires in `recovery.py` so a second, phrase-encrypted copy of your
identity key exists for password resets.

### `haven/recovery.py`
Generates and validates 12-word recovery phrases from the standard
2048-word BIP39 English wordlist (`haven/data/wordlist.txt` — chosen
for the phrase's human-transcription safety, not for BIP39's mnemonic
math, which isn't used here). Shared by both the desktop app's
"forgot password" flow and the web app's server-mediated equivalent.

### `haven/network.py`
The transport and handshake layer: `NetworkManager` runs the
HELLO/HELLO_ACK exchange, derives the ratchet session from it, and
sends/receives length-prefixed JSON frames over either a direct LAN
TCP socket or a relay connection — the framing and message shapes are
identical either way, which is what lets `relay_server.py` and the
browser's `network.js` interoperate with this file without either
side needing to know which transport the other is using.

### `haven/discovery.py`
LAN peer discovery: a small UDP broadcast every few seconds announcing
your username, identity public key, and listening port. This is the
*entire* directory service on a LAN — there's no server to trust,
which is also why verifying a new contact's safety number matters (see
`crypto.py`'s `fingerprint`).

### `haven/relay_client.py`
The desktop app's client for talking to a relay server: registers via
a DH proof-of-possession challenge (proving you hold the private key
for the identity you claim, without a password), then sends/receives
opaque payloads addressed by identity key, with automatic reconnect.

### `haven/relay_server.py`
The self-hostable relay: store-and-forward routing for encrypted
messages between clients who aren't on the same LAN. Speaks **two
transports into the same routing table** — raw TCP (desktop clients)
and WebSocket (browser clients, which can't open raw sockets) — so a
desktop user and a web user registered on the same relay can reach
each other transparently. Queues a message in a local SQLite file if
the recipient is offline, flushing it in order once they reconnect on
either transport. Sees who's talking to whom and when (coarse
metadata, the same tradeoff Signal's own servers accept) but never
plaintext.

### `haven/storage.py`
Local, encrypted-at-rest chat history and session state (SQLite). This
is deliberately a **second** encryption layer, separate from the wire
ratchet: ratchet keys are a one-way chain, so you can't use them to
re-decrypt an old message for "scroll up and re-read" — instead,
plaintext is re-encrypted once on receipt with a storage key derived
(via HKDF) from your identity key, independent of the ratchet's
one-way advancement.

### `haven/backup.py`
Export/import an encrypted, portable backup file for one account. Uses
the *unauthenticated* CTR cipher from `crypto.py` rather than the
authenticated one local storage uses — deliberately, so that decrypting
a stolen backup file with the wrong password silently produces
plausible-looking garbage instead of a clean "wrong password" error,
removing the cheap oracle an offline brute-forcer would otherwise get
from every guess.

### `haven/groups.py`
Group chat, built entirely on top of the existing 1:1 encrypted
channel — there is no separate group transport or group server-side
concept. Uses a **sender-keys** design (the same one Signal/WhatsApp
use): each member has one outgoing symmetric chain used for everything
they send to the group, and holds a copy of every other member's chain
to decrypt what they send. New members can't decrypt history from
before they joined; removing a member rotates every remaining member's
sender key so the removed member can't keep reading forward either.

### `haven/attachments.py`
Images/GIFs/stickers as a message "kind" (`image`/`gif`/`sticker`)
whose content is a small JSON envelope (filename, mime type, base64
bytes) instead of a plain string — no changes needed anywhere else,
since the rest of the pipeline already treats message content as an
opaque string. Caps attachments at 8 MB.

### `haven/calls.py`
Voice/video calls over the *same* encrypted 1:1 channel as text —
deliberately no WebRTC/ICE/STUN/TURN and no separate media key
exchange; call signaling and every audio/video chunk are just
ratchet-encrypted messages (`kind="call"`). The honest tradeoff (every
chunk pays for a full encrypted message, in-order/reliable delivery
rather than real-time-media's "drop late packets") is walkie-talkie
quality by design, not a bug. Uses `sounddevice` and `opencv-python`
for actual mic/camera capture, both optional.

### `haven/ai.py`
On-device AI: a local LLM assistant (`llama-cpp-python`), speech-to-text
(`faster-whisper`), and translation (`argos-translate`) — all inference
runs on your machine, nothing is sent to a cloud API (the one exception
being a one-time model-weights download before first use).

### `haven/config.py`
A tiny per-account JSON settings file (currently just relay server
addresses), merged rather than overwritten on save so unrelated
settings don't clobber each other.

### `haven/gui.py`
The Tkinter desktop UI — by far the largest file in `haven/` (1,600+
lines). Wires together every module above into sign-in/sign-up
screens, a LAN + contacts list, and chat windows (text, attachments,
calls, group management, AI features).

### `haven/__init__.py`
Just the package docstring and version number.

### `main.py`
The desktop app's entry point: `python3 main.py` calls
`haven.gui.main()`.

---

## `webapp/` — the hosted accounts service

### `webapp/accounts_server.py`
A FastAPI service providing what a website needs that a LAN app
doesn't: globally unique usernames and a way to find "your" identity
key again from any browser. Endpoints include `/api/signup`,
`/api/login`, `/api/username-available`, `/api/search-users` (powers
the sidebar's people search), `/api/forgot-password/verify` +
`/api/forgot-password/reset`, `/api/update-identity-pub` (a
self-healing directory backfill), `/api/translate` (proxies one call
audio clip to OpenAI's Whisper API for live captions, keeping the API
key server-side only), and `/api/contacts/sync` +
`/api/mutual-friends` (records that two accounts became mutual
contacts, purely to power the Suggested tab's "people you may know").
Authentication is **zero-knowledge**: the browser derives an
`auth_key` (sent here, bcrypt/Argon2id-hashed) and a separate `enc_key`
(never leaves the browser) from the same password via
`derive_split_keys` — this server can verify a login and gate access,
but can never decrypt anyone's stored identity key, even with full
database access. Every endpoint is behind a simple in-memory rate
limiter (`SimpleRateLimiter`).

### `webapp/accounts_db.py`
SQLite storage backing the service above. The `accounts` table stores,
per user: username, password/recovery salts and auth-key hashes, the
*encrypted* identity key blob (unreadable without `enc_key`, which
this server never has), the account's public identity key (not a
secret — it's what a contact card already hands out), and the scrypt
cost each credential was derived with (so raising the default cost for
new accounts doesn't break existing ones' passwords). A second table,
`contact_edges`, records mutual-contact pairs for the Suggested tab —
the module's docstring calls out explicitly that this is the one place
the server learns real social-graph information it didn't have before.

### `webapp/serve_static.py`
A drop-in replacement for `python3 -m http.server` that adds the
security headers (CSP, HSTS, X-Frame-Options, etc.) the stock server
doesn't set — serves `webapp/static/`.

### `webapp/generate_vectors.py`
A dev tool, not part of the running service: runs `haven/crypto.py`
(the Python reference implementation) against fixed inputs and writes
the outputs to `webapp/static/js/test_vectors.json`, which
`test_crypto.html` then checks the JavaScript port against — this is
how the two independent crypto implementations are proven to agree
byte-for-byte.

### `webapp/__init__.py`
Package docstring explaining the web app's different trust model
versus the desktop app.

---

## `webapp/static/` — the browser client

Plain HTML/CSS/JS loaded as ordinary `<script>` tags (no bundler, no
framework, no build step) — each file below defines one global object
(e.g. `Haven`, `HavenNetwork`) inside an IIFE, and `app.js` wires them
all together against the DOM.

### `index.html`
The entire app shell: login/signup screen, the sidebar (search,
Chats/Requests/Suggested/Settings tabs), chat area, and every modal
(recovery phrase, confirm dialogs, group management, call UI). Also
where every script tag's cache-busting `?v=N` query string lives — all
of them are bumped together on any static-file change, since browsers
otherwise cache these files aggressively. Loads a strict
Content-Security-Policy (via `serve_static.py`'s headers) that blocks
inline scripts entirely, which is why the test pages below load their
logic from separate `.js` files instead of inline `<script>` blocks.

### `js/crypto.js`
A byte-for-byte JavaScript port of `haven/crypto.py`, verified against
Python-generated test vectors (`test_vectors.json`) in
`test_crypto.html`. Implements X25519 from scratch (WebCrypto has no
native X25519/scrypt), scrypt key derivation, the ratchet, and
AES-GCM/HKDF via the browser's native WebCrypto where available. This
file is the one place correctness matters most in the entire browser
client — any bug here is a bug in the encryption itself.

### `js/scrypt-worker.js` + `js/scrypt-worker-client.js`
Runs the expensive scrypt password derivation inside a Web Worker
instead of the main thread, so signing in doesn't freeze the tab for
several seconds. `scrypt-worker.js` is the worker itself (just calls
into `crypto.js`); `scrypt-worker-client.js` is the main-thread handle
that posts requests to it and resolves promises when results come
back, reusing one worker for the page's lifetime.

### `js/network.js`
The browser equivalent of `haven/network.py` + `relay_client.py`
combined (a browser can only reach a relay, never open a raw LAN
socket): `RelayClient` manages the WebSocket connection and the DH
registration handshake; `NetworkManager` runs the same HELLO/HELLO_ACK
protocol as the desktop app and derives the same ratchet sessions.
This file also owns the **invite/accept contact gate**: a `hello` from
someone who isn't already an accepted (or mutually-pending) contact is
parked as a contact request instead of automatically completing the
handshake, surfaced via `onContactRequest` for the UI's Requests tab.

### `js/storage.js`
IndexedDB-backed local storage — the browser equivalent of
`haven/storage.py`. Stores contacts (including their invite-flow
`status`: `pending_out` / `pending_in` / `accepted`), ratchet session
state, and encrypted message history, using the same
"re-encrypt-at-rest with an identity-derived key" pattern as desktop.

### `js/auth.js`
`AccountsClient`: the browser's HTTP client for `accounts_server.py`
— signup, login, password reset, username search, and (newer) the
mutual-contact sync/suggestion calls. Derives `auth_key`/`enc_key` via
`crypto.js`, keeps the `auth_key` cached in memory for the rest of the
session (never persisted) so later authenticated calls don't need to
re-prompt for the password.

### `js/backup.js`
Export/import an encrypted portable backup of the browser account —
same "deniable" CTR cipher as the desktop app's `backup.py`, same
reasoning (no cheap oracle for an offline password-guessing attack).

### `js/groups.js`
Sender-keys group chat — the browser port of `haven/groups.py`, same
design (per-member outgoing chain, rotate-on-removal), riding the same
1:1 channel as everything else.

### `js/attachments.js`, `js/avatars.js`
Images/GIFs/audio/video as a message "kind" with a small JSON
envelope, matching `haven/attachments.py`'s wire format so a file sent
from one client type opens correctly on the other. `avatars.js` is the
same idea specialized for a small square profile picture.

### `js/giphy.js`
GIF search via Giphy's public API — talks directly to Giphy from the
browser (not private, same as browsing giphy.com); the chosen GIF is
then sent through the normal encrypted attachment channel.

### `js/calls.js`, `js/groupcalls.js`
Voice/video calls (1:1 and group), same no-WebRTC design as
`haven/calls.py`: signaling and audio/video chunks are just encrypted
messages. `groupcalls.js` fans audio/video out through the group's
existing sender-keys chains instead of a pairwise channel.

### `js/translation.js`
Live call captions/translation — the one deliberate exception to "this
app is private," clearly called out in its own header comment: a few
seconds of call audio is sent to OpenAI's Whisper API (via
`accounts_server.py`'s `/api/translate` proxy, so the OpenAI key never
reaches the browser) for translated captions during a call only.

### `js/app.js`
The largest file in the repo (~2,000 lines): all UI glue. Owns
`state` (the current identity, contacts, open chat, etc.), renders the
sidebar and message list, and wires every DOM event to the modules
above — including the invite-based contact flow (`sendContactRequest`,
the Requests tab's accept/decline, the Suggested tab's mutual-friend
suggestions) added most recently.

### `js/test_crypto_runner.js`, `js/test_e2e_runner.js`
The actual test logic for `test_crypto.html` and `test_e2e.html`
below — pulled into separate files (rather than inline `<script>`
blocks) specifically because the site's CSP blocks inline scripts.

### `test_crypto.html`
Loads `crypto.js` and `test_crypto_runner.js` to run the JS crypto port
against the Python-generated `test_vectors.json`, plus its own
ratchet-session round-trip tests, entirely in-browser.

### `test_e2e.html`
A fuller in-browser test: signup, login, relay connection, and a real
message exchange against the actually-running accounts and relay
services (not mocked).

---

## `deploy/` — running the hosted deployment as background services

Only relevant if you're self-hosting the web app long-term (see
`WEB_DEPLOYMENT.md`). Two service-manager formats are provided —
macOS `launchd` (`.plist` files) and Linux `systemd` (`.service`
files) — plus a few helper shell scripts:

- **`com.haven.accounts.plist` / `haven-accounts.service`** — runs
  `accounts_server.py`.
- **`com.haven.relay.plist` / `haven-relay.service`** — runs
  `relay_server.py`.
- **`com.haven.static.plist`** — runs `serve_static.py`.
- **`com.haven.tunnel-template.plist`** + **`watch-tunnels.sh`** +
  **`com.haven.tunnel-watchdog.plist`** — Cloudflare quick tunnels
  exposing the three services publicly, plus a watchdog script because
  a dead/evicted tunnel doesn't crash its process or trigger normal
  restart logic — the watchdog is what actually notices and recovers.
- **`publish-urls.sh` / `com.haven.publish-urls.plist`** — since quick
  tunnel URLs change on every restart, this periodically rewrites
  `CURRENT_LINKS.md` with whatever URLs are live right now and pushes
  it, so that file is always a stable, accurate pointer.
- **`renew-relay-cert.sh` / `com.haven.cert-renew.plist`** — renews the
  relay's own TLS certificate (the relay terminates its own TLS rather
  than relying on the tunnel to do it — see `WEB_DEPLOYMENT.md`) and
  restarts the relay only when the cert actually changed.
- **`check-tunnels.sh`** — a manual status check: prints current public
  URLs and whether all six launchd jobs are actually running.

---

## `test_*.py` — headless smoke tests (repo root)

Each corresponds to one build phase and exercises the real code (real
sockets, a real relay process, a real running accounts server — not
mocks) rather than just unit-testing individual functions:

- **`test_smoke.py`** — Phase 1: full handshake + ratchet message
  exchange over real TCP, plus storage and backup round-trips.
- **`test_recovery_smoke.py`** — desktop "forgot password": both
  unlock paths (password and phrase) reach the same identity key.
- **`test_relay_smoke.py`** — Phase 2: two clients with no shared LAN,
  talking purely through a real relay process, including offline
  message queuing.
- **`test_ws_relay_smoke.py`** — Phase 7b: the relay's WebSocket
  transport (what browsers use), proven equivalent to the TCP path.
- **`test_multi_relay_smoke.py`** — an account registered with several
  relays at once, each contact remembering which one reaches them.
- **`test_group_smoke.py`** — Phase 3: sender-keys group messaging
  across three independent clients over a real relay, including the
  "new member can't read history" and "removed member can't read
  forward" guarantees.
- **`test_attachment_smoke.py`** — Phase 4: the full encode → encrypt
  → transport → decrypt → decode round trip for images/GIFs, 1:1 and
  group, plus the oversized-attachment rejection path.
- **`test_call_smoke.py`** — Phase 5: call signaling and the encrypted
  media pipeline over a real relay (synthetic audio/video bytes in
  place of real mic/camera hardware, which this environment can't
  grant permission for).
- **`test_ai_smoke.py`** — Phase 6: on-device AI features against real
  local models (with the one-time-download pieces made skippable).
- **`test_webapp_accounts_smoke.py`** — Phase 7a: the hosted accounts
  service, driven over real HTTP against a real running uvicorn
  instance, using a Python stand-in for what a browser client does.

---

## Dependencies

- **`requirements.txt`** (repo root) — the desktop app's dependencies
  (`haven/`, `main.py`): `cryptography` for the crypto core, `pillow`
  for images/avatars, `sounddevice`/`numpy`/`opencv-python-headless`
  for calls, and `faster-whisper`/`argostranslate`/`llama-cpp-python`/
  `certifi` for on-device AI.
- **`webapp/requirements.txt`** — the hosted accounts service's own,
  separate dependencies: `fastapi`/`uvicorn` (the server itself),
  `argon2-cffi` (current password hashing) plus `bcrypt` (kept only to
  verify pre-existing legacy hashes), `python-multipart` (for
  `/api/translate`'s file upload), and `requests` (also used by
  `test_webapp_accounts_smoke.py`'s simulated-browser client).

The two are intentionally separate — running the desktop app never
requires installing FastAPI, and running just the accounts service
never requires `llama-cpp-python`.

---

## Top-level docs

- **`README.md`** — the project pitch, desktop quick-start, and links
  to everything else.
- **`ROADMAP.md`** — phase-by-phase build history and each phase's
  known tradeoffs; the closest thing to a changelog with reasoning
  attached.
- **`WEB_DEPLOYMENT.md`** — how to actually run the three hosted-app
  processes, from a quick no-TLS test to a real always-on deployment.
- **`CURRENT_LINKS.md`** — the live, permanent URL(s) for the hosted
  deployment (kept accurate automatically by `deploy/publish-urls.sh`).
- **`Instructions_and_Link.md`** — an end-user (not developer) setup
  and usage guide with annotated screenshots.
- **`webapp/README.md`** — the web app's design doc: exactly what
  changes (and what trust you're extending) versus the desktop app.

---

## Following one message end-to-end

To tie the files above together, here's what actually happens when you
type a message and hit send in the browser client, to someone you're
already an accepted contact with:

1. `app.js`'s send handler calls `network.js`'s `NetworkManager.sendText`.
2. That calls `conn.session.encrypt` — the ratchet session object from
   `crypto.js`, which derives a fresh message key from the chain key,
   encrypts with AES-256-GCM, and advances the chain.
3. `storage.js` re-encrypts the *plaintext* with your local storage key
   and saves it to IndexedDB (your own readable chat history) —
   independent of the ratchet ciphertext, which is one-way and can't
   be used to re-decrypt for display later.
4. `network.js` hands the ratchet ciphertext to `RelayClient.sendTo`,
   which wraps it in a `{"type": "relay", "to": <their identity_pub>,
   "payload": {...}}` WebSocket frame.
5. `haven/relay_server.py` receives that frame, looks up the
   recipient's identity key in its routing table, and either forwards
   it immediately (if they're connected — desktop or web, doesn't
   matter which transport) or queues it in SQLite until they reconnect.
   It never decrypts anything; it can't.
6. On the recipient's side — whether that's `network.js` in another
   browser tab or `haven/network.py` on someone's desktop app — the
   frame arrives, gets matched to the right ratchet session by sender
   identity key, decrypted, and handed to storage for the same
   re-encrypt-at-rest treatment, then rendered in their chat window.

Every step above is the same whether both people are on the desktop
app, both on the web app, or one of each — that cross-compatibility is
the entire point of keeping `haven/crypto.py` and `crypto.js` (and
`haven/network.py` and `network.js`) in lockstep.
