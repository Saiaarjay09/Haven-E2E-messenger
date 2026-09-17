# Haven web app — Phase 7

Everything in `haven/` (the desktop app) runs entirely on your machine:
keys are generated locally, encrypted locally, and never touch a server
you don't control. Turning that into "a real website my friends visit
and sign up on, no install needed" is a genuinely different trust model,
not just a different UI — this document explains exactly what changes,
what's built so far, and what's still ahead.

**Want to actually put this live so a friend can use it?** See
`WEB_DEPLOYMENT.md` at the repo root for step-by-step hosting
instructions. This document is about the design and tradeoffs; that one
is about running the three processes involved.

## The tradeoff this accepts, stated plainly

A native app's code is fixed the moment you install it — you (or anyone)
can audit it once, and it doesn't silently change. A web app's code is
whatever the server sends your browser **on every single page load**. If
the browser is the thing running your encryption (generating keys,
encrypting messages, holding your decrypted identity in memory), then a
compromised or dishonest server can serve subtly modified JavaScript that
quietly exfiltrates keys or plaintext — and there is no way for an
ordinary user to detect this by using the app normally. This is exactly
why Signal and WhatsApp avoid pure browser-based crypto as a primary
client (WhatsApp Web mirrors an already-paired phone instead of being a
first-class encrypted client; Signal Desktop is a fixed-code Electron
app, not a page reloaded from a server).

Building this phase means accepting that risk in exchange for
"no install, works in any browser, log in from anywhere." Everything
below is designed to minimize what a compromised server could do
*beyond* that irreducible risk — but it cannot eliminate the irreducible
risk itself. If that tradeoff isn't worth it for a particular use case,
the desktop app (or the "local browser UI only for me" option that was
turned down when this phase was scoped) doesn't have this problem at all.

## What's built: the accounts service (Phase 7a)

`accounts_server.py` (FastAPI) + `accounts_db.py` (SQLite) provide:

- **Globally unique usernames** — a real central registry, which is new
  centralized state the desktop app never needed. This is the direct
  cost of "no two Haven users anywhere can pick the same name."
- **Zero-knowledge password auth**, the same pattern Bitwarden and
  similar services use: your password never reaches this server. The
  client derives ONE expensive key from your password (scrypt) and then
  splits it via HKDF into two independent values —
  `crypto.derive_split_keys()`:
  - `auth_key` — sent to the server, bcrypt-hashed there, used only to
    prove it's really you logging in.
  - `enc_key` — **never leaves the client.** It's the only thing that can
    decrypt your stored identity blob. Even a fully compromised server
    (database dump *and* control of its running code from that point
    forward) cannot derive `enc_key` from `auth_key` — HKDF is one-way,
    and the split is by design cryptographically independent. It also
    still can't retroactively decrypt anything from before the compromise.
- **Forgot password, via recovery phrase** — the exact same split-key
  pattern again, keyed by a 12-word phrase (`haven/recovery.py`, the
  standard BIP39 English wordlist) instead of a password. `/verify` and
  `/reset` re-check the phrase independently rather than trusting a
  chained token, and the phrase itself keeps working for next time.

Run it:
```bash
pip install -r webapp/requirements.txt
export HAVEN_ACCOUNTS_DB=haven_accounts.db   # optional, defaults shown
uvicorn webapp.accounts_server:app --host 0.0.0.0 --port 8000
```

See `test_webapp_accounts_smoke.py` — it drives a real running instance
over real HTTP with a Python stand-in for what a browser client does,
which was in turn the protocol spec the actual JS client (below) follows
exactly: derive keys the same way, hit the same endpoints, in the same
order.

CORS is wide open (`allow_origins=["*"]`) deliberately, not as an
oversight: every request here carries its own explicit `auth_key` in the
JSON body rather than a browser-attached cookie/session, so there's no
ambient credential for a stricter origin policy to protect — the
CSRF-style attack that CORS restrictions normally prevent doesn't apply
to this API's shape. A production deployment MAY still restrict origins
for defense in depth; it isn't required for the auth model to be sound.

### API summary

| Endpoint | Purpose |
|---|---|
| `GET /api/username-available?username=` | Check before signup |
| `POST /api/signup` | Create an account (409 if the name is taken) |
| `GET /api/login-salt?username=` | Fetch the salt needed to derive `auth_key` |
| `POST /api/login` | Returns the encrypted identity blob if `auth_key` matches |
| `GET /api/recovery-salt?username=` | Salt for the recovery-phrase derivation |
| `POST /api/forgot-password/verify` | Recover the identity via phrase, no password needed |
| `POST /api/forgot-password/reset` | Set a new password after recovering via phrase |

A single in-memory rate limiter guards login/signup/recovery (10-ish
attempts per minute per username) — fine for one process, the same
honest single-process tradeoff `haven/relay_server.py` already has (see
main `ROADMAP.md`); a real multi-instance deployment would need a shared
store instead.

## What's built: a real, working browser chat client (Phases 7b-7d)

Two people can sign up, add each other, and exchange real end-to-end
encrypted text messages entirely in the browser — verified end-to-end,
not just unit-tested. Run it:

```bash
pip install -r requirements.txt -r webapp/requirements.txt
uvicorn webapp.accounts_server:app --port 8000 &
python3 -m haven.relay_server --port 8443 --ws-port 8444 &
python3 -m http.server 8899 --directory webapp/static
```
Then open `http://localhost:8899` in two browser tabs (or two devices).

### 7b — WebSocket relay transport
`haven/relay_server.py` now listens on a WebSocket port (`--ws-port`,
default 8444) alongside its original TCP port — same handshake, same
frame shapes, ONE shared routing table and message queue, so a browser
client and a desktop client on the same relay reach each other
transparently. See `test_ws_relay_smoke.py`, which includes the actual
interop case: a TCP client and a WebSocket client on the same relay
exchanging a handshake.

### 7c — Browser crypto engine + storage + network (`webapp/static/js/`)
- **`crypto.js`** is a byte-for-byte port of `haven/crypto.py`: X25519
  (via native WebCrypto), the 3-DH handshake, the symmetric ratchet,
  AES-256-GCM/CTR, HKDF, and — since WebCrypto has no native scrypt — a
  from-spec scrypt implementation (Salsa20/8 + BlockMix + ROMix, with
  WebCrypto's PBKDF2 doing the outer calls). This is the part that
  mattered most to get right, so it's the most heavily verified code in
  the whole project: `test_crypto.html` checks it against **three of
  scrypt's own official RFC 7914 test vectors** (independent ground
  truth, not just self-consistency) AND against 20+ vectors generated
  directly from `haven/crypto.py` for every custom primitive
  (fingerprint, HKDF, the handshake, the ratchet, `dh_proof`,
  `derive_split_keys`), confirming the browser and desktop
  implementations produce **identical output for identical input** —
  plus full round-trip and security-property checks (out-of-order
  rejection, tamper detection, wrong-key-gives-garbage for the deniable
  backup cipher).
- **`storage.js`** is the IndexedDB equivalent of `haven/storage.py`:
  same design, message content decrypted once and re-encrypted at rest
  with an identity-derived key, independent of the ratchet.
- **`network.js`** is the relay-only equivalent of `haven/network.py` —
  a browser can't open raw TCP/UDP, so unlike the desktop app there's no
  direct-LAN path here; every contact is reached through a relay.
- **`auth.js`** is the reference browser implementation of the Phase 7a
  zero-knowledge protocol: `derive_split_keys`, then hit the accounts
  API in the documented order.

### 7d — UI (`webapp/static/index.html`, `app.js`)
Sign up or log in, see a real 12-word recovery phrase once (shown inline,
not via a JS `alert()` — those are unreliable to copy from and hard to
test), add a contact by pasting their card, see the same safety number
your contact sees, verify it, and chat. Verified two ways:
- `test_e2e.html` drives the actual `storage.js`/`network.js`/`auth.js`
  stack (two independent identities, both hitting a real running
  accounts service and relay) and checks 13 properties automatically:
  signup, login, the full message round trip in both directions,
  encrypted local history, and — including the complete recovery-phrase
  password reset flow against the live server.
- Manually driven in a real browser across two tabs: signup, login,
  contact exchange, live bidirectional messaging, and confirming a
  received message survives a full page reload (recovered from
  encrypted IndexedDB storage, not just in-memory state).

Chat history lives in IndexedDB, scoped per-account (`haven-<username>`)
and per-browser — it's never sent to any server, which also means it
doesn't follow you to a different browser or device on its own. `backup.js`
covers that: "Backup…" once logged in exports your identity key, contacts,
and full message history as a single password-protected `.havenbackup`
file (`HAVEN-BACKUP-V1`), using the exact same format as the desktop app's
`haven/backup.py` — same scrypt-derived key, same deniable AES-CTR cipher,
so a file exported here should restore on the desktop app and vice versa.
"Restore from backup file…" on the login screen reverses this entirely
offline, without contacting the accounts server at all: it decrypts the
file locally and writes straight into a fresh IndexedDB store for that
username, then connects to the relay directly with the recovered identity.
Verified live: exported a real account's backup, deleted its IndexedDB
database entirely (simulating a brand new device), and confirmed restoring
from the file recovered the identical identity (same safety number), the
same contact, and the same message history.

## What's built: groups, calls, and rich content (Phase 7e)

- **Emoji** (`app.js`) — a picker button next to the message input; no
  protocol changes needed since emoji are already valid UTF-8 in an
  ordinary text message.
- **Photo/GIF/audio/video sharing** (`attachments.js`) — mirrors
  `haven/attachments.py`'s exact envelope (filename + mime + base64
  bytes) and 8 MB limit, so an attachment sent from the web client is
  wire-compatible with the desktop app. Required raising the relay's
  WebSocket frame-size limit (see `haven/relay_server.py`), since the
  browser's hex-encoded ciphertext plus the attachment's own base64
  needs real headroom over that default.
- **Group chats** (`groups.js`) — a direct port of `haven/groups.py`'s
  sender-keys design: control messages and group chat both ride the
  existing 1:1 encrypted channel as `kind="group"`, no separate
  transport or server-side state. Verified live with three real
  accounts, including sender-key distribution to a member with no
  prior 1:1 relationship with the sender — the actual point of
  sender-keys — and member removal correctly rotating the remover's
  chain.
- **Voice and video calls** (`calls.js`) — a direct port of
  `haven/calls.py`'s deliberate no-WebRTC design: signaling and every
  audio/video chunk are `kind="call"` messages on the same encrypted
  channel, using `getUserMedia`/Web Audio/`<canvas>` in place of
  desktop's `sounddevice`/`opencv`. Same accepted tradeoff as desktop —
  walkie-talkie/early-Skype quality, not enterprise telephony — see
  `calls.py`'s own docstring for why that's a deliberate choice.

## What's NOT built yet

- **On-device AI in-browser** (`haven/ai.py`'s equivalent) — would need
  Whisper/an LLM running via WASM, heavier and slower than the desktop
  app's native libraries; likely reduced scope rather than full parity.
- **No LAN/direct-connect path for the browser client** — inherent to
  running in a browser, not a gap to close; every contact goes through
  a relay.
- **No queue-and-retry UX for sending mid-handshake.** The desktop app
  queues a message and retries for a few seconds if you type before a
  relay handshake finishes; the web client currently does a single fixed
  ~500ms wait before sending. Fine for a demo, worth hardening before
  relying on it.
- **No per-contact relay assignment** (the desktop app's multi-relay
  feature) — the web client currently has exactly one relay, configured
  at login.
