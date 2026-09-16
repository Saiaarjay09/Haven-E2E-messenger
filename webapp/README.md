# Haven web app — Phase 7

Everything in `haven/` (the desktop app) runs entirely on your machine:
keys are generated locally, encrypted locally, and never touch a server
you don't control. Turning that into "a real website my friends visit
and sign up on, no install needed" is a genuinely different trust model,
not just a different UI — this document explains exactly what changes,
what's built so far, and what's still ahead.

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
and that stand-in **is** the protocol spec for whoever writes the actual
JS client: derive keys the same way, hit the same endpoints, in the same
order.

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

## What's NOT built yet: the actual browser client (Phase 7b+)

Signing up and logging in doesn't yet get you a working chat in a
browser — that needs a much larger piece of work, planned as follow-on
phases:

- **7b — WebSocket relay**: browsers can't open raw TCP sockets, so
  `relay_server.py`'s protocol needs a WebSocket transport alongside (or
  instead of) TCP. The message format doesn't need to change, only how
  bytes get from client to relay.
- **7c — Browser crypto + storage**: reimplementing `crypto.py`'s
  X25519/AES-GCM/ratchet in JavaScript (via a well-audited library like
  libsodium.js compiled to WASM, not hand-rolled crypto), plus IndexedDB
  as the browser's equivalent of the desktop's encrypted SQLite store,
  plus a WebSocket-based `network.py` equivalent. This is the biggest
  single chunk of remaining work — realistically its own multi-session
  effort, mirroring how the desktop app's Phases 1-2 were the foundation
  everything else built on.
- **7d — UI**: an HTML/JS chat interface covering what `gui.py` covers,
  starting with text chat and expanding from there the same way the
  desktop app's phases did.
- **7e — Calls and rich content in-browser**: WebRTC/`getUserMedia` for
  calls, `<input type=file>` + canvas for images/GIFs — smaller ports of
  `calls.py`/`attachments.py`'s existing designs once 7c exists.
- **On-device AI in-browser** is its own open question: running
  Whisper/an LLM inside a browser tab via WASM (projects like
  whisper.cpp's WASM build or transformers.js exist) is possible but
  meaningfully heavier and slower than the desktop app's native
  `faster-whisper`/`llama-cpp-python` — likely a reduced-scope version
  rather than full parity, if it's built at all.
