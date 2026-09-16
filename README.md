# Haven

A local-first, end-to-end encrypted messenger. No account server, no cloud,
no phone number. Two people on the same local network find each other
automatically; two people anywhere else can reach each other through a
relay server either of you self-hosts.

All six planned phases are built (see `ROADMAP.md` for what each one
covers and its known tradeoffs): 1-on-1 encrypted text chat, local
accounts, encrypted local storage, encrypted portable backups, LAN
discovery, a self-hosted relay for reaching friends off your LAN with
offline message queuing, real end-to-end encrypted group chats,
images/GIFs/stickers/links, voice and video calls, and on-device AI
(speech-to-text, translation, a local assistant, and live call captions).
Work has also started on a hosted web app (global unique usernames +
account recovery are live; see `webapp/README.md`).

## Run it (LAN only, no setup)

```bash
pip3 install -r requirements.txt
python3 main.py
```

Calls and on-device AI pull in a few more (larger) libraries — see
`requirements.txt`. If you only want text chat and don't need those yet,
`pip3 install cryptography pillow` is enough on its own.

Run it on two machines on the same Wi-Fi/LAN (or two accounts on one
machine for a quick test — see `test_smoke.py` for a fully scripted,
no-GUI version of this). Create an account on each, and within a few
seconds each should see the other appear in the "Nearby & contacts" list.
Click a name to open a chat.

When you create an account, Haven shows you a **12-word recovery
phrase** exactly once — write it down somewhere safe. It's the only way
back in if you forget your password (click **Forgot password?** on the
sign-in screen and enter it there); Haven cannot recover your account
any other way, and can't show you the phrase again after that first
screen. See `test_recovery_smoke.py` for this verified end-to-end,
including that the phrase is never written to disk in plaintext.

## Reaching friends who aren't on your LAN (Phase 2)

1. Pick a machine to run the relay on — your own computer for testing, or
   something always-on for real use (a Raspberry Pi, a home NAS, or a
   cheap VPS). Run:
   ```bash
   python3 -m haven.relay_server --port 8443
   ```
   Make sure that port is reachable from your friends' networks (forward
   it on your router, or use a VPS with a public IP).
2. In the Haven GUI, click **Manage relays…** and add that machine's
   address and port (give it a name, like "Home relay"). Do this on every
   device that should be reachable off-LAN, including your own — you can
   add more than one relay here (see "Multiple relays" below).
3. Click **My contact card** to get a short string encoding your username
   and public identity key (not secret — safe to paste anywhere), and
   pick one of your configured relays to embed in it. Send the card to a
   friend through any existing app (iMessage, email, in person). They
   click **Add contact…** and paste it in — if the card includes a relay
   they don't have configured yet, Haven offers to add and connect to it
   for them automatically.
4. As long as both of you are connected to that same relay (or reachable
   directly on a shared LAN), messages go through. If one of you is
   offline, the relay queues encrypted envelopes and delivers them the
   moment you reconnect — it never sees the plaintext, only that an
   opaque blob is waiting for your public key.
5. **Still verify the safety number** the same way you would for a LAN
   contact — a contact card only bootstraps a connection attempt, it
   doesn't prove nobody tampered with it in transit.

### Multiple relays

An account can be registered with several relays at once, and each
contact remembers which specific one reaches them — useful if, say, one
friend group runs its own relay and a different one runs theirs. A
contact usually gets its relay automatically from whoever's card they
were added with; to set or change it by hand, open that contact's DM and
click **Assign relay…**. Reaching a contact only ever goes through their
assigned relay — not any other relay you happen to also be connected to
— so a friend who isn't registered on that particular relay stays
unreachable through it, exactly as it should. See
`test_multi_relay_smoke.py` for this verified with two live relay
servers and three clients split across them.

See `test_relay_smoke.py` for a fully scripted example of two clients
talking purely through a relay, including one going offline mid-conversation.

### Reaching friends in other countries

This needs no code changes — the relay is plain TCP over the ordinary
internet (it binds `0.0.0.0`, not just localhost), so it doesn't care
where either side is. What matters is hosting it somewhere with a public
address:

- **Easiest**: a cheap VPS (DigitalOcean, Linode, Oracle Cloud's free
  tier, AWS Lightsail — a few dollars a month or free). It already has a
  public IP, so there's no router configuration needed.
- **Free but more setup**: run it on a home computer or Raspberry Pi,
  forward the port on your router, and use a dynamic DNS service (like
  DuckDNS or No-IP) since home internet IPs usually change over time.

Either way, keep it running persistently rather than only while a
terminal window happens to be open — `deploy/haven-relay.service` is a
systemd unit for a Linux VPS, and `deploy/com.haven.relay.plist` is a
launchd config for keeping it running on a Mac. Both auto-restart if the
process crashes and start on boot.

Two things that specifically affect international reach:
- **Restrictive networks/countries sometimes block non-standard ports.**
  If a friend somewhere can't connect, try re-running the relay on port
  `443` — traffic on that port is rarely blocked since it looks like
  ordinary HTTPS.
- **Latency scales with distance** (it's still real TCP round-trips
  across the actual physical distance), which shows up as slightly
  delayed calls, not broken text/group messaging.

## Group chats (Phase 3)

Click **Create group…**, name it, and pick from your known contacts
(anyone you've discovered on LAN or added by contact card). Groups use a
sender-keys scheme — see `haven/groups.py` — riding entirely over the
same 1:1 encrypted channels, direct or relayed, that DMs use. From the
group's chat window, **Manage members…** lets you add someone (paste
their contact card) or remove a current member. A member added later
can't see anything sent before they joined; removing a member rotates
your own sending key so they can't keep reading afterward either. See
`test_group_smoke.py` for a fully scripted three-person example covering
create/message/add/remove and the key-rotation security property.

## Images, GIFs, stickers, and links (Phase 4)

Click **🖼 Image/GIF…** in any open chat (DM or group) to send a picture
or animated GIF — it's end-to-end encrypted exactly like a text message,
just carrying image bytes instead. GIFs play inline. **😀 Stickers…**
opens your personal sticker library (per account, stored locally); **Add
sticker…** imports any image into it, and clicking a thumbnail sends it
immediately. A plain URL typed in a text message becomes clickable and
opens in your system browser — Haven does not fetch a preview of the
link itself, since that would quietly tell whoever runs that site someone
in the conversation opened it. See `test_attachment_smoke.py` for a
byte-for-byte round-trip test of an image and a GIF through the full
encrypt/transport/decrypt/decode pipeline, for both a DM and a group.

## Voice and video calls (Phase 5)

Open a DM (calls are 1:1 only, not group calls) and click **📞 Call** or
**🎥 Video call**. Your contact gets a ring dialog to accept or reject;
once accepted, a call window shows elapsed time, a **Mute** toggle, and
**Hang up**. Calls ride the exact same encrypted channel as everything
else in Haven (`haven/calls.py`) rather than a separate WebRTC stack, so
there's no STUN/TURN server to run — it just uses whatever connection
(LAN or relay) you already have to that contact. That also means quality
depends on that connection: expect early-Skype-era quality over a relay,
not landline-grade clarity. Audio needs `sounddevice` and microphone
permission; video needs `opencv-python` and camera permission — both
report a clear in-call error rather than crashing if unavailable. See
`test_call_smoke.py` for signaling and media-pipeline verification (real
mic/camera capture needs your own hardware and OS permission prompts, so
it's the one thing in this project you'll have to try yourself to confirm).

## On-device AI and live translation (Phase 6)

Everything here runs locally — nothing is ever sent to a cloud AI API.
Click **AI settings…** to point at a `.gguf` model file you already have,
or click **Download a small model…** to fetch a small (~490MB) one with
one click (needs internet for that one-time download only). Type
`/ai <question>` into any chat to ask it something — the question and
answer stay on your device and are never sent to your contact or saved
in chat history, unless you copy the answer into a message yourself. Set
a "translate live call captions to" language in the same dialog, then
toggle **Live captions** in any call window: Haven transcribes the other
person's speech and translates it to your chosen language in near
real-time, using `faster-whisper` and `argos-translate` — both fully
offline after their own one-time model downloads. See `test_ai_smoke.py`
for verification against real synthesized speech (transcription, language
detection, translation, and a real local-LLM response all checked
end-to-end).

**Before you trust a contact**, verify their safety number. Click "My
safety number" to see your own, have your friend read theirs to you over
a voice call (or in person), and use "Verify safety number…" in the chat
window to confirm it matches. This is what actually proves nobody swapped
in a fake key in the middle — the same trust model Signal uses.

## What's real here (not a mockup)

- **End-to-end encryption**: X25519 key exchange (3-DH handshake, like a
  simplified X3DH) plus a per-direction symmetric ratchet, AES-256-GCM
  for every message. Verified in `test_smoke.py` by asserting the raw
  `haven.db` SQLite file never contains message plaintext as bytes.
- **Local accounts**: your username + password unlocks a locally stored,
  password-encrypted identity keypair. No server ever sees your password
  or your keys.
- **Encrypted chat storage**: message history is decrypted once on
  receipt and re-encrypted at rest with a key derived from your identity
  key (not your password) — separate from the wire ratchet, since ratchet
  keys are one-way and can't be used to re-read old messages after the
  chain advances.
- **Encrypted, "no-oracle" backups**: `Export backup…` writes a single
  file encrypted with a cipher that has no authentication tag (AES-CTR).
  A wrong password on restore silently produces garbage bytes instead of
  a clean cryptographic failure — there's no cheap signal for an offline
  password-guessing script to know when it's found the right one. See the
  docstring in `haven/crypto.py` for the exact tradeoff this does and
  does not give you.
- **Avatars**: set a local profile picture per account.
- **LAN discovery**: no server, no internet — a UDP broadcast beacon.
- **Self-hosted relay (Phase 2)**: `haven/relay_server.py` is a standalone
  process you run yourself. It authenticates clients with a
  Diffie-Hellman proof-of-possession challenge (no password, no separate
  signing key — see `crypto.dh_proof`), routes opaque ciphertext envelopes
  by public identity key, and queues them in SQLite for anyone currently
  offline. It never sees plaintext or private key material — verified in
  `test_relay_smoke.py` by asserting the relay's own queue database never
  contains message text or key bytes.
- **Multiple relays**: an account can register with several relays at
  once, with each contact remembering which one specifically reaches
  them (`config.py`, `haven/network.py`). Verified in
  `test_multi_relay_smoke.py`: contact cards round-trip an embedded
  relay, an old single-relay config migrates into the new list format,
  and two contacts split across two live relays are each reachable only
  through their own — reaching one through the wrong relay correctly
  fails rather than silently working.
- **Contact cards**: since off-LAN contacts can't be found by the UDP
  discovery beacon, "My contact card" / "Add contact…" let you bootstrap
  a connection with someone's public identity key shared through any
  other channel — still not trusted until you verify the safety number.
- **Group chats (Phase 3)**: `haven/groups.py` implements a sender-keys
  scheme, verified in `test_group_smoke.py` to correctly (a) let a new
  member see only messages sent after they join, and (b) make a removed
  member's last-known key useless against messages sent after rotation.
- **Images, GIFs, stickers, links (Phase 4)**: `haven/attachments.py`
  handles encode/decode + a size cap; images and GIFs are just another
  message `kind` on the same encrypted channel, verified byte-for-byte in
  `test_attachment_smoke.py`. Links are clickable, never auto-fetched.
- **Voice/video calls (Phase 5)**: `haven/calls.py` implements call
  signaling and media streaming over the same encrypted channel as
  everything else — no separate WebRTC/STUN/TURN infrastructure. Verified
  in `test_call_smoke.py`: full signaling state machine, plus byte-for-byte
  audio/video chunk delivery through the real encrypt/transport/decrypt
  pipeline (real mic/camera hardware needs your own OS permission grant
  to test, which no automated test can do for you).
- **On-device AI (Phase 6)**: `haven/ai.py` wraps `faster-whisper`
  (speech-to-text), `argos-translate` (translation), and
  `llama-cpp-python` (a local assistant) — all local inference, no cloud
  calls. Verified against real synthesized speech in `test_ai_smoke.py`:
  correct transcription, correct language detection, correct translation,
  and a real local-LLM response.
- **Recovery phrases**: `haven/recovery.py` generates a 12-word phrase
  (the standard BIP39 wordlist) at account creation, used to encrypt a
  second independent copy of your identity key — either the password or
  the phrase alone unlocks the account. Verified in
  `test_recovery_smoke.py`: both paths recover the identical key, a
  password reset via the phrase actually invalidates the old password,
  a wrong phrase is rejected without touching the account, and the
  phrase is never written to disk in plaintext anywhere.
- **Hosted web accounts service (Phase 7a)**: `webapp/` is a real
  zero-knowledge accounts server (FastAPI) — global username uniqueness
  and password auth where the server never sees your password or
  anything that could decrypt your identity blob (the same auth-key/
  encryption-key split pattern Bitwarden uses). Verified against a real
  running server process in `test_webapp_accounts_smoke.py`: signup,
  case-insensitive uniqueness, login, recovery-phrase reset, and that the
  server's own database never contains a plaintext password, phrase, or
  private key. See `webapp/README.md` for what this is (and isn't) yet —
  the browser-based chat client itself is a much larger, separate piece
  of work still ahead, and for the real, unavoidable security tradeoff
  browser-delivered crypto accepts that the desktop app doesn't have.

## Known limitations

- The ratchet is a symmetric-chain ratchet without the periodic
  Diffie-Hellman re-key step full Double Ratchet has, so it has forward
  secrecy but not the "self-healing" post-compromise recovery a full
  implementation (e.g. via `libsignal`) would add.
- Calls are 1:1 only (no group calls), with no jitter buffer or
  packet-loss concealment — quality tracks however good your LAN/relay
  connection is, closer to early Skype than a phone line.
- On-device AI models need a one-time internet-connected download before
  they work fully offline — a small (~75-490MB depending on the model)
  but real exception to "no internet needed."
- Live captions only cover the other person's incoming speech, not your
  own; and the local AI assistant has no memory between `/ai` questions.
- Attachments cap out at 8 MB and go through as one encrypted message —
  fine for chat images/GIFs, not built for video or large files.
- No opt-in link-preview fetching yet — links are clickable only.
- Stickers are a personal per-account library, not a shared pack a whole
  group installs together.
- Anyone in a group can currently add or remove anyone else — no
  admin/creator-only restriction. Fine for a small friend group; worth
  revisiting before using this for anything larger.
- A group message can be dropped (not buffered) if it races its sender's
  key distribution message and arrives first.
- Requires in-order delivery per contact. The relay preserves send order
  for queued messages, but if a delivered message's `ack` is lost (e.g.
  the client crashes right after receiving it) the relay will redeliver
  it on next reconnect, and the ratchet will reject it as an out-of-order
  replay rather than silently duplicating it in your history — you'd see
  a dropped message rather than a duplicate, which is the safer failure
  mode but still a known gap versus proper exactly-once delivery.
- The relay is a single process with no redundancy — if it's down and
  you're not on a shared LAN with your contact, messages won't send.
- Metadata (who's messaging whom, when) is visible to whoever runs the
  relay, by design for this phase — see "content-private, metadata
  best-effort" in `ROADMAP.md`.
- If both your password AND your recovery phrase are lost, the account
  is unrecoverable by design — same as any crypto-wallet-style recovery
  phrase, there is deliberately no third way in.
- The hosted web accounts service (`webapp/`) has no actual chat client
  yet — see `webapp/README.md` for the (large) remaining scope, and for
  the real security tradeoff it accepts that the desktop app doesn't have.

## Project layout

```
haven/
  crypto.py        identity keys, handshake, ratchet, backup ciphers, relay DH-proof
  identity.py      local account creation / sign-in, contact cards
  storage.py       encrypted-at-rest SQLite message store + session state
  discovery.py     UDP broadcast LAN peer discovery
  network.py       handshake + encrypted message transport (direct LAN or relay)
  relay_server.py  standalone self-hosted relay (run with -m haven.relay_server)
  relay_client.py  relay connection + auto-reconnect used by the app
  config.py        per-account settings (relay address)
  backup.py        encrypted export/import of a whole account
  groups.py        sender-keys group messaging, layered on the 1:1 channel
  attachments.py   image/GIF/sticker encode-decode + size cap (Phase 4)
  calls.py         call signaling + audio/video streaming (Phase 5)
  ai.py            local speech-to-text, translation, assistant (Phase 6)
  recovery.py      recovery-phrase generation (BIP39 wordlist)
  data/wordlist.txt  the 2048-word BIP39 English wordlist
  gui.py           Tkinter UI
webapp/                    hosted accounts service (Phase 7a) — see webapp/README.md
  accounts_server.py       FastAPI app: signup/login/forgot-password
  accounts_db.py           SQLite storage for hosted accounts
  requirements.txt         webapp-only dependencies (fastapi, uvicorn, bcrypt)
main.py                        entry point
requirements.txt               pip dependencies for the desktop app
test_smoke.py                  headless end-to-end test: direct LAN handshake, messaging, backups
test_relay_smoke.py            headless end-to-end test: relay handshake + offline queuing
test_group_smoke.py            headless end-to-end test: group create/message/add/remove + key rotation
test_attachment_smoke.py       headless end-to-end test: image/GIF round trip over DM + group
test_call_smoke.py             headless end-to-end test: call signaling + audio/video chunk transport
test_ai_smoke.py               headless end-to-end test: STT + translation + live captions + local LLM
test_multi_relay_smoke.py      headless end-to-end test: per-contact relay assignment across two live relays
test_recovery_smoke.py         headless end-to-end test: recovery-phrase password reset
test_webapp_accounts_smoke.py  headless end-to-end test: hosted signup/login/recovery over real HTTP
```
