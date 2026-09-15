# Roadmap

All six planned phases are built: real E2E crypto, local accounts,
encrypted storage/backups, LAN discovery, a self-hosted relay, group
chats, rich content, calls, and on-device AI. What follows is a record of
what got built in each phase, its known tradeoffs, and the cross-cutting
hardening still worth doing before trusting this with real money-related
conversations at scale.

## Phase 2 — Reach beyond one Wi-Fi network ✅ done
Added a self-hosted relay server (`haven/relay_server.py`, run with
`python3 -m haven.relay_server`) that forwards encrypted blobs between
clients that aren't on the same LAN. The relay never has the keys to read
message content — it only sees ciphertext plus routing metadata (who's
sending to whom, when), which is the same tradeoff Signal's own servers
make. It authenticates a connecting client with a Diffie-Hellman
proof-of-possession challenge (`crypto.dh_proof`) rather than a password
or a separate signing keypair. Clients try direct LAN connection first
(via existing discovery) and fall back to the relay when a peer isn't
locally reachable, so "runs locally" stays true whenever it can. This
also unlocked **offline messaging**: the relay queues encrypted envelopes
for a contact who's offline in a local SQLite file and flushes them, in
order, the moment that contact reconnects. Contact cards (`My contact
card` / `Add contact…` in the GUI) bootstrap adding someone you're not on
a LAN with, since UDP discovery obviously can't find them.

**Later extension — multiple relays**: an account can register with
several relays at once (`NetworkManager.attach_relay(key, client)` keyed
by "host:port"), and each contact remembers which specific relay reaches
them (`storage.py`'s `relay_host`/`relay_port` columns, set via a
contact's card or "Assign relay…"). Reaching a contact only ever goes
through their own assigned relay, never any other relay you also happen
to be connected to — verified in `test_multi_relay_smoke.py` with two
live relays and contacts split across them, including confirming that
the wrong relay correctly fails rather than silently working.

Known gaps to pick up later, not blocking Phase 3: the relay is a single
process with no redundancy or horizontal scaling; a lost delivery
acknowledgment causes a dropped (not duplicated) message on reconnect
rather than true exactly-once delivery; and there's no sealed sender yet,
so whoever runs the relay can see the *from* address on every message,
not just the *to* address (tracked under "metadata minimization" below).

## Phase 3 — Groups ✅ done
Added a sender-keys group scheme (`haven/groups.py`), the same design
Signal and WhatsApp use for groups: every member has their own outgoing
ratchet chain for messages they send, and a copy of each other member's
chain to decrypt what they send. Group control traffic (invites,
sender-key distribution, membership changes) and group chat messages
both ride as ordinary end-to-end encrypted 1:1 messages between members —
no separate group server or transport, so a group is exactly as private
as the pairwise channel it's built from. A member added later starts
receiving messages from that point forward but can never decrypt
anything sent before they joined. Removing a member rotates the
remover's sender key and redistributes the new one only to the remaining
members, so the removed member's last-known chain key — which they could
otherwise keep advancing forever, since the ratchet only gives forward
secrecy for the past, not the future — stops being useful. Verified in
`test_group_smoke.py`, including the specific security property that a
removed member's stale key cannot decrypt anything sent after rotation.

Known gaps, deferred deliberately: anyone in a group can currently add or
remove anyone else (no admin/creator-only restriction — fine for a small
friend group, worth revisiting for larger ones); a message can arrive
before its sender's key if the two race, and is dropped rather than
buffered for later; and there's no read-receipts or typing-indicator
concept yet (not needed until Phase 4's richer content anyway).

## Phase 4 — Rich content ✅ done
Images, GIFs, and stickers ride the exact same end-to-end encrypted
channel as text — a message's `kind` (already threaded through every
layer since Phase 1) is `"image"`, `"gif"`, or `"sticker"` instead of
`"text"`, carrying a small JSON envelope (filename, MIME type, base64
bytes) as its content instead of a plain string. This needed zero changes
to `crypto.py`, `network.py`, or `storage.py` — they already treat
message content as an opaque string. New: `haven/attachments.py`
(encode/decode + an 8 MB size cap enforced before anything touches the
network), animated GIF playback in the chat view via Pillow, and a local
sticker library per account (drop images in, click to send). Links in
plain text messages are now clickable — opened in the system's default
browser — but Haven deliberately does **not** auto-fetch a preview: doing
so would tell whoever runs the linked site that someone in this
conversation opened it, which cuts against the whole point of the app.
Verified in `test_attachment_smoke.py`: byte-for-byte round trip of a
real image and a real animated GIF through encrypt → transport → decrypt
→ decode, for both a 1:1 DM and a group message.

Known gaps, deferred deliberately: no opt-in "load preview" button for
links yet (mentioned above, not built); large attachments still pass
through the same single-message encrypted envelope rather than being
chunked/streamed, which is fine at chat-image sizes but wouldn't scale to
video; and stickers are a personal per-account library, not a shared
"pack" a whole group installs together.

## Phase 5 — Calls ✅ done
Rather than building a separate WebRTC/ICE/STUN/TURN stack, calls reuse
the exact same encrypted 1:1 channel as text and attachments: call
signaling (offer/answer/reject/end) and every audio/video chunk are just
messages with `kind="call"` (`haven/calls.py`), riding whatever
transport — direct LAN or the Phase 2 relay — is already connected to
that contact. This sidesteps the NAT-traversal problem entirely (no STUN
server, no TURN relay to run) because it's the same routing Haven already
has for everything else. The honest cost of that shortcut: each audio
chunk pays for a full encrypted message (ratchet step, JSON framing, a
reliable in-order TCP write) rather than a lightweight real-time RTP
packet, so this is walkie-talkie/early-Skype quality, not
telephony-grade — see the tradeoff note in `calls.py`. Audio capture uses
`sounddevice`, video uses `opencv-python`; both degrade to a clear
in-call error (not a crash) if the library is missing or the OS denies
mic/camera permission. `test_call_smoke.py` verifies the full signaling
state machine and proves audio/video chunks survive the encrypt →
transport → decrypt pipeline byte-for-byte — real microphone/camera
capture itself can only be verified by actually running the app, since
that needs a live OS permission grant no automated test can click through.

Known gaps, deferred deliberately: 1:1 calls only, no group calls; no
jitter buffer or packet-loss concealment (a late chunk just arrives late,
same as a text message would); call quality will visibly suffer over a
slow relay link since it's carrying continuous media over what's really a
message-passing channel, not a streaming one.

## Phase 6 — On-device AI and live translation ✅ done
Three local models, all CPU-only and verified actually running during
development (`haven/ai.py`, `test_ai_smoke.py`):

  * **Speech-to-text**: `faster-whisper` (`tiny` model, ~75MB, downloads
    once). Verified transcribing real synthesized speech correctly,
    including detecting the spoken language.
  * **Translation**: `argos-translate`. Each language pair downloads a
    small (~50-100MB) package once, then translates fully offline.
    Verified producing correct Spanish output from English input.
  * **A local assistant**: `llama-cpp-python` running a small
    quantized instruct model (Qwen2.5-0.5B-Instruct, ~490MB GGUF —
    "AI settings…" can download it with one click, or point at any
    other GGUF file you already have). Reachable in any chat by typing
    `/ai <question>` — the question and answer are processed entirely
    on-device and are **never sent to your contact or stored in chat
    history**, only shown to you locally, unless you copy the answer
    into a message yourself. Verified answering a real prompt in ~0.2s
    once the tiny model is loaded.
  * **Live call captions**: during a call, toggling "Live captions"
    buffers a few seconds of the other person's incoming audio, runs it
    through the same local speech-to-text, and translates it to your
    configured target language — shown as a caption under the call
    window. Verified end-to-end on real synthesized speech: correct
    transcription, correct language detection, correct translation.

The "nothing leaves the device" requirement's real cost, exactly as
expected going in: quality is well behind a cloud model like Claude or
GPT (a 0.5B local model vs. a frontier model is a large gap), and the
one-time model downloads need an internet connection before any of this
works offline — the same tradeoff as installing any offline AI feature.
`certifi`'s CA bundle is wired in automatically since this project's
Python install didn't trust the system CA store by default, which would
otherwise surface as a confusing SSL error on first download.

Known gaps, deferred deliberately: captioning only covers the *incoming*
side of a call (not your own outgoing speech); there's no way to swap in
a different Whisper model size for better accuracy at the cost of speed;
and the assistant has no memory across `/ai` calls — each question is a
fresh, stateless prompt.

## Ongoing, cross-cutting hardening
- **Full Double Ratchet**: upgrade the current symmetric ratchet to add
  the periodic Diffie-Hellman re-key step, giving post-compromise
  recovery (or adopt `libsignal`'s implementation directly rather than a
  hand-rolled one, once the group/relay design is settled — hand-rolled
  crypto is fine for proving out an architecture, but a protocol this
  security-sensitive deserves the audited reference implementation
  before real friends rely on it for money-related conversations).
- **Metadata minimization**: sealed sender (so even the relay can't see
  who a message is *from*, only where to deliver it), padding message
  sizes, and optional cover traffic — worth adding once Phase 2's relay
  exists, if "content-private, metadata best-effort" ever needs to become
  "metadata-private too."
- **True backup deniability**: the current backup cipher removes the
  cheap "wrong password → clean error" oracle, but it is not
  VeraCrypt-style hidden-volume deniability (there's no second, innocuous
  volume to reveal under duress). If that stronger property matters,
  it's a deliberate separate feature, not a side effect of picking an
  unauthenticated cipher.
- **Security review before real use**: once money-related conversations
  are actually flowing through this, get the crypto design reviewed by
  someone other than its author before trusting it the way you'd trust
  Signal.
