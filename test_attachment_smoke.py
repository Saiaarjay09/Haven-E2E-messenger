"""Headless smoke test for Phase 4: images/GIFs/stickers ride the same
encrypted channel as text (as a "kind" of message whose content is a
small JSON envelope — see haven/attachments.py). Proves the full
encode -> encrypt -> transport -> decrypt -> decode round trip for both
a 1:1 DM and a group message, using real fixture image/GIF files, plus
that oversized attachments are rejected before ever touching the network.
Run: python3 test_attachment_smoke.py
"""
import shutil
import tempfile
import threading
import time
from pathlib import Path

from haven import attachments, groups, identity, network, relay_client, relay_server, storage

tmp = Path(tempfile.mkdtemp())

# Self-contained fixtures (this test used to depend on pre-existing files
# under /tmp, which silently vanished the moment anything else cleaned
# /tmp — a real test-design bug found the hard way. Generate them fresh
# every run instead.)
from PIL import Image

IMG_PATH = str(tmp / "test_red_dot.png")
GIF_PATH = str(tmp / "test_anim.gif")
Image.new("RGB", (10, 10), color=(255, 0, 0)).save(IMG_PATH, format="PNG")
gif_frames = [Image.new("RGB", (10, 10), color=(255, 0, 0)), Image.new("RGB", (10, 10), color=(0, 255, 0))]
gif_frames[0].save(GIF_PATH, save_all=True, append_images=gif_frames[1:], duration=100, loop=0)

identity.DATA_ROOT = tmp
print("test data root:", tmp)

RELAY_PORT = 18643
relay = relay_server.RelayServer(port=RELAY_PORT, db_path=str(tmp / "relay.db"))
threading.Thread(target=relay.start, daemon=True).start()
time.sleep(0.3)


def wait_until(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class Client:
    def __init__(self, username, password):
        self.account = identity.create_account(username, password)
        self.store = storage.Store(self.account.data_dir, self.account.identity)
        self.net = network.NetworkManager(self.account.identity, username, self.store)
        self.received = []  # (kind, text)
        self.net.on_message = self._on_message
        self.relay = relay_client.RelayClient(self.account.identity, username, "127.0.0.1", RELAY_PORT)
        self.net.attach_relay(self.relay)
        self.relay.start()
        self.group_mgr = groups.GroupManager(
            self.net, self.store, self.account.identity, username, resolve_route=lambda _pub: None
        )

    def _on_message(self, fingerprint, kind, text, sender_identity_pub):
        if kind == "group":
            self.group_mgr.handle_incoming(sender_identity_pub, text)
        else:
            self.received.append((kind, text))

    def stop(self):
        self.relay.stop()
        self.net.stop()
        self.store.close()


alice = Client("alice", "alice-password-123")
bob = Client("bob", "bob-password-456")
assert wait_until(lambda: alice.relay.connected.is_set())
assert wait_until(lambda: bob.relay.connected.is_set())
print("alice and bob registered with the relay")

# --- 1:1 DM: send an image ---
fp = alice.net.connect_relay(bob.account.identity.public_bytes, "bob")
image_payload = attachments.encode_attachment(IMG_PATH)
assert wait_until(lambda: alice.net.is_connected(fp))
alice.net.send_text(fp, image_payload, kind="image")

assert wait_until(lambda: any(k == "image" for k, _ in bob.received))
received_kind, received_payload = next((k, t) for k, t in bob.received if k == "image")
decoded = attachments.decode_attachment(received_payload)
assert decoded["filename"] == "test_red_dot.png"
assert decoded["mime"] == "image/png"
with open(IMG_PATH, "rb") as f:
    original_bytes = f.read()
assert decoded["data"] == original_bytes, "decoded image bytes don't match the original file"
print("confirmed: 1:1 image round-trips byte-for-byte through encrypt/transport/decrypt/decode")

# --- 1:1 DM: send a GIF ---
gif_payload = attachments.encode_attachment(GIF_PATH)
assert attachments.guess_kind(GIF_PATH) == "gif"
alice.net.send_text(fp, gif_payload, kind="gif")
assert wait_until(lambda: any(k == "gif" for k, _ in bob.received))
_, received_gif_payload = next((k, t) for k, t in bob.received if k == "gif")
decoded_gif = attachments.decode_attachment(received_gif_payload)
with open(GIF_PATH, "rb") as f:
    original_gif_bytes = f.read()
assert decoded_gif["data"] == original_gif_bytes
print("confirmed: 1:1 GIF round-trips byte-for-byte")

# --- Group: send a sticker (same pipeline, different kind label) ---
group_id = alice.group_mgr.create_group("stickers-test", [("bob", bob.account.identity.public_bytes)])
assert wait_until(lambda: group_id in bob.group_mgr.groups)
sticker_payload = attachments.encode_attachment(IMG_PATH)
alice.group_mgr.send_group_message(group_id, sticker_payload, kind="sticker")
assert wait_until(
    lambda: any(m["kind"] == "sticker" for m in bob.group_mgr.group_history(group_id))
)
sticker_row = next(m for m in bob.group_mgr.group_history(group_id) if m["kind"] == "sticker")
decoded_sticker = attachments.decode_attachment(sticker_row["text"])
assert decoded_sticker["data"] == original_bytes
print("confirmed: group sticker round-trips byte-for-byte and is tagged with the right kind")

# --- oversized attachment is rejected before ever touching the network ---
big_path = tmp / "too_big.bin"
big_path.write_bytes(b"0" * (attachments.MAX_ATTACHMENT_BYTES + 1))
try:
    attachments.encode_attachment(str(big_path))
    raise SystemExit("FAIL: oversized attachment should have been rejected")
except attachments.AttachmentTooLarge as exc:
    print("confirmed: oversized attachment rejected locally:", exc)

alice.stop()
bob.stop()
relay.stop()
shutil.rmtree(tmp)

print("\nALL ATTACHMENT SMOKE TESTS PASSED")
