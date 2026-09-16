"""Headless smoke test for Phase 5: call signaling and the encrypted
media-transport pipeline, over a real relay server. This deliberately
bypasses actual microphone/camera hardware (send_audio_chunk /
send_video_frame are called directly with synthetic bytes) since real
capture/playback needs OS microphone/camera permission this sandboxed
test environment cannot grant — what's verified here is the part that
actually is Haven's own code: offer/answer/reject/hangup signaling, and
that audio/video chunks survive the same encrypt/transport/decrypt
pipeline as everything else byte-for-byte.
Run: python3 test_call_smoke.py
"""
import queue as queue_mod
import shutil
import tempfile
import threading
import time
from pathlib import Path

from haven import calls, identity, network, relay_client, relay_server, storage

# accept_call()/_on_answer() normally call _start_media(), which opens the
# real microphone/camera via background threads. On a first run, macOS
# would pop up a permission dialog that nothing in this automated test can
# click — hanging the test forever. Since real hardware capture needs a
# human with OS permission dialogs anyway (can't be verified by this test
# regardless), stub _start_media to do only the bookkeeping real code does
# (create stop_event/play_queue) without touching any hardware. The actual
# media pipeline (send_audio_chunk/send_video_frame/_on_audio/_on_video) is
# real, unpatched code, exercised directly below with synthetic bytes.
def _fake_start_media(self, fingerprint, video):
    call = self.calls[fingerprint]
    call["stop_event"] = threading.Event()
    call["muted"] = False
    call["play_queue"] = queue_mod.Queue()


calls.CallManager._start_media = _fake_start_media

tmp = Path(tempfile.mkdtemp())
identity.DATA_ROOT = tmp
print("test data root:", tmp)

RELAY_PORT = 18743
RELAY_KEY = f"127.0.0.1:{RELAY_PORT}"
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
        self.account, _ = identity.create_account(username, password)
        self.store = storage.Store(self.account.data_dir, self.account.identity)
        self.net = network.NetworkManager(self.account.identity, username, self.store)
        self.net.on_message = self._on_message
        self.relay = relay_client.RelayClient(self.account.identity, username, "127.0.0.1", RELAY_PORT)
        self.net.attach_relay(RELAY_KEY, self.relay)
        self.relay.start()
        self.call_mgr = calls.CallManager(self.net, self.account.identity, username)
        self.states = []
        self.incoming = []
        self.call_mgr.on_call_state = lambda fp, state: self.states.append(state)
        self.call_mgr.on_incoming_call = lambda fp, cid, video: self.incoming.append((fp, cid, video))

    def _on_message(self, fingerprint, kind, text, sender_identity_pub):
        if kind == "call":
            self.call_mgr.handle_incoming(fingerprint, text)

    def stop(self):
        self.relay.stop()
        self.net.stop()
        self.store.close()


alice = Client("alice", "alice-password-123")
bob = Client("bob", "bob-password-456")
assert wait_until(lambda: alice.relay.connected.is_set())
assert wait_until(lambda: bob.relay.connected.is_set())

fp = alice.net.connect_relay(bob.account.identity.public_bytes, "bob", relay_key=RELAY_KEY)
assert wait_until(lambda: alice.net.is_connected(fp))
print("alice and bob connected via relay")

# --- offer -> accept -> both sides active ---
alice.call_mgr.start_call(fp, video=True)
assert wait_until(lambda: len(bob.incoming) == 1)
bob_fp, call_id, video = bob.incoming[0]
assert video is True
print("bob received the video call offer")

bob.call_mgr.accept_call(bob_fp)
assert wait_until(lambda: "active" in alice.states)
assert wait_until(lambda: bob.call_mgr.calls.get(bob_fp, {}).get("state") == "active")
print("call is active on both sides")

# --- audio round trip (synthetic PCM, bypassing real microphone hardware) ---
fake_pcm = bytes(range(256)) * 4  # 1024 bytes of deterministic "audio"
alice.call_mgr.send_audio_chunk(fp, fake_pcm)
assert wait_until(lambda: bob.call_mgr.calls[bob_fp].get("received_audio_for_test"))
received_pcm = bob.call_mgr.calls[bob_fp]["received_audio_for_test"][0]
assert received_pcm == fake_pcm, "audio chunk did not survive the encrypted transport byte-for-byte"
print("confirmed: audio chunk round-trips byte-for-byte through the encrypted call channel")

# --- video round trip (synthetic JPEG bytes, bypassing real camera hardware) ---
fake_jpeg = b"\xff\xd8\xff\xe0" + bytes(range(200))  # fake-but-plausible JPEG-ish payload
alice.call_mgr.send_video_frame(fp, fake_jpeg)
assert wait_until(lambda: bob.call_mgr.calls[bob_fp].get("received_video_for_test"))
received_jpeg = bob.call_mgr.calls[bob_fp]["received_video_for_test"][0]
assert received_jpeg == fake_jpeg
print("confirmed: video frame round-trips byte-for-byte through the encrypted call channel")

# --- hangup ---
alice.call_mgr.hangup(fp)
assert wait_until(lambda: "ended" in bob.states)
assert fp not in alice.call_mgr.calls
assert wait_until(lambda: bob_fp not in bob.call_mgr.calls)
print("confirmed: hangup ends the call and clears state on both sides")

# --- reject path ---
alice.call_mgr.start_call(fp, video=False)
assert wait_until(lambda: len(bob.incoming) == 2)
bob.call_mgr.reject_call(bob_fp)
assert wait_until(lambda: "rejected" in alice.states)
assert fp not in alice.call_mgr.calls
print("confirmed: reject path clears state and notifies the caller")

alice.stop()
bob.stop()
relay.stop()
shutil.rmtree(tmp)

print("\nALL CALL SIGNALING/TRANSPORT SMOKE TESTS PASSED")
print("(Real microphone/camera capture and playback are NOT exercised by this test —")
print(" that needs OS mic/camera permission and can only be verified by actually running Haven.)")
