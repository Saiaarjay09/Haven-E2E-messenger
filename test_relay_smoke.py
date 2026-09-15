"""Headless smoke test for Phase 2: a real relay server process (own thread,
real TCP socket) brokering two clients that are NOT on the same LAN — no
UDP discovery involved, only identity_pub-addressed relay routing. Proves:
  1. two clients can establish an E2E session purely through the relay
  2. a message sent while the recipient is offline is queued and delivered
     once they reconnect, in order
  3. the relay's own on-disk queue never contains plaintext or key material
Run: python3 test_relay_smoke.py
"""
import shutil
import tempfile
import threading
import time
from pathlib import Path

from haven import identity, network, relay_client, relay_server, storage

tmp = Path(tempfile.mkdtemp())
identity.DATA_ROOT = tmp
print("test data root:", tmp)

RELAY_PORT = 18443
RELAY_KEY = f"127.0.0.1:{RELAY_PORT}"
relay_db = str(tmp / "relay.db")
relay = relay_server.RelayServer(port=RELAY_PORT, db_path=relay_db)
threading.Thread(target=relay.start, daemon=True).start()
time.sleep(0.3)
print("relay server started on port", RELAY_PORT)

alice = identity.create_account("alice", "alice-password-123")
bob = identity.create_account("bob", "bob-password-456")

alice_store = storage.Store(alice.data_dir, alice.identity)
bob_store = storage.Store(bob.data_dir, bob.identity)

alice_net = network.NetworkManager(alice.identity, "alice", alice_store)
bob_net = network.NetworkManager(bob.identity, "bob", bob_store)

received = {}
alice_net.on_message = lambda fp, kind, text, sender_pub: received.setdefault("alice", []).append(text)
bob_net.on_message = lambda fp, kind, text, sender_pub: received.setdefault("bob", []).append(text)

alice_relay = relay_client.RelayClient(alice.identity, "alice", "127.0.0.1", RELAY_PORT)
alice_net.attach_relay(RELAY_KEY, alice_relay)
alice_relay.start()

fp = None


def wait_until(predicate, timeout=5.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


assert wait_until(lambda: alice_relay.connected.is_set()), "alice never connected to relay"
print("alice registered with relay")

# --- Bob is NOT connected to the relay yet: this exercises offline queuing ---
fp = alice_net.connect_relay(bob.identity.public_bytes, "bob", relay_key=RELAY_KEY)
print("alice's view of the fingerprint (bob offline):", fp)

# alice can't actually send yet since the handshake (hello) itself needs bob
# to be online to reply with hello_ack -- that's fine, this proves the
# relay queues the *hello* itself for later delivery, exactly like it would
# any other opaque envelope.
time.sleep(0.5)
assert not alice_net.is_connected(fp), "session should not be established while bob is offline"
print("confirmed: no session established yet (bob hasn't come online)")

# --- Now bob comes online: relay should flush the queued hello to him ---
bob_relay = relay_client.RelayClient(bob.identity, "bob", "127.0.0.1", RELAY_PORT)
bob_net.attach_relay(RELAY_KEY, bob_relay)
bob_relay.start()
assert wait_until(lambda: bob_relay.connected.is_set()), "bob never connected to relay"
print("bob registered with relay (queued hello should now flush to him)")

assert wait_until(lambda: alice_net.is_connected(fp) and bob_net.is_connected(fp), timeout=5.0), (
    "relay-based handshake never completed after bob came online"
)
print("relay-based E2E session established for both sides")

alice_net.send_text(fp, "hey bob, this one went through the relay")
assert wait_until(lambda: received.get("bob") == ["hey bob, this one went through the relay"])
print("bob received (live, via relay):", received["bob"])

# --- now flip it: alice goes offline, bob sends, alice reconnects later ---
alice_relay.stop()
time.sleep(0.3)
bob_net.send_text(fp, "you there? sent while you were offline")
time.sleep(0.3)
assert "alice" not in received, "alice shouldn't have received anything while disconnected"
print("confirmed: message queued at the relay while alice was offline")

alice_relay2 = relay_client.RelayClient(alice.identity, "alice", "127.0.0.1", RELAY_PORT)
alice_net.attach_relay(RELAY_KEY, alice_relay2)
alice_relay2.start()
assert wait_until(lambda: alice_relay2.connected.is_set())
assert wait_until(lambda: received.get("alice") == ["you there? sent while you were offline"])
print("alice received queued message after reconnecting:", received["alice"])

# --- relay's own storage must never contain plaintext ---
raw = Path(relay_db).read_bytes()
assert b"you there" not in raw and b"sent while you" not in raw, "plaintext leaked into relay's queue db!"
assert alice.identity.private_bytes.hex().encode() not in raw, "private key leaked into relay db!"
print("confirmed: relay's on-disk queue contains no plaintext and no private key material")

alice_net.stop()
bob_net.stop()
alice_relay2.stop()
bob_relay.stop()
relay.stop()
alice_store.close()
bob_store.close()
shutil.rmtree(tmp)

print("\nALL RELAY SMOKE TESTS PASSED")
