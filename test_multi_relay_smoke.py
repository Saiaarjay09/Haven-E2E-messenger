"""Headless smoke test for multi-relay support: an account can be
registered with several self-hosted relays at once, and each contact
remembers which specific relay reaches them (set by hand, or carried in
their contact card). Proves:
  1. contact cards round-trip an embedded relay host/port correctly
  2. config.py's relay list persists, including migrating an old
     single-relay config into the new list format
  3. storage.py remembers a per-contact relay assignment
  4. a client registered with two relays can reach one contact through
     relay A and a different contact through relay B, and reaching a
     contact through the WRONG relay (one they never registered with)
     correctly fails rather than silently working
Run: python3 test_multi_relay_smoke.py
"""
import shutil
import tempfile
import threading
import time
from pathlib import Path

from haven import config, identity, network, relay_client, relay_server, storage

tmp = Path(tempfile.mkdtemp())
identity.DATA_ROOT = tmp
print("test data root:", tmp)


def wait_until(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# --- 1. contact card round-trips an embedded relay ---
alice, _ = identity.create_account("alice", "alice-password-123")
card_no_relay = identity.make_contact_card(alice)
uname, pub, rhost, rport = identity.parse_contact_card(card_no_relay)
assert (rhost, rport) == (None, None)
print("confirmed: a plain contact card carries no relay info")

card_with_relay = identity.make_contact_card(alice, "relay.example.com", 8443)
uname, pub, rhost, rport = identity.parse_contact_card(card_with_relay)
assert (uname, pub, rhost, rport) == ("alice", alice.identity.public_bytes, "relay.example.com", 8443)
print("confirmed: a contact card with a relay round-trips host+port exactly:", card_with_relay)

# --- 2. config.py: relay list persistence + legacy migration ---
bob, _ = identity.create_account("bob", "bob-password-456")
# simulate an old single relay_host/relay_port from before multi-relay existed
config.save(bob.data_dir, {"relay_host": "old.example.com", "relay_port": 1111})
migrated = config.list_relays(bob.data_dir)
assert len(migrated) == 1
legacy_key = config.relay_key("old.example.com", 1111)
assert migrated[legacy_key]["host"] == "old.example.com"
print("confirmed: a legacy single relay_host/relay_port config is migrated into the relay list")

key_a = config.add_relay(bob.data_dir, "Relay A", "127.0.0.1", 19001)
key_b = config.add_relay(bob.data_dir, "Relay B", "127.0.0.1", 19002)
relays = config.list_relays(bob.data_dir)
assert len(relays) == 3 and key_a in relays and key_b in relays
config.remove_relay(bob.data_dir, legacy_key)
assert legacy_key not in config.list_relays(bob.data_dir)
print("confirmed: relays can be added and removed independently, list persists to disk")

# --- 3. storage.py: per-contact relay assignment ---
carol, _ = identity.create_account("carol", "carol-password-789")
bob_store = storage.Store(bob.data_dir, bob.identity)
carol_fp = "deadbeef" * 8  # fingerprint format is opaque to storage.py, any string works for this check
bob_store.upsert_contact(carol_fp, "carol", carol.identity.public_bytes, "", 0, "127.0.0.1", 19002)
row = bob_store.get_contact(carol_fp)
assert (row["relay_host"], row["relay_port"]) == ("127.0.0.1", 19002)
bob_store.set_contact_relay(carol_fp, "127.0.0.1", 19001)
row = bob_store.get_contact(carol_fp)
assert (row["relay_host"], row["relay_port"]) == ("127.0.0.1", 19001)
print("confirmed: a contact's assigned relay is stored and can be changed with set_contact_relay")
bob_store.close()

# --- 4. two live relays; each contact reachable only through their own ---
RELAY_A_PORT, RELAY_B_PORT = 19101, 19102
RELAY_A_KEY = f"127.0.0.1:{RELAY_A_PORT}"
RELAY_B_KEY = f"127.0.0.1:{RELAY_B_PORT}"

relay_a = relay_server.RelayServer(port=RELAY_A_PORT, db_path=str(tmp / "relay_a.db"))
relay_b = relay_server.RelayServer(port=RELAY_B_PORT, db_path=str(tmp / "relay_b.db"))
threading.Thread(target=relay_a.start, daemon=True).start()
threading.Thread(target=relay_b.start, daemon=True).start()
time.sleep(0.3)

alice2 = identity.sign_in("alice", "alice-password-123")
alice_store = storage.Store(alice2.data_dir, alice2.identity)
alice_net = network.NetworkManager(alice2.identity, "alice", alice_store)

# alice registers with BOTH relays
alice_relay_a = relay_client.RelayClient(alice2.identity, "alice", "127.0.0.1", RELAY_A_PORT)
alice_relay_b = relay_client.RelayClient(alice2.identity, "alice", "127.0.0.1", RELAY_B_PORT)
alice_net.attach_relay(RELAY_A_KEY, alice_relay_a)
alice_net.attach_relay(RELAY_B_KEY, alice_relay_b)
alice_relay_a.start()
alice_relay_b.start()
assert wait_until(lambda: alice_relay_a.connected.is_set())
assert wait_until(lambda: alice_relay_b.connected.is_set())

# bob registers ONLY with relay A; carol registers ONLY with relay B
bob2 = identity.sign_in("bob", "bob-password-456")
bob_store2 = storage.Store(bob2.data_dir, bob2.identity)
bob_net = network.NetworkManager(bob2.identity, "bob", bob_store2)
bob_relay = relay_client.RelayClient(bob2.identity, "bob", "127.0.0.1", RELAY_A_PORT)
bob_net.attach_relay(RELAY_A_KEY, bob_relay)
bob_relay.start()
assert wait_until(lambda: bob_relay.connected.is_set())

carol2, _ = identity.create_account("carol2", "carol2-password-000")
carol_store = storage.Store(carol2.data_dir, carol2.identity)
carol_net = network.NetworkManager(carol2.identity, "carol2", carol_store)
carol_relay = relay_client.RelayClient(carol2.identity, "carol2", "127.0.0.1", RELAY_B_PORT)
carol_net.attach_relay(RELAY_B_KEY, carol_relay)
carol_relay.start()
assert wait_until(lambda: carol_relay.connected.is_set())

print("alice is on both relays; bob is only on A; carol is only on B")

# Reaching bob through his assigned relay (A) must work.
fp_bob = alice_net.connect_relay(bob2.identity.public_bytes, "bob", relay_key=RELAY_A_KEY)
assert wait_until(lambda: alice_net.is_connected(fp_bob) and bob_net.is_connected(fp_bob))
print("confirmed: alice reached bob through relay A (his assigned relay)")

# Reaching carol through her assigned relay (B) must ALSO work, independently.
fp_carol = alice_net.connect_relay(carol2.identity.public_bytes, "carol2", relay_key=RELAY_B_KEY)
assert wait_until(lambda: alice_net.is_connected(fp_carol) and carol_net.is_connected(fp_carol))
print("confirmed: alice reached carol through relay B (her assigned relay) at the same time")

received = {}
bob_net.on_message = lambda fp, kind, text, pub: received.__setitem__("bob", text)
carol_net.on_message = lambda fp, kind, text, pub: received.__setitem__("carol", text)
alice_net.send_text(fp_bob, "hi bob, via relay A")
alice_net.send_text(fp_carol, "hi carol, via relay B")
assert wait_until(lambda: received.get("bob") == "hi bob, via relay A")
assert wait_until(lambda: received.get("carol") == "hi carol, via relay B")
print("confirmed: each message reached the right contact through their own relay")

# Trying to reach a THIRD identity through the wrong relay (one they were
# never registered on) must fail rather than silently succeeding.
dave, _ = identity.create_account("dave", "dave-password-000")
fp_dave_wrong = alice_net.connect_relay(dave.identity.public_bytes, "dave", relay_key=RELAY_A_KEY)
time.sleep(1.0)
assert not alice_net.is_connected(fp_dave_wrong), "should not connect — dave was never registered on relay A"
print("confirmed: reaching a contact through the wrong relay correctly fails, not silently works")

alice_net.stop()
bob_net.stop()
carol_net.stop()
alice_relay_a.stop()
alice_relay_b.stop()
bob_relay.stop()
carol_relay.stop()
relay_a.stop()
relay_b.stop()
alice_store.close()
bob_store2.close()
carol_store.close()
shutil.rmtree(tmp)

print("\nALL MULTI-RELAY SMOKE TESTS PASSED")
