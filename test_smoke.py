"""Headless smoke test: two in-process 'clients' talk over real TCP sockets
on localhost, doing the full handshake + ratchet-encrypted message exchange,
plus storage persistence and backup export/import with a wrong-password check.
Run: python3 test_smoke.py
"""
import shutil
import tempfile
import time
from pathlib import Path

from haven import backup, crypto, identity, network, storage

tmp = Path(tempfile.mkdtemp())
identity.DATA_ROOT = tmp
print("test data root:", tmp)

alice, _ = identity.create_account("alice", "alice-password-123")
bob, _ = identity.create_account("bob", "bob-password-456")
print("created accounts:", alice.username, bob.username)

alice_store = storage.Store(alice.data_dir, alice.identity)
bob_store = storage.Store(bob.data_dir, bob.identity)

alice_net = network.NetworkManager(alice.identity, "alice", alice_store)
bob_net = network.NetworkManager(bob.identity, "bob", bob_store)

received = {}
alice_net.on_message = lambda fp, kind, text, sender_pub: received.setdefault("alice", []).append(text)
bob_net.on_message = lambda fp, kind, text, sender_pub: received.setdefault("bob", []).append(text)

alice_port = alice_net.start_server()
bob_port = bob_net.start_server()
print("alice listening on", alice_port, "bob listening on", bob_port)

fp_from_alice = alice_net.connect_to_peer("127.0.0.1", bob_port)
print("alice's view of the shared fingerprint:", fp_from_alice)

time.sleep(0.3)  # let bob's inbound handler register

# find bob's fingerprint for alice (should match, since fingerprint() sorts inputs)
fp_from_bob = crypto.fingerprint(alice.identity.public_bytes, bob.identity.public_bytes)
assert fp_from_alice == fp_from_bob, "fingerprint mismatch between the two sides!"
print("fingerprints match:", fp_from_alice)

alice_net.send_text(fp_from_alice, "hey bob, is this thing secure?")
bob_net.send_text(fp_from_alice, "seems like it, alice.")
time.sleep(0.3)

print("bob received:", received.get("bob"))
print("alice received:", received.get("alice"))
assert received.get("bob") == ["hey bob, is this thing secure?"]
assert received.get("alice") == ["seems like it, alice."]

# persisted plaintext history readback
alice_hist = [m["text"] for m in alice_store.history(fp_from_alice)]
bob_hist = [m["text"] for m in bob_store.history(fp_from_alice)]
print("alice's stored history:", alice_hist)
print("bob's stored history:", bob_hist)
assert alice_hist == ["hey bob, is this thing secure?", "seems like it, alice."]
assert bob_hist == ["hey bob, is this thing secure?", "seems like it, alice."]

# raw DB file should not contain the plaintext anywhere
raw_db = (alice.data_dir / "haven.db").read_bytes()
assert b"is this thing secure" not in raw_db, "plaintext leaked into the DB file!"
print("confirmed: plaintext is NOT present in the raw sqlite file bytes")

alice_store.upsert_contact(fp_from_alice, "bob", bob.identity.public_bytes, "127.0.0.1", bob_port)
alice_store.set_verified(fp_from_alice, True)

alice_net.stop()
bob_net.stop()
alice_store.close()
bob_store.close()

# --- backup export/import round trip, including wrong-password behavior ---
alice2 = identity.sign_in("alice", "alice-password-123")
backup_path = tmp / "alice.havenbackup"
backup.export_backup(alice2, "backup-pw-789", str(backup_path))
print("exported backup to", backup_path, "size", backup_path.stat().st_size, "bytes")

bundle = backup.restore_backup(str(backup_path), "backup-pw-789")
assert bundle["username"] == "alice"
assert any(m["text"] == "hey bob, is this thing secure?" for m in bundle["messages"])
print("restore with correct password: OK, recovered", len(bundle["messages"]), "messages")

try:
    backup.restore_backup(str(backup_path), "totally-wrong-password")
    raise SystemExit("FAIL: wrong password should not restore successfully")
except backup.RestoreFailed as exc:
    print("restore with wrong password correctly rejected as garbage:", exc)

shutil.rmtree(tmp)
print("\nALL SMOKE TESTS PASSED")
