"""Generates cross-implementation test vectors from the Python reference
crypto (haven/crypto.py) for the JS port (crypto.js) to be checked
against. Run from the repo root: python3 webapp/static/js/generate_vectors.py
Writes webapp/static/js/test_vectors.json (checked into the repo — these
are fixed, deterministic vectors, not secrets).
"""
import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from haven import crypto

vectors = {}

# --- fixed, deterministic key material (NOT secrets — test fixtures only) ---
alice = crypto.KeyPair.from_private_bytes(bytes(range(1, 33)))
alice_eph = crypto.KeyPair.from_private_bytes(bytes([(i * 7) % 256 or 1 for i in range(32)]))
bob = crypto.KeyPair.from_private_bytes(bytes([(i * 3 + 5) % 256 or 2 for i in range(32)]))
bob_eph = crypto.KeyPair.from_private_bytes(bytes([(i * 11 + 1) % 256 or 3 for i in range(32)]))

vectors["keys"] = {
    "alice_priv": alice.private_bytes.hex(),
    "alice_pub": alice.public_bytes.hex(),
    "alice_eph_priv": alice_eph.private_bytes.hex(),
    "alice_eph_pub": alice_eph.public_bytes.hex(),
    "bob_priv": bob.private_bytes.hex(),
    "bob_pub": bob.public_bytes.hex(),
    "bob_eph_priv": bob_eph.private_bytes.hex(),
    "bob_eph_pub": bob_eph.public_bytes.hex(),
}

# --- fingerprint ---
vectors["fingerprint"] = {
    "expected": crypto.fingerprint(alice.public_bytes, bob.public_bytes),
}

# --- raw X25519 ECDH shared secret (alice_priv x bob_pub) ---
vectors["dh"] = {
    "expected_hex": crypto._dh(alice.private_key, bob.public_bytes).hex(),
}

# --- HKDF ---
vectors["hkdf"] = {
    "key_material_hex": (b"some shared secret material, 32b").hex(),
    "info": "test-info",
    "length": 32,
    "expected_hex": crypto._hkdf(b"some shared secret material, 32b", info=b"test-info").hex(),
}

# --- dh_proof ---
nonce = bytes(range(16))
vectors["dh_proof"] = {
    "priv_hex": alice.private_bytes.hex(),
    "pub_hex": bob.public_bytes.hex(),
    "nonce_hex": nonce.hex(),
    "expected_hex": crypto.dh_proof(alice.private_key, bob.public_bytes, nonce),
}

# --- ratchet_step ---
chain_key = hashlib.sha256(b"initial chain key seed").digest()
message_key, next_chain_key = crypto.ratchet_step(chain_key)
vectors["ratchet_step"] = {
    "chain_key_hex": chain_key.hex(),
    "expected_message_key_hex": message_key.hex(),
    "expected_next_chain_key_hex": next_chain_key.hex(),
}

# --- compute_shared_root_key + derive_chain_keys (both directions must agree) ---
root_from_alice = crypto.compute_shared_root_key(
    is_initiator=True, my_identity=alice, my_ephemeral=alice_eph,
    their_identity_pub=bob.public_bytes, their_ephemeral_pub=bob_eph.public_bytes,
)
root_from_bob = crypto.compute_shared_root_key(
    is_initiator=False, my_identity=bob, my_ephemeral=bob_eph,
    their_identity_pub=alice.public_bytes, their_ephemeral_pub=alice_eph.public_bytes,
)
assert root_from_alice == root_from_bob, "sanity check failed: both sides should derive the same root key"
alice_send, alice_recv = crypto.derive_chain_keys(root_from_alice, is_initiator=True)
bob_send, bob_recv = crypto.derive_chain_keys(root_from_bob, is_initiator=False)
assert alice_send == bob_recv and alice_recv == bob_send, "sanity check failed: chains should cross-match"

vectors["handshake"] = {
    "expected_root_key_hex": root_from_alice.hex(),
    "expected_alice_send_chain_hex": alice_send.hex(),
    "expected_alice_recv_chain_hex": alice_recv.hex(),
}

# --- AES-256-GCM (raw primitive, fixed nonce for a deterministic vector) ---
gcm_key = hashlib.sha256(b"aes-gcm-test-key-seed").digest()
gcm_nonce = bytes(range(12))
gcm_plaintext = b"Hello from the Python reference implementation!"
gcm_aad = b"test-aad"
gcm_ciphertext = AESGCM(gcm_key).encrypt(gcm_nonce, gcm_plaintext, gcm_aad)
vectors["aes_gcm"] = {
    "key_hex": gcm_key.hex(),
    "nonce_hex": gcm_nonce.hex(),
    "plaintext_utf8": gcm_plaintext.decode(),
    "aad_utf8": gcm_aad.decode(),
    "expected_ciphertext_hex": gcm_ciphertext.hex(),
}

# --- AES-256-CTR (deniable backup cipher) ---
ctr_key = hashlib.sha256(b"aes-ctr-test-key-seed").digest()
ctr_iv = bytes(range(16))
ctr_plaintext = b"Backup plaintext material, arbitrary length here."
ctr_cipher = Cipher(algorithms.AES(ctr_key), modes.CTR(ctr_iv))
ctr_ciphertext = ctr_cipher.encryptor().update(ctr_plaintext)
vectors["aes_ctr"] = {
    "key_hex": ctr_key.hex(),
    "iv_hex": ctr_iv.hex(),
    "plaintext_utf8": ctr_plaintext.decode(),
    "expected_ciphertext_hex": ctr_ciphertext.hex(),
}

# --- scrypt (also cross-checked against RFC 7914's own published vectors
# separately in the JS test page -- this one just checks our specific
# N/r/p parameters match between the two implementations) ---
scrypt_salt = bytes(range(16))
scrypt_key = crypto.derive_key_from_password("correct horse battery staple", scrypt_salt)
vectors["scrypt"] = {
    "password": "correct horse battery staple",
    "salt_hex": scrypt_salt.hex(),
    "n": 2**15,
    "r": 8,
    "p": 1,
    "length": 32,
    "expected_hex": scrypt_key.hex(),
}

# --- derive_split_keys (webapp zero-knowledge auth/enc split) ---
split_salt = bytes(range(16, 32))
auth_key, enc_key = crypto.derive_split_keys("hunter2-but-better", split_salt)
vectors["derive_split_keys"] = {
    "password": "hunter2-but-better",
    "salt_hex": split_salt.hex(),
    "expected_auth_key_hex": auth_key.hex(),
    "expected_enc_key_hex": enc_key.hex(),
}

# --- full RatchetSession round trip (encrypt with fixed inputs via the
# actual class, patching os.urandom briefly for a deterministic nonce) ---
import haven.crypto as crypto_mod

fixed_nonce = bytes(range(90, 102))
_orig_urandom = os.urandom
os.urandom = lambda n: fixed_nonce if n == 12 else _orig_urandom(n)
try:
    session = crypto_mod.RatchetSession(send_chain_key=alice_send, recv_chain_key=alice_recv)
    envelope = session.encrypt(b"integration test message", aad=b"session-aad")
finally:
    os.urandom = _orig_urandom

vectors["ratchet_session_encrypt"] = {
    "send_chain_key_hex": alice_send.hex(),
    "aad_utf8": "session-aad",
    "plaintext_utf8": "integration test message",
    "expected_index": envelope["index"],
    "expected_nonce_hex": envelope["nonce"].hex(),
    "expected_ciphertext_hex": envelope["ciphertext"].hex(),
    "expected_next_send_chain_key_hex": session.send_chain_key.hex(),
}

out_path = os.path.join(os.path.dirname(__file__), "static", "js", "test_vectors.json")
with open(out_path, "w") as f:
    json.dump(vectors, f, indent=2)
print("wrote", out_path)
