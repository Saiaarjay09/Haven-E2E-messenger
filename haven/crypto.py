"""
Cryptographic core for Haven.

Design (milestone 1 — LAN, both parties online at handshake time):

  * Every account has a long-term X25519 identity keypair. Peers learn each
    other's identity public key over the LAN discovery beacon and MUST verify
    the resulting "safety number" (fingerprint) out of band (in person, over
    a call) before trusting a contact — this is trust-on-first-use, the same
    model Signal uses for its safety numbers.

  * Session setup is a 3-DH handshake (X3DH without the async pre-key
    server, since both sides are live): each side contributes a fresh
    ephemeral X25519 key, and the shared secret mixes
    ECDH(identity, ephemeral) both ways plus ECDH(ephemeral, ephemeral).
    That gives mutual authentication (identity keys involved) and forward
    secrecy for the handshake itself (ephemeral keys are discarded after).

  * Each direction then runs an independent symmetric-key ratchet (the
    "chain" half of Signal's Double Ratchet): every message derives a fresh
    message key from the chain key via HMAC and the chain key is advanced
    and the old one discarded, so compromising today's key never exposes
    yesterday's messages. NOTE: this milestone does NOT yet add the DH
    ratchet step (fresh ephemeral keys mixed in periodically during an
    ongoing conversation), so it lacks Double Ratchet's post-compromise
    ("future secrecy") recovery. That is tracked as a phase-2 upgrade in
    ROADMAP.md.

  * Message encryption is AES-256-GCM (authenticated — tampering or the
    wrong key is detected and rejected). This is deliberately different
    from the backup cipher below, where an "obviously wrong password"
    signal is exactly what we do NOT want to leak.

  * At-rest backups use a separate, unauthenticated construction (AES-256
    in CTR mode, no MAC) so that decrypting a stolen backup file with the
    wrong password silently produces plausible-looking garbage bytes
    instead of a clean "MAC verification failed" exception. This removes
    the cheap oracle an offline brute-forcer would otherwise get from
    every guess. It is NOT information-theoretic plausible deniability
    (VeraCrypt-style hidden volumes) — see ROADMAP.md for that caveat.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --------------------------------------------------------------------------
# Identity keys
# --------------------------------------------------------------------------


@dataclass
class KeyPair:
    private_key: X25519PrivateKey
    public_bytes: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        return cls(private_key=priv, public_bytes=pub)

    @property
    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes_raw()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyPair":
        priv = X25519PrivateKey.from_private_bytes(raw)
        return cls(private_key=priv, public_bytes=priv.public_key().public_bytes_raw())


def fingerprint(*public_keys: bytes) -> str:
    """Human-checkable safety number for one or two public keys (sorted so
    both sides compute the same string regardless of who is 'self')."""
    material = b"".join(sorted(public_keys))
    digest = hashlib.sha256(material).digest()
    numeric = int.from_bytes(digest[:30], "big")
    groups = []
    for _ in range(6):
        groups.append(f"{numeric % 100000:05d}")
        numeric //= 100000
    return " ".join(groups)


def _dh(priv: X25519PrivateKey, pub_bytes: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(pub_bytes))


def _hkdf(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"haven-v1", info=info).derive(
        key_material
    )


def dh_proof(my_priv: X25519PrivateKey, their_pub: bytes, nonce: bytes) -> str:
    """Proof-of-possession primitive used for relay registration: whoever
    computes this correctly must hold the private key matching one side of
    the DH exchange. Because ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub), the
    exact same call works on both ends of a challenge-response — the relay
    calls it with its own ephemeral private key and the client's claimed
    public identity key; the client calls it with its own private identity
    key and the relay's ephemeral public key. If the client doesn't hold
    the matching private key, its proof won't match what the relay
    computes independently. No signature scheme or extra keypair needed."""
    shared = _dh(my_priv, their_pub)
    return hmac.new(shared, nonce, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# Handshake (3-DH, X3DH-lite for two live parties)
# --------------------------------------------------------------------------


def compute_shared_root_key(
    *,
    is_initiator: bool,
    my_identity: KeyPair,
    my_ephemeral: KeyPair,
    their_identity_pub: bytes,
    their_ephemeral_pub: bytes,
) -> bytes:
    """Both sides call this with the same four keys (two of them their own
    private material) and get back an identical 32-byte root key."""
    if is_initiator:
        dh1 = _dh(my_identity.private_key, their_ephemeral_pub)
        dh2 = _dh(my_ephemeral.private_key, their_identity_pub)
        dh3 = _dh(my_ephemeral.private_key, their_ephemeral_pub)
    else:
        dh1 = _dh(my_ephemeral.private_key, their_identity_pub)
        dh2 = _dh(my_identity.private_key, their_ephemeral_pub)
        dh3 = _dh(my_ephemeral.private_key, their_ephemeral_pub)
    return _hkdf(dh1 + dh2 + dh3, info=b"root")


def derive_chain_keys(root_key: bytes, is_initiator: bool) -> tuple[bytes, bytes]:
    """Returns (send_chain_key, recv_chain_key) for this side."""
    initiator_to_responder = _hkdf(root_key, info=b"init->resp")
    responder_to_initiator = _hkdf(root_key, info=b"resp->init")
    if is_initiator:
        return initiator_to_responder, responder_to_initiator
    return responder_to_initiator, initiator_to_responder


# --------------------------------------------------------------------------
# Symmetric ratchet + authenticated message encryption
# --------------------------------------------------------------------------


def ratchet_step(chain_key: bytes) -> tuple[bytes, bytes]:
    """Advance a chain key one step. Returns (message_key, next_chain_key)."""
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


@dataclass
class RatchetSession:
    send_chain_key: bytes
    recv_chain_key: bytes
    send_index: int = 0
    recv_index: int = 0

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> dict:
        message_key, self.send_chain_key = ratchet_step(self.send_chain_key)
        nonce = os.urandom(12)
        index = self.send_index
        self.send_index += 1
        full_aad = aad + struct.pack(">Q", index)
        ciphertext = AESGCM(message_key).encrypt(nonce, plaintext, full_aad)
        return {"index": index, "nonce": nonce, "ciphertext": ciphertext}

    def decrypt(self, envelope: dict, aad: bytes = b"") -> bytes:
        index = envelope["index"]
        if index != self.recv_index:
            raise ValueError(
                f"out-of-order message (expected #{self.recv_index}, got #{index}); "
                "milestone-1 ratchet requires in-order delivery"
            )
        message_key, self.recv_chain_key = ratchet_step(self.recv_chain_key)
        self.recv_index += 1
        full_aad = aad + struct.pack(">Q", index)
        return AESGCM(message_key).decrypt(envelope["nonce"], envelope["ciphertext"], full_aad)


@dataclass
class SenderKeyChain:
    """One direction of a group's sender-keys scheme (see groups.py): every
    member has exactly one of these for messages THEY send to a group, and
    one copy of every OTHER member's chain (received from them) to decrypt
    what that member sends. It's the same one-way hash-ratchet primitive as
    RatchetSession's two chains, just used unidirectionally and shared with
    many recipients instead of negotiated pairwise — which is exactly what
    makes group fan-out O(members) instead of O(members^2)."""

    chain_key: bytes
    index: int = 0

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> dict:
        message_key, self.chain_key = ratchet_step(self.chain_key)
        nonce = os.urandom(12)
        index = self.index
        self.index += 1
        full_aad = aad + struct.pack(">Q", index)
        ciphertext = AESGCM(message_key).encrypt(nonce, plaintext, full_aad)
        return {"index": index, "nonce": nonce, "ciphertext": ciphertext}

    def decrypt(self, envelope: dict, aad: bytes = b"") -> bytes:
        index = envelope["index"]
        if index != self.index:
            raise ValueError(
                f"out-of-order sender-key message (expected #{self.index}, got #{index})"
            )
        message_key, self.chain_key = ratchet_step(self.chain_key)
        self.index += 1
        full_aad = aad + struct.pack(">Q", index)
        return AESGCM(message_key).decrypt(envelope["nonce"], envelope["ciphertext"], full_aad)


# --------------------------------------------------------------------------
# Password-based encryption for local identity storage and backups
# --------------------------------------------------------------------------


# The original scrypt cost — kept as the default so every EXISTING
# caller (local identity-file unlock in identity.py, backup.py's
# desktop AND web backup files) keeps deriving byte-identical keys from
# already-encrypted-with-this-N data. Never bump this default; bump the
# `n` argument at the specific call site you actually want stronger
# instead (see webapp/accounts_server.py's SCRYPT_N_CURRENT for why the
# hosted web app's login/signup does exactly that).
SCRYPT_N_LEGACY = 2**15


def derive_key_from_password(password: str, salt: bytes, length: int = 32, n: int = SCRYPT_N_LEGACY) -> bytes:
    return Scrypt(salt=salt, length=length, n=n, r=8, p=1).derive(password.encode("utf-8"))


def derive_split_keys(password: str, salt: bytes, n: int = SCRYPT_N_LEGACY) -> tuple[bytes, bytes]:
    """Zero-knowledge split for the hosted web app (webapp/): ONE expensive
    scrypt derivation, then HKDF domain-separation into two independent
    keys — an auth_key sent to the server to prove who you are, and an
    enc_key that never leaves the client and is the only thing that can
    decrypt your identity blob. This is the same pattern Bitwarden and
    similar zero-knowledge services use: even a fully compromised server
    (database dump AND live code) that captures every auth_key it's ever
    seen still cannot derive enc_key from it — HKDF is one-way, and the
    two outputs are cryptographically independent. Returns (auth_key,
    enc_key).

    `n` defaults to the legacy cost for the same reason
    derive_key_from_password's does; webapp/accounts_server.py passes a
    stronger value explicitly for new/reset credentials, and reads back
    whichever `n` an existing account was actually created with (stored
    server-side) so a returning user's password still derives correctly."""
    combined = derive_key_from_password(password, salt, length=32, n=n)
    auth_key = _hkdf(combined, info=b"webapp-auth-key")
    enc_key = _hkdf(combined, info=b"webapp-enc-key")
    return auth_key, enc_key


def encrypt_authenticated(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM, used for the local identity file: we WANT a clear
    'wrong password' failure here (it's a login prompt, not a backup we're
    trying to protect against offline brute forcing with no rate limit)."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt_authenticated(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def encrypt_deniable(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CTR, no MAC. Wrong key => different-but-equally-plausible
    garbage bytes, not an exception. Used only for exported backup files."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def decrypt_deniable(key: bytes, blob: bytes) -> bytes:
    iv, ciphertext = blob[:16], blob[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
