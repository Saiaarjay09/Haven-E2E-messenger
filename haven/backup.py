"""Export / import an encrypted, portable backup of one account.

The backup file uses the "deniable" cipher from crypto.py (AES-CTR, no
MAC) instead of the authenticated cipher used for local storage: if
someone steals this file and brute-forces the password offline, every
wrong guess "successfully" decrypts to a different plausible-looking
blob of bytes instead of raising a clean authentication failure. There is
no cheap oracle telling an attacker's script when it has found the right
password — it has to fall back to noticing the output isn't valid JSON,
which is a far weaker signal than a MAC check.

This is a real hardening step, not full plausible deniability (there is
no second hidden volume to point to under duress) — see ROADMAP.md.
"""

from __future__ import annotations

import json
import os
import sqlite3

from . import crypto, identity as identity_mod, recovery

MAGIC = "HAVEN-BACKUP-V1"


def export_backup(account: identity_mod.Account, password: str, out_path: str) -> None:
    conn = sqlite3.connect(account.data_dir / "haven.db")
    storage_key = crypto._hkdf(account.identity.private_bytes, info=b"local-storage-v1")

    contacts = conn.execute(
        "SELECT fingerprint, username, identity_pub, host, port, verified, added_at FROM contacts"
    ).fetchall()
    messages = conn.execute(
        "SELECT fingerprint, direction, kind, encrypted_body, timestamp FROM messages ORDER BY id"
    ).fetchall()
    conn.close()

    decrypted_messages = []
    for fp, direction, kind, body, ts in messages:
        text = crypto.decrypt_authenticated(storage_key, body, aad=fp.encode()).decode("utf-8")
        decrypted_messages.append(
            {"fingerprint": fp, "direction": direction, "kind": kind, "text": text, "ts": ts}
        )

    bundle = {
        "magic": MAGIC,
        "username": account.username,
        "identity_private_key": account.identity.private_bytes.hex(),
        "created_at": account.created_at,
        "contacts": [
            {
                "fingerprint": c[0],
                "username": c[1],
                "identity_pub": c[2].hex(),
                "host": c[3],
                "port": c[4],
                "verified": c[5],
                "added_at": c[6],
            }
            for c in contacts
        ],
        "messages": decrypted_messages,
    }

    salt = os.urandom(16)
    key = crypto.derive_key_from_password(password, salt)
    plaintext = json.dumps(bundle).encode("utf-8")
    ciphertext = crypto.encrypt_deniable(key, plaintext)

    with open(out_path, "wb") as f:
        f.write(salt + ciphertext)


class RestoreFailed(Exception):
    pass


def restore_backup(path: str, password: str) -> dict:
    raw = open(path, "rb").read()
    salt, ciphertext = raw[:16], raw[16:]
    key = crypto.derive_key_from_password(password, salt)
    plaintext = crypto.decrypt_deniable(key, ciphertext)
    try:
        bundle = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreFailed("could not restore backup (wrong password or corrupted file)") from exc
    if bundle.get("magic") != MAGIC:
        raise RestoreFailed("could not restore backup (wrong password or corrupted file)")
    return bundle


def apply_restored_bundle(bundle: dict, new_password: str) -> tuple[identity_mod.Account, str]:
    """Returns (account, recovery_phrase) — restoring a backup sets up a
    brand new recovery.enc too (same idea as a fresh create_account: a
    fresh phrase for a fresh local password), since the backup itself
    carried no recovery secret of its own."""
    username = bundle["username"]
    identity_key = crypto.KeyPair.from_private_bytes(bytes.fromhex(bundle["identity_private_key"]))
    created_at = bundle["created_at"]

    d = identity_mod.account_dir(username)
    d.mkdir(parents=True, exist_ok=True)
    identity_mod._write_unlock_blob(d / "identity.enc", new_password, username, identity_key, created_at)

    recovery_phrase = recovery.generate_recovery_phrase()
    identity_mod._write_unlock_blob(
        d / "recovery.enc", recovery.normalize_phrase(recovery_phrase), username, identity_key, created_at
    )

    account = identity_mod.Account(username=username, identity=identity_key, created_at=created_at, data_dir=d)

    from . import storage as storage_mod

    store = storage_mod.Store(d, identity_key)
    for c in bundle["contacts"]:
        store.upsert_contact(
            c["fingerprint"], c["username"], bytes.fromhex(c["identity_pub"]), c["host"], c["port"]
        )
        if c["verified"]:
            store.set_verified(c["fingerprint"], True)
    for m in bundle["messages"]:
        store.save_message(m["fingerprint"], m["direction"], m["text"], kind=m["kind"])
    store.close()
    return account, recovery_phrase
