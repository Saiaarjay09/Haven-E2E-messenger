"""Local accounts: sign up / sign in, identity keys, avatar, per-user data dir.

Nothing here ever leaves the machine. There is no central account server —
"signing in" means unlocking your own locally-stored, password-encrypted
identity key with your password, the same way a password manager unlocks
its vault.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from . import crypto, recovery

DATA_ROOT = Path.home() / ".haven"


class WrongPassword(Exception):
    pass


class AccountExists(Exception):
    pass


class NoSuchAccount(Exception):
    pass


class InvalidRecoveryPhrase(Exception):
    pass


@dataclass
class Account:
    username: str
    identity: crypto.KeyPair
    created_at: float
    data_dir: Path

    @property
    def public_fingerprint(self) -> str:
        return crypto.fingerprint(self.identity.public_bytes)

    @property
    def avatar_path(self) -> Path | None:
        for ext in (".png", ".jpg", ".jpeg", ".gif"):
            p = self.data_dir / f"avatar{ext}"
            if p.exists():
                return p
        return None

    def set_avatar(self, source_path: str) -> None:
        src = Path(source_path)
        dest = self.data_dir / f"avatar{src.suffix.lower()}"
        for ext in (".png", ".jpg", ".jpeg", ".gif"):
            old = self.data_dir / f"avatar{ext}"
            if old.exists() and old != dest:
                old.unlink()
        shutil.copyfile(src, dest)


def list_accounts() -> list[str]:
    if not DATA_ROOT.exists():
        return []
    return sorted(p.name for p in DATA_ROOT.iterdir() if (p / "identity.enc").exists())


def account_dir(username: str) -> Path:
    return DATA_ROOT / username


def _write_unlock_blob(path: Path, secret: str, username: str, identity: crypto.KeyPair, created_at: float) -> None:
    """Writes one password-or-phrase-protected copy of the identity key.
    identity.enc and recovery.enc are two independent copies of the SAME
    private key, encrypted with two independent secrets — either one alone
    unlocks the account, which is exactly what makes the recovery phrase
    a working substitute when the password is forgotten."""
    salt = os.urandom(16)
    key = crypto.derive_key_from_password(secret, salt)
    payload = json.dumps(
        {"private_key": identity.private_bytes.hex(), "created_at": created_at}
    ).encode("utf-8")
    blob = crypto.encrypt_authenticated(key, payload, aad=username.encode("utf-8"))
    path.write_bytes(salt + blob)


def _read_unlock_blob(path: Path, secret: str, username: str) -> dict:
    raw = path.read_bytes()
    salt, blob = raw[:16], raw[16:]
    key = crypto.derive_key_from_password(secret, salt)
    payload = crypto.decrypt_authenticated(key, blob, aad=username.encode("utf-8"))
    return json.loads(payload.decode("utf-8"))


def create_account(username: str, password: str) -> tuple[Account, str]:
    """Returns (account, recovery_phrase). The recovery phrase is generated
    once, here, and is never written to disk in plaintext anywhere — only
    the caller sees it (show it to the user immediately and don't keep it
    around in memory longer than needed), matching how any recovery-phrase
    system (crypto wallets, etc.) is supposed to work: if this phrase and
    the password are both lost, the account is unrecoverable by design."""
    d = account_dir(username)
    if (d / "identity.enc").exists():
        raise AccountExists(username)
    d.mkdir(parents=True, exist_ok=True)

    identity = crypto.KeyPair.generate()
    created_at = time.time()
    _write_unlock_blob(d / "identity.enc", password, username, identity, created_at)

    recovery_phrase = recovery.generate_recovery_phrase()
    _write_unlock_blob(
        d / "recovery.enc", recovery.normalize_phrase(recovery_phrase), username, identity, created_at
    )

    account = Account(username=username, identity=identity, created_at=created_at, data_dir=d)
    return account, recovery_phrase


def reset_password_with_recovery(username: str, recovery_phrase: str, new_password: str) -> Account:
    """The 'forgot password' flow: unlock with the recovery phrase instead
    of the password, then re-encrypt identity.enc under a brand-new
    password. recovery.enc is left untouched — the same phrase keeps working
    for next time, since the underlying identity key never changed."""
    d = account_dir(username)
    recovery_path = d / "recovery.enc"
    if not recovery_path.exists():
        raise NoSuchAccount(username)

    normalized = recovery.normalize_phrase(recovery_phrase)
    try:
        data = _read_unlock_blob(recovery_path, normalized, username)
    except InvalidTag as exc:
        raise InvalidRecoveryPhrase(username) from exc

    identity = crypto.KeyPair.from_private_bytes(bytes.fromhex(data["private_key"]))
    created_at = data["created_at"]
    _write_unlock_blob(d / "identity.enc", new_password, username, identity, created_at)
    return Account(username=username, identity=identity, created_at=created_at, data_dir=d)


def sign_in(username: str, password: str) -> Account:
    d = account_dir(username)
    enc_path = d / "identity.enc"
    if not enc_path.exists():
        raise NoSuchAccount(username)

    try:
        data = _read_unlock_blob(enc_path, password, username)
    except InvalidTag as exc:
        raise WrongPassword(username) from exc

    identity = crypto.KeyPair.from_private_bytes(bytes.fromhex(data["private_key"]))
    return Account(username=username, identity=identity, created_at=data["created_at"], data_dir=d)


CONTACT_CARD_PREFIX = "haven1"


def make_contact_card(account: Account, relay_host: str | None = None, relay_port: int | None = None) -> str:
    """A contact card carries only public information (username + public
    identity key, and optionally a relay address) — safe to paste into any
    existing chat app, email, or read aloud, the same way sharing a phone
    number is safe. It is NOT a substitute for safety-number verification:
    it just bootstraps enough to attempt a connection (directly on a
    shared LAN, or via the included relay). Verify the safety number
    afterwards, the same as any contact discovered over LAN.

    Including a relay means whoever adds you from this card automatically
    remembers to reach you through that specific relay (see
    config.py's multi-relay support) — handy when your friend group runs
    its own relay and everyone's cards point at it."""
    base = f"{CONTACT_CARD_PREFIX}:{account.username}:{account.identity.public_bytes.hex()}"
    if relay_host and relay_port:
        return f"{base}:{relay_host}:{relay_port}"
    return base


class InvalidContactCard(Exception):
    pass


def parse_contact_card(card: str) -> tuple[str, bytes, str | None, int | None]:
    """Returns (username, identity_pub, relay_host, relay_port) — the relay
    fields are None for an older-style card with no relay embedded."""
    parts = card.strip().split(":")
    if len(parts) not in (3, 5) or parts[0] != CONTACT_CARD_PREFIX:
        raise InvalidContactCard("not a valid Haven contact card")
    username, pub_hex = parts[1], parts[2]
    try:
        pub = bytes.fromhex(pub_hex)
    except ValueError as exc:
        raise InvalidContactCard("not a valid Haven contact card") from exc
    if len(pub) != 32:
        raise InvalidContactCard("not a valid Haven contact card")
    if len(parts) == 5:
        relay_host = parts[3]
        try:
            relay_port = int(parts[4])
        except ValueError as exc:
            raise InvalidContactCard("not a valid Haven contact card") from exc
        return username, pub, relay_host, relay_port
    return username, pub, None, None
