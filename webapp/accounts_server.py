"""Hosted accounts service: global username uniqueness + zero-knowledge
password auth + recovery-phrase password reset, for Haven's web client.

Zero-knowledge design (see accounts_db.py's module docstring for the
field-by-field reasoning): the browser derives two independent keys from
each secret (password, and separately the recovery phrase) via
crypto.derive_split_keys — an auth_key sent here to prove identity, and
an enc_key that never leaves the browser and is the only thing able to
decrypt the identity blob this service stores. This server can gate
logins and can be fully compromised (database dump, or malicious code
running on it) without ever gaining the ability to decrypt anyone's
identity key, PROVIDED the browser client's crypto code itself has not
also been compromised — see webapp/README.md for why that residual risk
is real and irreducible for any browser-delivered crypto app.

Run: uvicorn webapp.accounts_server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import os
import re
import threading
import time

import bcrypt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from .accounts_db import AccountsDB, UsernameTaken

USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,23}$")

# A hash of a value nobody will ever supply, used to keep login/verify
# response timing similar whether or not the username exists — reduces
# (does not eliminate — see webapp/README.md) username enumeration via
# this endpoint specifically.
_DUMMY_HASH = bcrypt.hashpw(b"no-such-account-placeholder", bcrypt.gensalt())


def _validate_username(username: str) -> str:
    if not USERNAME_RE.match(username):
        raise ValueError(
            "Usernames must be 3-24 characters, start with a letter, and contain only "
            "letters, digits, and underscores."
        )
    return username


class SignupRequest(BaseModel):
    username: str
    password_salt: str
    password_auth_key: str
    encrypted_identity_blob: str
    recovery_salt: str
    recovery_auth_key: str
    encrypted_identity_blob_recovery: str

    _validate = field_validator("username")(_validate_username)


class LoginRequest(BaseModel):
    username: str
    password_auth_key: str


class RecoveryVerifyRequest(BaseModel):
    username: str
    recovery_auth_key: str


class RecoveryResetRequest(BaseModel):
    username: str
    recovery_auth_key: str
    new_password_salt: str
    new_password_auth_key: str
    new_encrypted_identity_blob: str


class SimpleRateLimiter:
    """Per-key sliding-window limiter, in-memory. Fine for a single
    process (same honest tradeoff as haven/relay_server.py being a single
    process with no horizontal scaling) — a real multi-instance deployment
    would need a shared store like Redis instead."""

    def __init__(self, max_attempts: int, window_seconds: float):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.time()
        with self._lock:
            attempts = [t for t in self._attempts.get(key, []) if now - t < self.window_seconds]
            if len(attempts) >= self.max_attempts:
                raise HTTPException(status_code=429, detail="Too many attempts. Try again shortly.")
            attempts.append(now)
            self._attempts[key] = attempts


db = AccountsDB(os.environ.get("HAVEN_ACCOUNTS_DB", "haven_accounts.db"))
login_limiter = SimpleRateLimiter(max_attempts=10, window_seconds=60.0)
signup_limiter = SimpleRateLimiter(max_attempts=5, window_seconds=60.0)

app = FastAPI(title="Haven Accounts Service")


@app.get("/api/username-available")
def username_available(username: str):
    try:
        _validate_username(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"available": db.is_username_available(username)}


@app.post("/api/signup", status_code=201)
def signup(req: SignupRequest, request_ip: str = "unknown"):
    signup_limiter.check(req.username.lower())
    password_auth_hash = bcrypt.hashpw(req.password_auth_key.encode(), bcrypt.gensalt()).decode()
    recovery_auth_hash = bcrypt.hashpw(req.recovery_auth_key.encode(), bcrypt.gensalt()).decode()
    try:
        user_id = db.create_account(
            username=req.username,
            password_salt=req.password_salt,
            password_auth_hash=password_auth_hash,
            encrypted_identity_blob=req.encrypted_identity_blob,
            recovery_salt=req.recovery_salt,
            recovery_auth_hash=recovery_auth_hash,
            encrypted_identity_blob_recovery=req.encrypted_identity_blob_recovery,
        )
    except UsernameTaken as exc:
        raise HTTPException(status_code=409, detail="That username is already taken.") from exc
    return {"user_id": user_id, "username": req.username}


@app.get("/api/login-salt")
def login_salt(username: str):
    """Salts are not secret — this just lets the browser derive auth_key
    from the password BEFORE calling /api/login, since it needs to know
    which salt was used for this specific account first."""
    row = db.get_by_username(username)
    if not row:
        raise HTTPException(status_code=404, detail="No such account.")
    return {"password_salt": row["password_salt"]}


@app.get("/api/recovery-salt")
def recovery_salt(username: str):
    row = db.get_by_username(username)
    if not row:
        raise HTTPException(status_code=404, detail="No such account.")
    return {"recovery_salt": row["recovery_salt"]}


@app.post("/api/login")
def login(req: LoginRequest):
    login_limiter.check(req.username.lower())
    row = db.get_by_username(req.username)
    stored_hash = row["password_auth_hash"] if row else _DUMMY_HASH.decode()
    ok = bcrypt.checkpw(req.password_auth_key.encode(), stored_hash.encode())
    if not row or not ok:
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    return {"password_salt": row["password_salt"], "encrypted_identity_blob": row["encrypted_identity_blob"]}


@app.post("/api/forgot-password/verify")
def forgot_password_verify(req: RecoveryVerifyRequest):
    login_limiter.check(f"recovery:{req.username.lower()}")
    row = db.get_by_username(req.username)
    stored_hash = row["recovery_auth_hash"] if row else _DUMMY_HASH.decode()
    ok = bcrypt.checkpw(req.recovery_auth_key.encode(), stored_hash.encode())
    if not row or not ok:
        raise HTTPException(status_code=401, detail="That recovery phrase doesn't match this account.")
    return {
        "recovery_salt": row["recovery_salt"],
        "encrypted_identity_blob_recovery": row["encrypted_identity_blob_recovery"],
    }


@app.post("/api/forgot-password/reset")
def forgot_password_reset(req: RecoveryResetRequest):
    """Re-verifies the recovery phrase itself (never trusts a prior
    /verify call alone) before performing the actual state change —
    defense in depth against e.g. a stolen intermediate token."""
    login_limiter.check(f"recovery-reset:{req.username.lower()}")
    row = db.get_by_username(req.username)
    stored_hash = row["recovery_auth_hash"] if row else _DUMMY_HASH.decode()
    ok = bcrypt.checkpw(req.recovery_auth_key.encode(), stored_hash.encode())
    if not row or not ok:
        raise HTTPException(status_code=401, detail="That recovery phrase doesn't match this account.")
    new_password_auth_hash = bcrypt.hashpw(req.new_password_auth_key.encode(), bcrypt.gensalt()).decode()
    db.update_password(
        req.username, req.new_password_salt, new_password_auth_hash, req.new_encrypted_identity_blob
    )
    return {"status": "ok"}
