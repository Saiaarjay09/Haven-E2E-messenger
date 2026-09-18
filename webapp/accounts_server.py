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
import sqlite3
import threading
import time

import argon2
import bcrypt
import requests
from argon2.exceptions import InvalidHash, VerifyMismatchError
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from .accounts_db import AccountsDB, UsernameTaken
from haven.crypto import SCRYPT_N_LEGACY

USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,23}$")

# New/reset credentials derive with this scrypt cost (client-side —
# see auth.js's SCRYPT_N_STRONG, which must match); existing accounts
# keep deriving with whatever cost they were created under (see
# accounts_db.py's password_kdf_n/recovery_kdf_n, returned at
# /api/login-salt and /api/recovery-salt) so their password keeps
# working. OWASP's current minimum recommendation for scrypt when
# Argon2id isn't available is N=2**17, but this JS scrypt
# implementation measured ~3-5s wall-clock at that cost (no native
# WebCrypto scrypt exists to lean on) — noticeable on every login for
# an affected account, not just once. N=2**16 is a deliberate,
# explicit choice below OWASP's strict minimum: still double the
# original N=2**15 this app used before, cutting that wait to roughly
# 1.5-2.5s, while Argon2id (see _hasher below) — which OWASP lists as
# the actual first-choice recommendation over scrypt — still protects
# the resulting auth_key at rest regardless of this number. The scrypt
# step here specifically guards a narrower case (a weak password
# combined with a stolen encrypted_identity_blob), which is why this
# tradeoff was made towards usability rather than maxing the cost out.
SCRYPT_N_CURRENT = 2**16

# Argon2id is OWASP's current first-choice recommendation for password
# hashing (stronger against GPU/ASIC cracking than bcrypt's fixed,
# comparatively small memory footprint), so all NEW auth_key/
# recovery_key hashes use it. Existing bcrypt hashes keep verifying
# correctly (see _verify_secret) and are upgraded to Argon2id in place
# the next time their owner successfully logs in — no new dependency
# on the client, no forced re-auth.
_hasher = argon2.PasswordHasher()


def _hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def _verify_secret(stored_hash: str, secret: str) -> tuple[bool, str | None]:
    """Verifies `secret` against whichever hash format is actually
    stored, transparently detected by its self-describing prefix.
    Returns (ok, upgraded_hash) — upgraded_hash is set only when this
    verified successfully against a legacy bcrypt hash, so the caller
    can re-store the SAME already-proven secret under Argon2id without
    the user doing anything differently."""
    if stored_hash.startswith("$argon2"):
        try:
            _hasher.verify(stored_hash, secret)
            return True, None
        except (VerifyMismatchError, InvalidHash):
            return False, None
    try:
        ok = bcrypt.checkpw(secret.encode(), stored_hash.encode())
    except ValueError:
        return False, None
    return (True, _hash_secret(secret)) if ok else (False, None)


# A hash of a value nobody will ever supply, used to keep login/verify
# response timing similar whether or not the username exists — reduces
# (does not eliminate — see webapp/README.md) username enumeration via
# this endpoint specifically. Argon2, to match what a real (modern)
# account's comparison now costs — see _verify_secret.
_DUMMY_HASH = _hash_secret("no-such-account-placeholder")


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
    # Optional (defaults to "") only so an older client or a test that
    # constructs this payload directly doesn't break — see auth.js,
    # which always sends the real value. A "" identity_pub just means
    # this account won't show up in people-search until it next logs in
    # (see /api/update-identity-pub's backfill).
    identity_pub: str = ""
    # Defaults to the legacy cost for the same reason: an older client
    # that doesn't send these still gets a working (if less strongly
    # derived) account rather than a broken signup. auth.js always sends
    # SCRYPT_N_CURRENT explicitly for real signups.
    password_kdf_n: int = SCRYPT_N_LEGACY
    recovery_kdf_n: int = SCRYPT_N_LEGACY

    _validate = field_validator("username")(_validate_username)


class LoginRequest(BaseModel):
    username: str
    password_auth_key: str


class UpdateIdentityPubRequest(BaseModel):
    username: str
    password_auth_key: str
    identity_pub: str


class SyncContactRequest(BaseModel):
    username: str
    password_auth_key: str
    contact_username: str


class MutualFriendsRequest(BaseModel):
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
    new_password_kdf_n: int = SCRYPT_N_LEGACY


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
search_limiter = SimpleRateLimiter(max_attempts=30, window_seconds=60.0)
# Covers the three unauthenticated GETs (username-available, login-salt,
# recovery-salt) that were previously unthrottled — none of them expose
# a secret, but login-salt/recovery-salt's 404-vs-200 response lets an
# unthrottled caller enumerate every username on the server; keyed by
# IP (not username) since the whole point of enumeration is iterating
# through many different usernames.
lookup_limiter = SimpleRateLimiter(max_attempts=60, window_seconds=60.0)
# Covers /api/contacts/sync and /api/mutual-friends — both authenticated
# (same password_auth_key check as update-identity-pub) so this is about
# limiting request volume, not guessing a secret, hence the more
# generous budget than login_limiter's.
contacts_limiter = SimpleRateLimiter(max_attempts=60, window_seconds=60.0)

# Deliberately never accepted from a request — an OpenAI key is tied to
# real billing, unlike this file's other secrets (auth_key/enc_key,
# which the browser derives itself and this server never sees in
# recoverable form). Read once from the environment at process start;
# see WEB_DEPLOYMENT.md for how to set it. /api/translate below is the
# only thing that uses it, and the key itself is never sent back to
# any client, only OpenAI's response is.
OPENAI_API_KEY = os.environ.get("HAVEN_OPENAI_API_KEY", "")
translate_limiter = SimpleRateLimiter(max_attempts=30, window_seconds=60.0)

app = FastAPI(title="Haven Accounts Service")

# CORS is scoped to this deployment's own known origins rather than "*".
# It was never load-bearing for the auth model itself — every request
# carries its own explicit auth_key in the JSON body, not a
# browser-attached credential, so there's no CSRF-style attack a
# stricter origin policy is protecting against here — but leaving it
# wide open let ANY third-party page's JS call these APIs directly
# against a visitor's browser (e.g. to enumerate /api/search-users),
# which restricting to real origins closes off. Self-hosters running
# this on a different domain should set HAVEN_ACCOUNTS_CORS_ORIGINS
# (comma-separated) rather than editing this default.
_DEFAULT_CORS_ORIGINS = "https://haven.taila6d3cb.ts.net,http://localhost:8899,http://127.0.0.1:8899"
CORS_ORIGINS = [
    o.strip() for o in os.environ.get("HAVEN_ACCOUNTS_CORS_ORIGINS", _DEFAULT_CORS_ORIGINS).split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # This origin is a pure JSON API — nothing here is ever meant to be
    # framed, sniffed as a different content type, or leak the referring
    # URL, and it never needs camera/mic access (unlike the static site,
    # which does for calls — see its own server's headers).
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/api/username-available")
def username_available(request: Request, username: str):
    lookup_limiter.check(request.client.host if request.client else "unknown")
    try:
        _validate_username(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"available": db.is_username_available(username)}


@app.post("/api/signup", status_code=201)
def signup(req: SignupRequest, request_ip: str = "unknown"):
    signup_limiter.check(req.username.lower())
    password_auth_hash = _hash_secret(req.password_auth_key)
    recovery_auth_hash = _hash_secret(req.recovery_auth_key)
    try:
        user_id = db.create_account(
            username=req.username,
            password_salt=req.password_salt,
            password_auth_hash=password_auth_hash,
            encrypted_identity_blob=req.encrypted_identity_blob,
            recovery_salt=req.recovery_salt,
            recovery_auth_hash=recovery_auth_hash,
            encrypted_identity_blob_recovery=req.encrypted_identity_blob_recovery,
            identity_pub=req.identity_pub,
            password_kdf_n=req.password_kdf_n,
            recovery_kdf_n=req.recovery_kdf_n,
        )
    except UsernameTaken as exc:
        raise HTTPException(status_code=409, detail="That username is already taken.") from exc
    return {"user_id": user_id, "username": req.username}


@app.get("/api/login-salt")
def login_salt(request: Request, username: str):
    """Salts (and the scrypt cost they were derived with — see
    accounts_db.py's docstring on password_kdf_n) are not secret — this
    just lets the browser derive auth_key from the password BEFORE
    calling /api/login, since it needs to know which salt/cost was used
    for this specific account first."""
    lookup_limiter.check(request.client.host if request.client else "unknown")
    row = db.get_by_username(username)
    if not row:
        raise HTTPException(status_code=404, detail="No such account.")
    return {"password_salt": row["password_salt"], "password_kdf_n": row["password_kdf_n"]}


@app.get("/api/recovery-salt")
def recovery_salt(request: Request, username: str):
    lookup_limiter.check(request.client.host if request.client else "unknown")
    row = db.get_by_username(username)
    if not row:
        raise HTTPException(status_code=404, detail="No such account.")
    return {"recovery_salt": row["recovery_salt"], "recovery_kdf_n": row["recovery_kdf_n"]}


@app.post("/api/login")
def login(req: LoginRequest):
    login_limiter.check(req.username.lower())
    row = db.get_by_username(req.username)
    stored_hash = row["password_auth_hash"] if row else _DUMMY_HASH
    ok, upgraded = _verify_secret(stored_hash, req.password_auth_key)
    if not row or not ok:
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    if upgraded:
        db.upgrade_password_hash(req.username, upgraded)
    return {"password_salt": row["password_salt"], "encrypted_identity_blob": row["encrypted_identity_blob"]}


@app.post("/api/update-identity-pub")
def update_identity_pub(req: UpdateIdentityPubRequest):
    """Backfills the directory entry search_users reads from. Reuses the
    SAME password_auth_key proof /api/login just verified (the browser
    calls this right after a successful login, with no extra password
    prompt) rather than trusting identity_pub unauthenticated — an
    unauthenticated version of this endpoint would let anyone overwrite
    someone else's directory entry with an attacker-controlled key,
    silently hijacking who a contact search actually connects you to."""
    login_limiter.check(req.username.lower())
    row = db.get_by_username(req.username)
    stored_hash = row["password_auth_hash"] if row else _DUMMY_HASH
    ok, upgraded = _verify_secret(stored_hash, req.password_auth_key)
    if not row or not ok:
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    if upgraded:
        db.upgrade_password_hash(req.username, upgraded)
    db.set_identity_pub(req.username, req.identity_pub)
    return {"status": "ok"}


@app.get("/api/search-users")
def search_users(q: str, exclude: str = ""):
    """Powers the sidebar's people-search: matches by substring against
    usernames (not case-sensitive), returning only accounts that have
    announced an identity_pub (see update_identity_pub) since a result
    with no key would be a dead end for actually starting a chat."""
    search_limiter.check(exclude.lower() or "anonymous")
    q = q.strip()
    if not q:
        return {"results": []}
    rows = db.search_usernames(q, exclude_username=exclude, limit=15)
    return {"results": [{"username": r["username"], "identity_pub": r["identity_pub"]} for r in rows]}


def _require_password_auth(username: str, password_auth_key: str) -> sqlite3.Row:
    """Shared by every endpoint below that needs to act as a specific
    account — same password_auth_key check /api/login itself uses, so
    calling this never prompts the user for their password again (the
    browser already has auth_key in memory for the session — see
    auth.js's AccountsClient)."""
    row = db.get_by_username(username)
    stored_hash = row["password_auth_hash"] if row else _DUMMY_HASH
    ok, upgraded = _verify_secret(stored_hash, password_auth_key)
    if not row or not ok:
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    if upgraded:
        db.upgrade_password_hash(username, upgraded)
    return row


@app.post("/api/contacts/sync")
def sync_contact(req: SyncContactRequest):
    """Records that req.username and req.contact_username are now
    mutual (accepted) contacts — see network.js, which calls this the
    moment a hello/hello_ack handshake actually completes, never on a
    one-sided request. This is the one place this server learns
    anything about the social graph beyond the username directory
    itself — see accounts_db.py's module docstring for that trade-off."""
    contacts_limiter.check(req.username.lower())
    _require_password_auth(req.username, req.password_auth_key)
    try:
        _validate_username(req.contact_username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.add_contact_edge(req.username, req.contact_username)
    return {"status": "ok"}


@app.post("/api/mutual-friends")
def mutual_friends(req: MutualFriendsRequest):
    """Powers the Mutual Friends tab: accounts that share at least one
    contact with you, that you're not already connected to. Only ever
    reads edges recorded by sync_contact above — this endpoint itself
    doesn't add anything to the graph."""
    contacts_limiter.check(req.username.lower())
    _require_password_auth(req.username, req.password_auth_key)
    rows = db.suggest_mutual_friends(req.username, limit=15)
    return {
        "results": [
            {"username": r["username"], "identity_pub": r["identity_pub"], "mutual_count": r["mutual_count"]}
            for r in rows
        ]
    }


@app.post("/api/forgot-password/verify")
def forgot_password_verify(req: RecoveryVerifyRequest):
    login_limiter.check(f"recovery:{req.username.lower()}")
    row = db.get_by_username(req.username)
    stored_hash = row["recovery_auth_hash"] if row else _DUMMY_HASH
    ok, upgraded = _verify_secret(stored_hash, req.recovery_auth_key)
    if not row or not ok:
        raise HTTPException(status_code=401, detail="That recovery phrase doesn't match this account.")
    if upgraded:
        db.upgrade_recovery_hash(req.username, upgraded)
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
    stored_hash = row["recovery_auth_hash"] if row else _DUMMY_HASH
    ok, upgraded = _verify_secret(stored_hash, req.recovery_auth_key)
    if not row or not ok:
        raise HTTPException(status_code=401, detail="That recovery phrase doesn't match this account.")
    if upgraded:
        db.upgrade_recovery_hash(req.username, upgraded)
    # Always Argon2id + the current scrypt cost for the freshly-set
    # password, same as signup — a reset is exactly the moment a weaker
    # legacy account can be brought fully up to date.
    new_password_auth_hash = _hash_secret(req.new_password_auth_key)
    db.update_password(
        req.username,
        req.new_password_salt,
        new_password_auth_hash,
        req.new_encrypted_identity_blob,
        password_kdf_n=req.new_password_kdf_n,
    )
    return {"status": "ok"}


@app.post("/api/translate")
def translate_audio(request: Request, file: UploadFile = File(...)):
    """Proxies one call-audio clip to OpenAI's Whisper translation
    endpoint and returns only its result — see translation.js for why
    this exists server-side rather than calling OpenAI directly from
    the browser. A plain `def` (not `async def`) so FastAPI runs this
    in its worker thread pool, since the outbound call below is a
    blocking `requests` call, not an awaited one."""
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=503, detail="Translation is not configured on this server.")
    client_ip = request.client.host if request.client else "unknown"
    translate_limiter.check(client_ip)

    audio_bytes = file.file.read()
    if len(audio_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Audio clip too large.")

    try:
        resp = requests.post(
            "https://api.openai.com/v1/audio/translations",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            files={"file": ("audio.wav", audio_bytes, "audio/wav")},
            data={"model": "whisper-1", "response_format": "verbose_json"},
            timeout=30,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="Could not reach the translation service.") from exc
    if not resp.ok:
        raise HTTPException(status_code=502, detail="Translation service error.")

    data = resp.json()
    return {"text": data.get("text", ""), "language": data.get("language", "")}
