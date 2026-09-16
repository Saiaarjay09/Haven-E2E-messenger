"""Headless smoke test for Phase 7a: the hosted accounts service.

Drives a REAL running uvicorn instance over real HTTP, using a Python
stand-in for what a browser client will eventually do in JavaScript
(haven/crypto.py's derive_split_keys + encrypt_authenticated define the
exact protocol any future JS client must replicate — this test doubles
as that protocol's specification). Proves:
  1. signup enforces global, case-insensitive username uniqueness
  2. login only succeeds with the right password, and correctly recovers
     the SAME identity key that was generated at signup
  3. the recovery-phrase flow recovers the same key and can reset the
     password; the old password stops working, the new one works
  4. a wrong recovery phrase is rejected and changes nothing
  5. the server's own database never contains the password, the
     recovery phrase, or the raw identity private key in plaintext —
     only auth hashes and ciphertext blobs
Run: python3 test_webapp_accounts_smoke.py
"""
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

from haven import crypto, recovery

PORT = 18901
BASE_URL = f"http://127.0.0.1:{PORT}"
tmp = Path(tempfile.mkdtemp())
db_path = str(tmp / "accounts.db")
print("test db:", db_path)


def wait_until(predicate, timeout=8.0, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _server_up():
    try:
        requests.get(f"{BASE_URL}/api/username-available", params={"username": "healthcheck"}, timeout=1)
        return True
    except requests.exceptions.ConnectionError:
        return False


# Started and torn down inside the try/finally below (not here) — a crash
# during startup itself must not leak the subprocess, the way an earlier,
# broken version of this test once did.
server_proc = None


# --- simulated browser client: EXACTLY what a real JS client must do ---
def browser_signup(username: str, password: str):
    identity_priv = os.urandom(32)  # stand-in for a freshly generated X25519 private key

    pw_salt = os.urandom(16)
    pw_auth_key, pw_enc_key = crypto.derive_split_keys(password, pw_salt)
    encrypted_pw = crypto.encrypt_authenticated(pw_enc_key, identity_priv, aad=username.encode())

    phrase = recovery.generate_recovery_phrase()
    normalized = recovery.normalize_phrase(phrase)
    rec_salt = os.urandom(16)
    rec_auth_key, rec_enc_key = crypto.derive_split_keys(normalized, rec_salt)
    encrypted_rec = crypto.encrypt_authenticated(rec_enc_key, identity_priv, aad=username.encode())

    resp = requests.post(
        f"{BASE_URL}/api/signup",
        json={
            "username": username,
            "password_salt": pw_salt.hex(),
            "password_auth_key": pw_auth_key.hex(),
            "encrypted_identity_blob": encrypted_pw.hex(),
            "recovery_salt": rec_salt.hex(),
            "recovery_auth_key": rec_auth_key.hex(),
            "encrypted_identity_blob_recovery": encrypted_rec.hex(),
        },
    )
    return resp, identity_priv, phrase


def browser_login(username: str, password: str) -> requests.Response:
    salt_resp = requests.get(f"{BASE_URL}/api/login-salt", params={"username": username})
    if salt_resp.status_code != 200:
        return salt_resp
    pw_salt = bytes.fromhex(salt_resp.json()["password_salt"])
    auth_key, enc_key = crypto.derive_split_keys(password, pw_salt)
    resp = requests.post(f"{BASE_URL}/api/login", json={"username": username, "password_auth_key": auth_key.hex()})
    if resp.status_code == 200:
        blob = bytes.fromhex(resp.json()["encrypted_identity_blob"])
        identity_priv = crypto.decrypt_authenticated(enc_key, blob, aad=username.encode())
        return resp, identity_priv
    return resp, None


def browser_recover(username: str, phrase: str, new_password: str | None = None):
    normalized = recovery.normalize_phrase(phrase)
    salt_resp = requests.get(f"{BASE_URL}/api/recovery-salt", params={"username": username})
    if salt_resp.status_code != 200:
        return salt_resp, None
    rec_salt = bytes.fromhex(salt_resp.json()["recovery_salt"])
    auth_key, enc_key = crypto.derive_split_keys(normalized, rec_salt)
    verify_resp = requests.post(
        f"{BASE_URL}/api/forgot-password/verify", json={"username": username, "recovery_auth_key": auth_key.hex()}
    )
    if verify_resp.status_code != 200:
        return verify_resp, None
    blob = bytes.fromhex(verify_resp.json()["encrypted_identity_blob_recovery"])
    identity_priv = crypto.decrypt_authenticated(enc_key, blob, aad=username.encode())

    if new_password is not None:
        new_salt = os.urandom(16)
        new_pw_auth_key, new_enc = crypto.derive_split_keys(new_password, new_salt)
        new_blob = crypto.encrypt_authenticated(new_enc, identity_priv, aad=username.encode())
        reset_resp = requests.post(
            f"{BASE_URL}/api/forgot-password/reset",
            json={
                "username": username,
                "recovery_auth_key": auth_key.hex(),
                "new_password_salt": new_salt.hex(),
                "new_password_auth_key": new_pw_auth_key.hex(),
                "new_encrypted_identity_blob": new_blob.hex(),
            },
        )
        return reset_resp, identity_priv
    return verify_resp, identity_priv


try:
    env = dict(os.environ, HAVEN_ACCOUNTS_DB=db_path)
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "webapp.accounts_server:app", "--port", str(PORT)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert wait_until(_server_up), "accounts server never came up"
    print("accounts server is up on port", PORT)

    # --- 1. signup + global uniqueness ---
    resp, alice_priv, alice_phrase = browser_signup("alice", "alice-password-123")
    assert resp.status_code == 201, resp.text
    print("confirmed: signup succeeds")

    resp, _, _ = browser_signup("alice", "different-password")
    assert resp.status_code == 409
    print("confirmed: signing up the same username again is rejected (409)")

    resp, _, _ = browser_signup("ALICE", "different-password")
    assert resp.status_code == 409
    print("confirmed: username uniqueness is case-insensitive ('ALICE' collides with 'alice')")

    avail = requests.get(f"{BASE_URL}/api/username-available", params={"username": "bob"}).json()
    assert avail["available"] is True
    avail = requests.get(f"{BASE_URL}/api/username-available", params={"username": "alice"}).json()
    assert avail["available"] is False
    print("confirmed: username-available reflects taken/free correctly")

    # --- 2. login recovers the same key, wrong password fails ---
    resp, recovered_priv = browser_login("alice", "alice-password-123")
    assert resp.status_code == 200
    assert recovered_priv == alice_priv, "login did not recover the same identity key generated at signup"
    print("confirmed: login with the correct password recovers the exact same identity key")

    resp, _ = browser_login("alice", "wrong-password")
    assert resp.status_code == 401
    print("confirmed: login with the wrong password is rejected (401)")

    # --- 3. forgot-password: verify + reset ---
    resp, recovered_priv = browser_recover("alice", alice_phrase)
    assert resp.status_code == 200
    assert recovered_priv == alice_priv
    print("confirmed: recovery phrase alone recovers the same identity key (no password needed)")

    resp, _ = browser_recover("alice", alice_phrase, new_password="brand-new-password-456")
    assert resp.status_code == 200
    print("confirmed: password reset via recovery phrase succeeds")

    resp, _ = browser_login("alice", "alice-password-123")
    assert resp.status_code == 401, "old password should no longer work after reset"
    print("confirmed: the old password no longer works after reset")

    resp, recovered_priv = browser_login("alice", "brand-new-password-456")
    assert resp.status_code == 200 and recovered_priv == alice_priv
    print("confirmed: the new password works and still unlocks the same identity")

    # --- 4. wrong recovery phrase is rejected, changes nothing ---
    resp, _ = browser_recover("alice", "totally the wrong twelve made up words right here now", "x")
    assert resp.status_code in (401, 404)
    print("confirmed: a wrong recovery phrase is rejected")

    resp, recovered_priv = browser_login("alice", "brand-new-password-456")
    assert resp.status_code == 200 and recovered_priv == alice_priv
    print("confirmed: the failed recovery attempt did not change the account")

    # --- 5. server-side storage never contains plaintext secrets ---
    server_proc.terminate()
    server_proc.wait(timeout=5)
    raw = Path(db_path).read_bytes()
    assert b"alice-password-123" not in raw
    assert b"brand-new-password-456" not in raw
    assert alice_priv not in raw, "raw identity private key bytes found in the accounts database!"
    # Check the whole contiguous phrase, not individual short words — a
    # 4-6 letter word can (and did, during testing) turn up as a
    # coincidental substring inside a bcrypt hash or hex blob by pure
    # chance. That's noise, not a leak; the actual phrase appearing
    # contiguously would be the real signal.
    assert alice_phrase.encode() not in raw, "the recovery phrase itself was found in the accounts database!"
    print("confirmed: the accounts database contains no plaintext passwords, phrases, or private keys")

finally:
    if server_proc is not None and server_proc.poll() is None:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait(timeout=5)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nALL WEBAPP ACCOUNTS SMOKE TESTS PASSED")
