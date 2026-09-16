"""Headless smoke test for desktop "forgot password" via recovery phrase.
Proves:
  1. account creation returns a real, well-formed 12-word phrase
  2. the SAME identity key is recoverable via either the password OR the
     phrase (two independent unlock paths to the same key)
  3. resetting the password via the phrase actually changes what unlocks
     the account (old password stops working, new one works)
  4. a wrong phrase is rejected, and doesn't touch the account at all
  5. the phrase is never written to disk in plaintext anywhere in the
     account directory
Run: python3 test_recovery_smoke.py
"""
import shutil
import tempfile
from pathlib import Path

from haven import identity

tmp = Path(tempfile.mkdtemp())
identity.DATA_ROOT = tmp
print("test data root:", tmp)

account, phrase = identity.create_account("alice", "original-password-123")
words = phrase.split()
assert len(words) == 12, f"expected a 12-word phrase, got {len(words)}"
print("generated recovery phrase:", phrase)

# --- the phrase is never persisted in plaintext anywhere on disk ---
# (checking the whole contiguous phrase, not individual short words: a
# 4-6 letter word can and does turn up as a coincidental substring inside
# base64/hex ciphertext by pure chance — that's noise, not a real leak.
# The actual phrase appearing as one contiguous string would be a real one.)
for path in account.data_dir.rglob("*"):
    if path.is_file():
        data = path.read_bytes()
        assert phrase.encode() not in data, f"recovery phrase found in plaintext in {path}!"
        assert " ".join(words).encode() not in data, f"recovery phrase (rejoined) found in {path}!"
print("confirmed: the recovery phrase is not stored in plaintext anywhere in the account directory")

# --- both the password and the phrase unlock the SAME identity key ---
via_password = identity.sign_in("alice", "original-password-123")
assert via_password.identity.private_bytes == account.identity.private_bytes
print("confirmed: signing in with the password works")

recovered = identity.reset_password_with_recovery("alice", phrase, "brand-new-password-456")
assert recovered.identity.private_bytes == account.identity.private_bytes
print("confirmed: the recovery phrase unlocks the SAME underlying identity key")

# --- after reset, the OLD password must no longer work, the NEW one must ---
try:
    identity.sign_in("alice", "original-password-123")
    raise SystemExit("FAIL: old password should no longer work after reset")
except identity.WrongPassword:
    print("confirmed: the old password is invalidated by the reset")

via_new_password = identity.sign_in("alice", "brand-new-password-456")
assert via_new_password.identity.private_bytes == account.identity.private_bytes
print("confirmed: the new password works and unlocks the same identity")

# --- the recovery phrase itself keeps working for NEXT time too ---
recovered_again = identity.reset_password_with_recovery("alice", phrase, "yet-another-password-789")
assert recovered_again.identity.private_bytes == account.identity.private_bytes
print("confirmed: the same recovery phrase can be used again for a future reset")

# --- a wrong phrase is rejected cleanly, and changes nothing ---
try:
    identity.reset_password_with_recovery("alice", "wrong words that are not the phrase at all here", "x123456")
    raise SystemExit("FAIL: a wrong recovery phrase should have been rejected")
except identity.InvalidRecoveryPhrase:
    print("confirmed: a wrong recovery phrase is rejected")

still_works = identity.sign_in("alice", "yet-another-password-789")
assert still_works.identity.private_bytes == account.identity.private_bytes
print("confirmed: a failed recovery attempt did not corrupt or change the account")

# --- normalization: extra whitespace/case shouldn't matter ---
messy_phrase = "  " + "  ".join(w.upper() for w in words) + "  "
recovered_messy = identity.reset_password_with_recovery("alice", messy_phrase, "final-password-000")
assert recovered_messy.identity.private_bytes == account.identity.private_bytes
print("confirmed: recovery phrase entry is forgiving of case and extra whitespace")

shutil.rmtree(tmp)
print("\nALL RECOVERY SMOKE TESTS PASSED")
