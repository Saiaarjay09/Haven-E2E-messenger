/**
 * Browser client for the hosted accounts service (webapp/accounts_server.py)
 * — this IS the reference implementation the protocol in
 * webapp/README.md describes: derive auth_key/enc_key locally via
 * crypto.derive_split_keys, send only auth_key to the server, keep
 * enc_key in the browser forever.
 */

const HavenAuth = (() => {
  "use strict";
  const H = Haven;
  let wordlist = null;

  async function loadWordlist() {
    if (!wordlist) wordlist = await fetch("js/wordlist.json").then((r) => r.json());
    return wordlist;
  }

  async function generateRecoveryPhrase(numWords = 12) {
    const words = await loadWordlist();
    const indices = crypto.getRandomValues(new Uint16Array(numWords));
    return Array.from(indices)
      .map((i) => words[i % words.length])
      .join(" ");
  }

  function normalizePhrase(phrase) {
    return phrase.trim().toLowerCase().split(/\s+/).join(" ");
  }

  class AccountsClient {
    constructor(baseUrl) {
      this.baseUrl = baseUrl.replace(/\/$/, "");
    }

    async usernameAvailable(username) {
      const r = await fetch(`${this.baseUrl}/api/username-available?username=${encodeURIComponent(username)}`);
      const data = await r.json();
      return data.available;
    }

    async signup(username, password) {
      const identity = await H.generateKeyPair();

      const pwSalt = crypto.getRandomValues(new Uint8Array(16));
      const { authKey: pwAuthKey, encKey: pwEncKey } = await H.deriveSplitKeys(password, pwSalt);
      const encryptedPw = await H.encryptAuthenticated(pwEncKey, identity.privateBytes, H.utf8(username));

      const phrase = await generateRecoveryPhrase();
      const normalized = normalizePhrase(phrase);
      const recSalt = crypto.getRandomValues(new Uint8Array(16));
      const { authKey: recAuthKey, encKey: recEncKey } = await H.deriveSplitKeys(normalized, recSalt);
      const encryptedRec = await H.encryptAuthenticated(recEncKey, identity.privateBytes, H.utf8(username));

      const resp = await fetch(`${this.baseUrl}/api/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password_salt: H.bytesToHex(pwSalt),
          password_auth_key: H.bytesToHex(pwAuthKey),
          encrypted_identity_blob: H.bytesToHex(encryptedPw),
          recovery_salt: H.bytesToHex(recSalt),
          recovery_auth_key: H.bytesToHex(recAuthKey),
          encrypted_identity_blob_recovery: H.bytesToHex(encryptedRec),
          // Not a secret — see accounts_db.py's docstring. Registers
          // this account in the people-search directory right away.
          identity_pub: H.bytesToHex(identity.publicBytes),
        }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(err.detail || "Signup failed");
      }
      return { identity, recoveryPhrase: phrase, username };
    }

    async login(username, password) {
      const saltResp = await fetch(`${this.baseUrl}/api/login-salt?username=${encodeURIComponent(username)}`);
      if (!saltResp.ok) throw new Error("No such account.");
      const { password_salt } = await saltResp.json();
      const pwSalt = H.hexToBytes(password_salt);
      const { authKey, encKey } = await H.deriveSplitKeys(password, pwSalt);

      const resp = await fetch(`${this.baseUrl}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password_auth_key: H.bytesToHex(authKey) }),
      });
      if (!resp.ok) throw new Error("Wrong username or password.");
      const { encrypted_identity_blob } = await resp.json();
      const privateBytes = await H.decryptAuthenticated(encKey, H.hexToBytes(encrypted_identity_blob), H.utf8(username));
      const identity = await H.keyPairFromPrivateBytes(privateBytes);

      // Best-effort directory backfill for accounts that predate the
      // identity_pub column (or whose last-announced key is somehow
      // stale) — reuses the SAME auth_key /api/login just verified, so
      // no extra password prompt, and never blocks login on failure.
      fetch(`${this.baseUrl}/api/update-identity-pub`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password_auth_key: H.bytesToHex(authKey), identity_pub: H.bytesToHex(identity.publicBytes) }),
      }).catch(() => {});

      return { identity, username };
    }

    async searchUsers(query, excludeUsername) {
      const params = new URLSearchParams({ q: query, exclude: excludeUsername || "" });
      const r = await fetch(`${this.baseUrl}/api/search-users?${params}`);
      if (!r.ok) return [];
      const data = await r.json();
      return data.results || [];
    }

    async resetPassword(username, recoveryPhrase, newPassword) {
      const normalized = normalizePhrase(recoveryPhrase);
      const saltResp = await fetch(`${this.baseUrl}/api/recovery-salt?username=${encodeURIComponent(username)}`);
      if (!saltResp.ok) throw new Error("No such account.");
      const { recovery_salt } = await saltResp.json();
      const recSalt = H.hexToBytes(recovery_salt);
      const { authKey, encKey } = await H.deriveSplitKeys(normalized, recSalt);

      const verifyResp = await fetch(`${this.baseUrl}/api/forgot-password/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, recovery_auth_key: H.bytesToHex(authKey) }),
      });
      if (!verifyResp.ok) throw new Error("That recovery phrase doesn't match this account.");
      const { encrypted_identity_blob_recovery } = await verifyResp.json();
      const privateBytes = await H.decryptAuthenticated(
        encKey,
        H.hexToBytes(encrypted_identity_blob_recovery),
        H.utf8(username)
      );

      const newSalt = crypto.getRandomValues(new Uint8Array(16));
      const { authKey: newAuthKey, encKey: newEncKey } = await H.deriveSplitKeys(newPassword, newSalt);
      const newBlob = await H.encryptAuthenticated(newEncKey, privateBytes, H.utf8(username));

      const resetResp = await fetch(`${this.baseUrl}/api/forgot-password/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          recovery_auth_key: H.bytesToHex(authKey),
          new_password_salt: H.bytesToHex(newSalt),
          new_password_auth_key: H.bytesToHex(newAuthKey),
          new_encrypted_identity_blob: H.bytesToHex(newBlob),
        }),
      });
      if (!resetResp.ok) throw new Error("Password reset failed.");
      const identity = await H.keyPairFromPrivateBytes(privateBytes);
      return { identity, username };
    }
  }

  return { AccountsClient, generateRecoveryPhrase, normalizePhrase };
})();
