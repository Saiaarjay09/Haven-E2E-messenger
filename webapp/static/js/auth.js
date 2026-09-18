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

  // Every NEW or reset password/recovery-phrase derivation uses this
  // scrypt cost — stronger than crypto.js's own SCRYPT_N default, which
  // stays fixed forever for local backup files (see crypto.js's
  // comment). Must match accounts_server.py's SCRYPT_N_CURRENT. An
  // EXISTING account keeps deriving with whatever cost the server
  // says it was actually created under (see login/resetPassword below,
  // which read password_kdf_n/recovery_kdf_n back from the server
  // rather than assuming this constant applies to every account).
  //
  // Deliberately 2**16, not OWASP's stricter 2**17 minimum — this repo
  // has no native scrypt to lean on (WebCrypto doesn't provide one) and
  // the from-spec JS implementation measured ~3-5s wall-clock at
  // 2**17 on real hardware, which is a genuinely bad "click Log in"
  // experience on every affected login, not just once at signup. This
  // still doubles the original N=2**15, and Argon2id (see
  // accounts_server.py) — the actually-preferred algorithm here —
  // protects the auth_key regardless of this number.
  const SCRYPT_N_STRONG = 2 ** 16;

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
      this.username = null;
      // Kept in memory only (never persisted) for the rest of the
      // session after signup/login so later authenticated calls —
      // syncContact, mutualFriends — don't need to re-prompt for the
      // password. Same proof /api/login itself already verified.
      this._authKeyHex = null;
    }

    async usernameAvailable(username) {
      const r = await fetch(`${this.baseUrl}/api/username-available?username=${encodeURIComponent(username)}`);
      const data = await r.json();
      return data.available;
    }

    async signup(username, password) {
      const identity = await H.generateKeyPair();
      const phrase = await generateRecoveryPhrase();
      const normalized = normalizePhrase(phrase);

      const pwSalt = crypto.getRandomValues(new Uint8Array(16));
      const recSalt = crypto.getRandomValues(new Uint8Array(16));
      // Both derivations are independent (different secrets, different
      // salts) — running them via Promise.all lets the worker start the
      // second as soon as it's free instead of the main thread awaiting
      // one fully before even asking for the other.
      const [
        { authKey: pwAuthKey, encKey: pwEncKey },
        { authKey: recAuthKey, encKey: recEncKey },
      ] = await Promise.all([
        HavenScryptWorker.deriveSplitKeys(password, pwSalt, SCRYPT_N_STRONG),
        HavenScryptWorker.deriveSplitKeys(normalized, recSalt, SCRYPT_N_STRONG),
      ]);
      const encryptedPw = await H.encryptAuthenticated(pwEncKey, identity.privateBytes, H.utf8(username));
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
          password_kdf_n: SCRYPT_N_STRONG,
          recovery_kdf_n: SCRYPT_N_STRONG,
        }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(err.detail || "Signup failed");
      }
      this.username = username;
      this._authKeyHex = H.bytesToHex(pwAuthKey);
      return { identity, recoveryPhrase: phrase, username };
    }

    async login(username, password) {
      const saltResp = await fetch(`${this.baseUrl}/api/login-salt?username=${encodeURIComponent(username)}`);
      if (!saltResp.ok) throw new Error("No such account.");
      const { password_salt, password_kdf_n } = await saltResp.json();
      const pwSalt = H.hexToBytes(password_salt);
      // Whatever cost THIS account was actually created/last-reset
      // under — not necessarily SCRYPT_N_STRONG, for an account that
      // predates it (see accounts_db.py's password_kdf_n).
      const { authKey, encKey } = await HavenScryptWorker.deriveSplitKeys(password, pwSalt, password_kdf_n);

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

      this.username = username;
      this._authKeyHex = H.bytesToHex(authKey);
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
      const { recovery_salt, recovery_kdf_n } = await saltResp.json();
      const recSalt = H.hexToBytes(recovery_salt);
      const { authKey, encKey } = await HavenScryptWorker.deriveSplitKeys(normalized, recSalt, recovery_kdf_n);

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

      // The NEW password always gets the current strong cost, fresh
      // salt — a reset is exactly the moment to bring an older account
      // fully up to date, same as accounts_server.py does for the hash
      // format on this same call.
      const newSalt = crypto.getRandomValues(new Uint8Array(16));
      const { authKey: newAuthKey, encKey: newEncKey } = await HavenScryptWorker.deriveSplitKeys(newPassword, newSalt, SCRYPT_N_STRONG);
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
          new_password_kdf_n: SCRYPT_N_STRONG,
        }),
      });
      if (!resetResp.ok) throw new Error("Password reset failed.");
      const identity = await H.keyPairFromPrivateBytes(privateBytes);
      this.username = username;
      this._authKeyHex = H.bytesToHex(newAuthKey);
      return { identity, username };
    }

    // Records a newly-mutual contact server-side (see accounts_server.py's
    // /api/contacts/sync) so it can power mutualFriends() below — called
    // once per pair, only once a hello/hello_ack handshake has actually
    // completed (see network.js), never for a one-sided request. A
    // no-op if this client never logged in this session (e.g. a session
    // restored straight from a backup file — see backup.js) or the call
    // fails for any reason; "people you may know" is a nice-to-have, not
    // something worth surfacing an error for.
    async syncContact(contactUsername) {
      if (!this._authKeyHex) return;
      try {
        await fetch(`${this.baseUrl}/api/contacts/sync`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: this.username, password_auth_key: this._authKeyHex, contact_username: contactUsername }),
        });
      } catch (e) {
        console.error("syncContact failed:", e);
      }
    }

    async mutualFriends() {
      if (!this._authKeyHex) return [];
      try {
        const r = await fetch(`${this.baseUrl}/api/mutual-friends`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: this.username, password_auth_key: this._authKeyHex }),
        });
        if (!r.ok) return [];
        const data = await r.json();
        return data.results || [];
      } catch (e) {
        console.error("mutualFriends failed:", e);
        return [];
      }
    }
  }

  return { AccountsClient, generateRecoveryPhrase, normalizePhrase };
})();
