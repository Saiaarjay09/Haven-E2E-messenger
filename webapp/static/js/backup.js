/**
 * Encrypted, portable account backup — export everything IndexedDB holds
 * for one account (identity key, contacts, full message history) into a
 * single password-protected file, and restore it back into a fresh
 * browser/device without ever touching the accounts server.
 *
 * Uses the exact same format as the desktop app's haven/backup.py: same
 * magic string, same JSON bundle shape, same scrypt-derived key, same
 * deniable AES-CTR cipher (wrong password decrypts to unstructured
 * garbage rather than a clean, attacker-visible failure — see
 * crypto.py's encrypt_deniable for why). A file exported here should be
 * restorable by the desktop app's restore_backup(), and vice versa.
 */

const HavenBackup = (() => {
  "use strict";
  const H = Haven;
  const MAGIC = "HAVEN-BACKUP-V1";

  async function exportBackup(identity, username, store, password) {
    const contacts = await store.listContacts();
    const messages = await store.listAllMessages();
    const bundle = {
      magic: MAGIC,
      username,
      identity_private_key: H.bytesToHex(identity.privateBytes),
      created_at: Date.now() / 1000,
      contacts: contacts.map((c) => ({
        fingerprint: c.fingerprint,
        username: c.username,
        identity_pub: c.identityPubHex,
        host: "",
        port: 0,
        verified: c.verified,
        added_at: c.addedAt,
      })),
      messages: messages.map((m) => ({
        fingerprint: m.fingerprint,
        direction: m.direction,
        kind: m.kind,
        text: m.text,
        ts: m.ts,
      })),
    };

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await HavenScryptWorker.deriveKeyFromPassword(password, salt);
    const plaintext = H.utf8(JSON.stringify(bundle));
    const ciphertext = await H.encryptDeniable(key, plaintext);
    return H.concatBytes(salt, ciphertext);
  }

  async function restoreBackup(fileBytes, password) {
    const salt = fileBytes.slice(0, 16);
    const ciphertext = fileBytes.slice(16);
    const key = await HavenScryptWorker.deriveKeyFromPassword(password, salt);
    const plaintext = await H.decryptDeniable(key, ciphertext);

    let bundle;
    try {
      // fatal:true matches Python's default strict UTF-8 decode — a wrong
      // password's garbage plaintext should fail fast here rather than
      // silently turning into a mangled string for JSON.parse to trip on.
      const text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      bundle = JSON.parse(text);
    } catch (e) {
      throw new Error("Could not restore backup (wrong password or corrupted file).");
    }
    if (bundle.magic !== MAGIC) {
      throw new Error("Could not restore backup (wrong password or corrupted file).");
    }
    return bundle;
  }

  return { exportBackup, restoreBackup, MAGIC };
})();
