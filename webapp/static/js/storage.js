/**
 * Browser-side encrypted local storage — the IndexedDB equivalent of
 * haven/storage.py. Same design: message content is decrypted once on
 * receipt and re-encrypted at rest with a key derived from the identity
 * key (never the password), independent of the wire ratchet.
 */

const HavenStorage = (() => {
  "use strict";
  const H = Haven;

  function openDb(username) {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(`haven-${username}`, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains("contacts")) {
          db.createObjectStore("contacts", { keyPath: "fingerprint" });
        }
        if (!db.objectStoreNames.contains("sessions")) {
          db.createObjectStore("sessions", { keyPath: "fingerprint" });
        }
        if (!db.objectStoreNames.contains("messages")) {
          const store = db.createObjectStore("messages", { keyPath: "id", autoIncrement: true });
          store.createIndex("fingerprint", "fingerprint", { unique: false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function tx(db, storeName, mode, fn) {
    return new Promise((resolve, reject) => {
      const t = db.transaction(storeName, mode);
      const store = t.objectStore(storeName);
      const result = fn(store);
      t.oncomplete = () => resolve(result);
      t.onerror = () => reject(t.error);
    });
  }

  function reqToPromise(req) {
    return new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  class Store {
    constructor(db, storageKey) {
      this.db = db;
      this.storageKey = storageKey;
    }

    static async open(username, identityPrivateBytes) {
      const db = await openDb(username);
      const storageKey = await H.hkdf(identityPrivateBytes, H.utf8("local-storage-v1"));
      return new Store(db, storageKey);
    }

    async upsertContact(fingerprint, username, identityPubHex, verified = false) {
      await tx(this.db, "contacts", "readwrite", (store) => {
        store.put({ fingerprint, username, identityPubHex, verified, addedAt: Date.now() });
      });
    }

    async setVerified(fingerprint, verified) {
      const existing = await this.getContact(fingerprint);
      if (!existing) return;
      existing.verified = verified;
      await tx(this.db, "contacts", "readwrite", (store) => store.put(existing));
    }

    async getContact(fingerprint) {
      const t = this.db.transaction("contacts", "readonly");
      return reqToPromise(t.objectStore("contacts").get(fingerprint));
    }

    async listContacts() {
      const t = this.db.transaction("contacts", "readonly");
      return reqToPromise(t.objectStore("contacts").getAll());
    }

    async saveSession(fingerprint, session) {
      const state = {
        sendChainKeyHex: H.bytesToHex(session.sendChainKey),
        recvChainKeyHex: H.bytesToHex(session.recvChainKey),
        sendIndex: session.sendIndex,
        recvIndex: session.recvIndex,
      };
      const blob = await H.encryptAuthenticated(this.storageKey, H.utf8(JSON.stringify(state)), H.utf8(fingerprint));
      await tx(this.db, "sessions", "readwrite", (store) => store.put({ fingerprint, blobHex: H.bytesToHex(blob) }));
    }

    async loadSession(fingerprint) {
      const t = this.db.transaction("sessions", "readonly");
      const row = await reqToPromise(t.objectStore("sessions").get(fingerprint));
      if (!row) return null;
      const plaintext = await H.decryptAuthenticated(this.storageKey, H.hexToBytes(row.blobHex), H.utf8(fingerprint));
      const state = JSON.parse(H.fromUtf8(plaintext));
      return new H.RatchetSession(
        H.hexToBytes(state.sendChainKeyHex),
        H.hexToBytes(state.recvChainKeyHex),
        state.sendIndex,
        state.recvIndex
      );
    }

    async saveMessage(fingerprint, direction, plaintext, kind = "text") {
      const blob = await H.encryptAuthenticated(this.storageKey, H.utf8(plaintext), H.utf8(fingerprint));
      await tx(this.db, "messages", "readwrite", (store) => {
        store.add({ fingerprint, direction, kind, blobHex: H.bytesToHex(blob), timestamp: Date.now() });
      });
    }

    async history(fingerprint) {
      const t = this.db.transaction("messages", "readonly");
      const index = t.objectStore("messages").index("fingerprint");
      const rows = await reqToPromise(index.getAll(fingerprint));
      const out = [];
      for (const row of rows) {
        const plaintext = await H.decryptAuthenticated(this.storageKey, H.hexToBytes(row.blobHex), H.utf8(fingerprint));
        out.push({ direction: row.direction, kind: row.kind, text: H.fromUtf8(plaintext), ts: row.timestamp });
      }
      return out;
    }
  }

  return { Store };
})();
