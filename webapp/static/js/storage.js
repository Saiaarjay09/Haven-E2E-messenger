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
      const req = indexedDB.open(`haven-${username}`, 2);
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
        if (!db.objectStoreNames.contains("groups")) {
          db.createObjectStore("groups", { keyPath: "groupId" });
        }
        if (!db.objectStoreNames.contains("groupMessages")) {
          const store = db.createObjectStore("groupMessages", { keyPath: "id", autoIncrement: true });
          store.createIndex("groupId", "groupId", { unique: false });
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

    // `verified` defaults to preserving whatever was already stored
    // rather than to false — this is called on every relay
    // (re)connection (see network.js's _registerConnection), and a
    // literal `= false` default here would silently wipe out a
    // contact's safety-number verification on every reconnect.
    async upsertContact(fingerprint, username, identityPubHex, verified) {
      const existing = await this.getContact(fingerprint);
      const record = {
        fingerprint,
        username,
        identityPubHex,
        verified: verified !== undefined ? verified : existing ? existing.verified : false,
        avatarDataUrl: existing ? existing.avatarDataUrl : undefined,
        addedAt: existing ? existing.addedAt : Date.now(),
      };
      await tx(this.db, "contacts", "readwrite", (store) => store.put(record));
    }

    async setVerified(fingerprint, verified) {
      const existing = await this.getContact(fingerprint);
      if (!existing) return;
      existing.verified = verified;
      await tx(this.db, "contacts", "readwrite", (store) => store.put(existing));
    }

    async setAvatar(fingerprint, avatarDataUrl) {
      const existing = await this.getContact(fingerprint);
      if (!existing) return;
      existing.avatarDataUrl = avatarDataUrl;
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

    async saveMessage(fingerprint, direction, plaintext, kind = "text", timestamp = Date.now()) {
      const blob = await H.encryptAuthenticated(this.storageKey, H.utf8(plaintext), H.utf8(fingerprint));
      await tx(this.db, "messages", "readwrite", (store) => {
        store.add({ fingerprint, direction, kind, blobHex: H.bytesToHex(blob), timestamp });
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

    // Every message across every contact, decrypted — used only for
    // building a full-account backup (see backup.js), not the normal
    // per-chat history() path above.
    async listAllMessages() {
      const t = this.db.transaction("messages", "readonly");
      const rows = await reqToPromise(t.objectStore("messages").getAll());
      const out = [];
      for (const row of rows) {
        const plaintext = await H.decryptAuthenticated(this.storageKey, H.hexToBytes(row.blobHex), H.utf8(row.fingerprint));
        out.push({ fingerprint: row.fingerprint, direction: row.direction, kind: row.kind, text: H.fromUtf8(plaintext), ts: row.timestamp });
      }
      return out;
    }

    // Group state (membership + sender-key chains) is encrypted the same
    // way a 1:1 session is — see groups.js for what "state" contains.
    async saveGroup(groupId, name, state) {
      const blob = await H.encryptAuthenticated(this.storageKey, H.utf8(JSON.stringify(state)), H.utf8(groupId));
      await tx(this.db, "groups", "readwrite", (store) => {
        store.put({ groupId, name, blobHex: H.bytesToHex(blob), updatedAt: Date.now() });
      });
    }

    async loadGroup(groupId) {
      const t = this.db.transaction("groups", "readonly");
      const row = await reqToPromise(t.objectStore("groups").get(groupId));
      if (!row) return null;
      const plaintext = await H.decryptAuthenticated(this.storageKey, H.hexToBytes(row.blobHex), H.utf8(groupId));
      return { name: row.name, state: JSON.parse(H.fromUtf8(plaintext)) };
    }

    async listGroups() {
      const t = this.db.transaction("groups", "readonly");
      const rows = await reqToPromise(t.objectStore("groups").getAll());
      return rows.map((r) => ({ groupId: r.groupId, name: r.name }));
    }

    async saveGroupMessage(groupId, senderIdentityPubHex, plaintext, kind = "text", timestamp = Date.now()) {
      const blob = await H.encryptAuthenticated(this.storageKey, H.utf8(plaintext), H.utf8(groupId));
      await tx(this.db, "groupMessages", "readwrite", (store) => {
        store.add({ groupId, senderIdentityPubHex, kind, blobHex: H.bytesToHex(blob), timestamp });
      });
    }

    async groupHistory(groupId) {
      const t = this.db.transaction("groupMessages", "readonly");
      const index = t.objectStore("groupMessages").index("groupId");
      const rows = await reqToPromise(index.getAll(groupId));
      const out = [];
      for (const row of rows) {
        const plaintext = await H.decryptAuthenticated(this.storageKey, H.hexToBytes(row.blobHex), H.utf8(groupId));
        out.push({
          senderIdentityPubHex: row.senderIdentityPubHex,
          kind: row.kind,
          text: H.fromUtf8(plaintext),
          ts: row.timestamp,
        });
      }
      return out;
    }
  }

  return { Store };
})();
