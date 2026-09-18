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

    // Returns the row's local auto-increment id — see network.js's
    // sendText/_handleMsg, which thread it through to the UI so a
    // rendered bubble can be found again later (to update its seen-tick,
    // or to pin/reply-target it). msgIndex is the ratchet envelope index
    // this plaintext was sent/received at (only meaningful for "out"
    // messages here — see markSeenUpTo, which uses it as a "read up to"
    // watermark instead of needing a per-message read-receipt id).
    async saveMessage(fingerprint, direction, plaintext, kind = "text", timestamp = Date.now(), msgIndex = null) {
      const blob = await H.encryptAuthenticated(this.storageKey, H.utf8(plaintext), H.utf8(fingerprint));
      const req = await tx(this.db, "messages", "readwrite", (store) =>
        store.add({ fingerprint, direction, kind, blobHex: H.bytesToHex(blob), timestamp, msgIndex, seen: false, pinned: false })
      );
      return req.result;
    }

    async history(fingerprint) {
      const t = this.db.transaction("messages", "readonly");
      const index = t.objectStore("messages").index("fingerprint");
      const rows = await reqToPromise(index.getAll(fingerprint));
      const out = [];
      for (const row of rows) {
        const plaintext = await H.decryptAuthenticated(this.storageKey, H.hexToBytes(row.blobHex), H.utf8(fingerprint));
        out.push({
          id: row.id,
          direction: row.direction,
          kind: row.kind,
          text: H.fromUtf8(plaintext),
          ts: row.timestamp,
          seen: !!row.seen,
          pinned: !!row.pinned,
        });
      }
      return out;
    }

    // Marks every outgoing message with a ratchet index <= upToIndex as
    // seen — the recipient sends this "read up to" watermark (their
    // session's recvIndex, see network.js) rather than acking each
    // message individually, which is simpler and self-healing (one lost
    // receipt doesn't leave a message stuck "unseen" forever, the next
    // receipt covers it too).
    async markSeenUpTo(fingerprint, upToIndex) {
      return new Promise((resolve, reject) => {
        const t = this.db.transaction("messages", "readwrite");
        const req = t.objectStore("messages").index("fingerprint").openCursor(IDBKeyRange.only(fingerprint));
        req.onsuccess = () => {
          const cursor = req.result;
          if (!cursor) return;
          const row = cursor.value;
          if (row.direction === "out" && row.msgIndex != null && row.msgIndex <= upToIndex && !row.seen) {
            row.seen = true;
            cursor.update(row);
          }
          cursor.continue();
        };
        req.onerror = () => reject(req.error);
        t.oncomplete = () => resolve();
        t.onerror = () => reject(t.error);
      });
    }

    async setPinned(id, pinned) {
      return new Promise((resolve, reject) => {
        const t = this.db.transaction("messages", "readwrite");
        const store = t.objectStore("messages");
        const getReq = store.get(id);
        getReq.onsuccess = () => {
          const row = getReq.result;
          if (!row) return;
          row.pinned = pinned;
          store.put(row);
        };
        getReq.onerror = () => reject(getReq.error);
        t.oncomplete = () => resolve();
        t.onerror = () => reject(t.error);
      });
    }

    // "Clear chat" — wipes this contact's message history but keeps the
    // contact and its session, so the chat is simply empty afterward
    // rather than gone. See deleteContact for the more destructive
    // "delete chat" operation.
    async clearMessages(fingerprint) {
      return new Promise((resolve, reject) => {
        const t = this.db.transaction("messages", "readwrite");
        const req = t.objectStore("messages").index("fingerprint").openCursor(IDBKeyRange.only(fingerprint));
        req.onsuccess = () => {
          const cursor = req.result;
          if (!cursor) return;
          cursor.delete();
          cursor.continue();
        };
        req.onerror = () => reject(req.error);
        t.oncomplete = () => resolve();
        t.onerror = () => reject(t.error);
      });
    }

    // "Delete chat" — this is a local, per-device operation (same as
    // every other privacy setting here): it forgets the contact and its
    // session on this device only, it does not notify them or affect
    // their copy of the conversation. If they message you again, a new
    // session simply gets re-established and they reappear as a contact.
    async deleteContact(fingerprint) {
      await this.clearMessages(fingerprint);
      await tx(this.db, "contacts", "readwrite", (store) => store.delete(fingerprint));
      await tx(this.db, "sessions", "readwrite", (store) => store.delete(fingerprint));
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
      const req = await tx(this.db, "groupMessages", "readwrite", (store) =>
        store.add({ groupId, senderIdentityPubHex, kind, blobHex: H.bytesToHex(blob), timestamp, pinned: false })
      );
      return req.result;
    }

    async groupHistory(groupId) {
      const t = this.db.transaction("groupMessages", "readonly");
      const index = t.objectStore("groupMessages").index("groupId");
      const rows = await reqToPromise(index.getAll(groupId));
      const out = [];
      for (const row of rows) {
        const plaintext = await H.decryptAuthenticated(this.storageKey, H.hexToBytes(row.blobHex), H.utf8(groupId));
        out.push({
          id: row.id,
          senderIdentityPubHex: row.senderIdentityPubHex,
          kind: row.kind,
          text: H.fromUtf8(plaintext),
          ts: row.timestamp,
          pinned: !!row.pinned,
        });
      }
      return out;
    }

    async setGroupMessagePinned(id, pinned) {
      return new Promise((resolve, reject) => {
        const t = this.db.transaction("groupMessages", "readwrite");
        const store = t.objectStore("groupMessages");
        const getReq = store.get(id);
        getReq.onsuccess = () => {
          const row = getReq.result;
          if (!row) return;
          row.pinned = pinned;
          store.put(row);
        };
        getReq.onerror = () => reject(getReq.error);
        t.oncomplete = () => resolve();
        t.onerror = () => reject(t.error);
      });
    }

    async clearGroupMessages(groupId) {
      return new Promise((resolve, reject) => {
        const t = this.db.transaction("groupMessages", "readwrite");
        const req = t.objectStore("groupMessages").index("groupId").openCursor(IDBKeyRange.only(groupId));
        req.onsuccess = () => {
          const cursor = req.result;
          if (!cursor) return;
          cursor.delete();
          cursor.continue();
        };
        req.onerror = () => reject(req.error);
        t.oncomplete = () => resolve();
        t.onerror = () => reject(t.error);
      });
    }

    // Local-only, same as deleteContact: forgets this group's messages
    // and membership state on this device without notifying anyone.
    async deleteGroup(groupId) {
      await this.clearGroupMessages(groupId);
      await tx(this.db, "groups", "readwrite", (store) => store.delete(groupId));
    }
  }

  return { Store };
})();
