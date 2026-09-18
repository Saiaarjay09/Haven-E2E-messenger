/**
 * Sender-keys style group messaging — the browser port of
 * haven/groups.py, ported as directly as the web client's relay-only
 * networking allows (no direct-LAN route resolution exists here, so
 * every send just goes through the relay). Group control messages
 * (invite, sender-key distribution, membership changes) and group chat
 * messages both ride as ordinary end-to-end encrypted 1:1 messages
 * between members (kind="group", a JSON payload as the text) — no
 * separate transport, and the relay never sees a decrypted group
 * message any more than it sees a decrypted 1:1 one.
 *
 * Sender keys: each member keeps one outgoing symmetric chain
 * (Haven.SenderKeyChain) used for everything THEY send to the group,
 * and one copy of every OTHER member's chain to decrypt what that
 * member sends — the same design Signal/WhatsApp use for groups.
 * Removing a member rotates your own chain (redistributed only to the
 * remaining members) so they can't keep reading forward using their
 * last-known copy of it. See groups.py's own module docstring for the
 * full rationale; this file mirrors it exactly.
 */

const HavenGroups = (() => {
  "use strict";
  const H = Haven;

  class GroupManager {
    constructor(net, store, identity, username) {
      this.net = net;
      this.store = store;
      this.identity = identity;
      this.username = username;
      this.myPubHex = H.bytesToHex(identity.publicBytes);

      this.onGroupMessage = null; // (groupId, senderUsername, text, kind, senderIdentityPubHex, id) => void — id is the local storage row id, or undefined for a GROUP_NON_MESSAGE_KINDS control frame
      this.onGroupUpdate = null; // (groupId) => void

      this.groups = new Map(); // groupId -> { name, members: Map(pubHex->username), myChain, peerChains: Map(pubHex->chain), removed }
    }

    static async create(net, store, identity, username) {
      const gm = new GroupManager(net, store, identity, username);
      const groupIds = (await store.listGroups()).map((g) => g.groupId);
      // Each loadGroup() is an independent IndexedDB round-trip — firing
      // them all at once instead of one-at-a-time is the difference
      // between O(groups) and O(1) round-trips on login for anyone in
      // more than a couple of groups.
      const loaded = await Promise.all(groupIds.map((groupId) => store.loadGroup(groupId)));
      for (let i = 0; i < groupIds.length; i++) {
        const groupId = groupIds[i];
        const g = loaded[i];
        if (!g) continue;
        gm.groups.set(groupId, {
          name: g.name,
          members: new Map(Object.entries(g.state.members)),
          myChain: new H.SenderKeyChain(H.hexToBytes(g.state.myChain.chainKey), g.state.myChain.index),
          peerChains: new Map(
            Object.entries(g.state.peerChains).map(([pubHex, c]) => [
              pubHex,
              new H.SenderKeyChain(H.hexToBytes(c.chainKey), c.index),
            ])
          ),
          removed: g.state.removed || false,
        });
      }
      return gm;
    }

    // -- public API ---------------------------------------------------------

    async createGroup(name, members) {
      // members: [{username, identityPubHex}]
      const groupId = H.bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
      const fullMembers = new Map([[this.myPubHex, this.username]]);
      for (const m of members) fullMembers.set(m.identityPubHex, m.username);
      const myChain = new H.SenderKeyChain(crypto.getRandomValues(new Uint8Array(32)));
      const g = { name, members: fullMembers, myChain, peerChains: new Map(), removed: false };
      this.groups.set(groupId, g);
      await this._persist(groupId);
      this._notifyUpdate(groupId);

      const membersPayload = Array.from(fullMembers.entries()).map(([p, u]) => ({ username: u, identity_pub: p }));
      for (const m of members) {
        await this._sendControl(m.identityPubHex, m.username, {
          type: "group_invite",
          group_id: groupId,
          name,
          members: membersPayload,
          sender_key: { chain_key: H.bytesToHex(myChain.chainKey), index: myChain.index },
        });
      }
      return groupId;
    }

    async addMember(groupId, username, identityPubHex) {
      const g = this._requireGroup(groupId);
      g.members.set(identityPubHex, username);
      await this._persist(groupId);
      this._notifyUpdate(groupId);

      const membersPayload = Array.from(g.members.entries()).map(([p, u]) => ({ username: u, identity_pub: p }));
      await this._sendControl(identityPubHex, username, {
        type: "group_invite",
        group_id: groupId,
        name: g.name,
        members: membersPayload,
        sender_key: { chain_key: H.bytesToHex(g.myChain.chainKey), index: g.myChain.index },
      });
      for (const [otherPubHex, otherUname] of g.members) {
        if (otherPubHex === this.myPubHex || otherPubHex === identityPubHex) continue;
        await this._sendControl(otherPubHex, otherUname, {
          type: "group_member_add",
          group_id: groupId,
          member: { username, identity_pub: identityPubHex },
        });
      }
    }

    async removeMember(groupId, identityPubHex) {
      const g = this._requireGroup(groupId);
      const removedUsername = g.members.get(identityPubHex);
      g.members.delete(identityPubHex);
      g.peerChains.delete(identityPubHex);
      g.myChain = new H.SenderKeyChain(crypto.getRandomValues(new Uint8Array(32))); // rotate: see module docstring
      await this._persist(groupId);
      this._notifyUpdate(groupId);

      if (removedUsername !== undefined) {
        await this._sendControl(identityPubHex, removedUsername, {
          type: "group_member_remove",
          group_id: groupId,
          member_identity_pub: identityPubHex,
        });
      }
      for (const [otherPubHex, otherUname] of g.members) {
        if (otherPubHex === this.myPubHex) continue;
        await this._sendControl(otherPubHex, otherUname, {
          type: "group_member_remove",
          group_id: groupId,
          member_identity_pub: identityPubHex,
        });
        await this._sendControl(otherPubHex, otherUname, {
          type: "group_sender_key",
          group_id: groupId,
          chain_key: H.bytesToHex(g.myChain.chainKey),
          index: g.myChain.index,
        });
      }
    }

    // GROUP_NON_MESSAGE_KINDS mirrors network.js's NON_MESSAGE_KINDS for
    // the 1:1 channel — control/transient traffic riding the group
    // channel that shouldn't be persisted as a chat message.
    static GROUP_NON_MESSAGE_KINDS = new Set(["group_call", "typing"]);

    // Returns the saved message's local id (see storage.js's
    // saveGroupMessage), or undefined for a GROUP_NON_MESSAGE_KINDS
    // control frame that was never persisted.
    async sendGroupMessage(groupId, text, kind = "text") {
      const g = this._requireGroup(groupId);
      const envelope = await g.myChain.encrypt(H.utf8(text), H.utf8(groupId));
      await this._persist(groupId);
      const persist = !GroupManager.GROUP_NON_MESSAGE_KINDS.has(kind);
      const id = persist ? await this.store.saveGroupMessage(groupId, this.myPubHex, text, kind) : undefined;

      const payloadJson = JSON.stringify({
        type: "group_msg",
        group_id: groupId,
        kind,
        envelope: { index: envelope.index, nonce: H.bytesToHex(envelope.nonce), ciphertext: H.bytesToHex(envelope.ciphertext) },
      });
      for (const [pubHex, uname] of g.members) {
        if (pubHex === this.myPubHex) continue;
        await this._sendRaw(pubHex, uname, payloadJson);
      }
      return id;
    }

    // Local-only: forgets this group on this device without notifying
    // anyone (see storage.js's deleteGroup for why — same "delete chat"
    // semantics as a 1:1 contact).
    async forgetGroup(groupId) {
      this.groups.delete(groupId);
      await this.store.deleteGroup(groupId);
    }

    listGroups() {
      return Array.from(this.groups.entries()).map(([groupId, g]) => ({
        groupId,
        name: g.name,
        members: g.members,
        removed: g.removed,
      }));
    }

    async groupHistory(groupId) {
      return this.store.groupHistory(groupId);
    }

    // -- inbound control-message handling ------------------------------------

    async handleIncoming(senderIdentityPubHex, text) {
      let payload;
      try {
        payload = JSON.parse(text);
      } catch (e) {
        return; // malformed control frame — drop it rather than crash
      }
      try {
        if (payload.type === "group_invite") await this._onInvite(senderIdentityPubHex, payload);
        else if (payload.type === "group_sender_key") await this._onSenderKey(senderIdentityPubHex, payload);
        else if (payload.type === "group_msg") await this._onGroupMsg(senderIdentityPubHex, payload);
        else if (payload.type === "group_member_add") await this._onMemberAdd(payload);
        else if (payload.type === "group_member_remove") await this._onMemberRemove(payload);
      } catch (e) {
        console.error("malformed group control frame, dropped:", e);
      }
    }

    async _onInvite(senderIdentityPubHex, payload) {
      const groupId = payload.group_id;
      const members = new Map(payload.members.map((m) => [m.identity_pub, m.username]));
      if (!members.has(this.myPubHex)) return;
      const sk = payload.sender_key;
      const senderChain = new H.SenderKeyChain(H.hexToBytes(sk.chain_key), sk.index || 0);

      let g = this.groups.get(groupId);
      if (!g) {
        const myChain = new H.SenderKeyChain(crypto.getRandomValues(new Uint8Array(32)));
        g = { name: payload.name, members, myChain, peerChains: new Map([[senderIdentityPubHex, senderChain]]), removed: false };
        this.groups.set(groupId, g);
        await this._persist(groupId);
        this._notifyUpdate(groupId);
        // newly joining: hand our sender key to everyone else so they can receive from us too
        for (const [pubHex, uname] of members) {
          if (pubHex === this.myPubHex) continue;
          await this._sendControl(pubHex, uname, {
            type: "group_sender_key",
            group_id: groupId,
            chain_key: H.bytesToHex(myChain.chainKey),
            index: myChain.index,
          });
        }
      } else {
        for (const [p, u] of members) g.members.set(p, u);
        g.peerChains.set(senderIdentityPubHex, senderChain);
        g.removed = false;
        await this._persist(groupId);
        this._notifyUpdate(groupId);
      }
    }

    async _onSenderKey(senderIdentityPubHex, payload) {
      const g = this.groups.get(payload.group_id);
      if (!g) return;
      g.peerChains.set(senderIdentityPubHex, new H.SenderKeyChain(H.hexToBytes(payload.chain_key), payload.index || 0));
      await this._persist(payload.group_id);
      this._notifyUpdate(payload.group_id);
    }

    async _onGroupMsg(senderIdentityPubHex, payload) {
      const groupId = payload.group_id;
      const g = this.groups.get(groupId);
      if (!g) return;
      const chain = g.peerChains.get(senderIdentityPubHex);
      if (!chain) return; // haven't received their sender key yet — drop (known limitation)
      const env = payload.envelope;
      const envelope = { index: env.index, nonce: H.hexToBytes(env.nonce), ciphertext: H.hexToBytes(env.ciphertext) };
      let plaintext;
      try {
        plaintext = H.fromUtf8(await chain.decrypt(envelope, H.utf8(groupId)));
      } catch (e) {
        return;
      }
      const kind = payload.kind || "text";
      await this._persist(groupId);
      // "group_call" is call signaling plus a stream of audio/video
      // chunks (up to ~10/sec), and "typing" a transient ping — neither
      // is something to persist as a group chat message, same reasoning
      // as 1:1 calls (see network.js).
      const persist = !GroupManager.GROUP_NON_MESSAGE_KINDS.has(kind);
      const id = persist ? await this.store.saveGroupMessage(groupId, senderIdentityPubHex, plaintext, kind) : undefined;
      if (this.onGroupMessage) {
        const username = g.members.get(senderIdentityPubHex) || senderIdentityPubHex.slice(0, 8);
        this.onGroupMessage(groupId, username, plaintext, kind, senderIdentityPubHex, id);
      }
    }

    async _onMemberAdd(payload) {
      const groupId = payload.group_id;
      const g = this.groups.get(groupId);
      if (!g) return;
      const member = payload.member;
      g.members.set(member.identity_pub, member.username);
      await this._persist(groupId);
      this._notifyUpdate(groupId);
      await this._sendControl(member.identity_pub, member.username, {
        type: "group_sender_key",
        group_id: groupId,
        chain_key: H.bytesToHex(g.myChain.chainKey),
        index: g.myChain.index,
      });
    }

    async _onMemberRemove(payload) {
      const groupId = payload.group_id;
      const g = this.groups.get(groupId);
      if (!g) return;
      const removedPubHex = payload.member_identity_pub;
      if (removedPubHex === this.myPubHex) {
        g.removed = true;
        await this._persist(groupId);
        this._notifyUpdate(groupId);
        return;
      }
      g.members.delete(removedPubHex);
      g.peerChains.delete(removedPubHex);
      await this._persist(groupId);
      this._notifyUpdate(groupId);
    }

    // -- helpers -------------------------------------------------------------

    _requireGroup(groupId) {
      const g = this.groups.get(groupId);
      if (!g) throw new Error(`unknown group ${groupId}`);
      return g;
    }

    async _persist(groupId) {
      const g = this.groups.get(groupId);
      const state = {
        members: Object.fromEntries(g.members),
        myChain: { chainKey: H.bytesToHex(g.myChain.chainKey), index: g.myChain.index },
        peerChains: Object.fromEntries(
          Array.from(g.peerChains.entries()).map(([p, c]) => [p, { chainKey: H.bytesToHex(c.chainKey), index: c.index }])
        ),
        removed: g.removed,
      };
      await this.store.saveGroup(groupId, g.name, state);
    }

    _notifyUpdate(groupId) {
      if (this.onGroupUpdate) this.onGroupUpdate(groupId);
    }

    async _sendControl(identityPubHex, usernameHint, payload) {
      await this._sendRaw(identityPubHex, usernameHint, JSON.stringify(payload));
    }

    async _sendRaw(identityPubHex, usernameHint, textJson) {
      const fp = await H.fingerprint(this.identity.publicBytes, H.hexToBytes(identityPubHex));
      if (!this.net.isConnected(fp)) {
        try {
          await this.net.connectRelay(H.hexToBytes(identityPubHex), usernameHint);
          await new Promise((r) => setTimeout(r, 500));
        } catch (e) {
          console.error("group: could not reach", usernameHint, e);
          return;
        }
      }
      try {
        await this.net.sendText(fp, textJson, "group");
      } catch (e) {
        console.error("group: send failed to", usernameHint, e);
      }
    }
  }

  return { GroupManager };
})();
