/**
 * Browser network layer — the WebSocket-only equivalent of
 * haven/network.py + haven/relay_client.py. A browser can't open raw
 * TCP/UDP sockets, so unlike the desktop app there is no direct-LAN
 * path here: every contact is reached through a relay (see Phase 7b's
 * WebSocket transport on the relay). Protocol is otherwise identical —
 * same register_init/challenge/register/registered handshake, same
 * hello/hello_ack/msg frame shapes — so a browser client and a desktop
 * client on the same relay can talk to each other.
 */

const HavenNetwork = (() => {
  "use strict";
  const H = Haven;

  class RelayClient {
    constructor(identity, username, wsUrl) {
      this.identity = identity;
      this.username = username;
      this.wsUrl = wsUrl;
      this.ws = null;
      this.connected = false;
      this.onDeliver = null; // (senderPubHex, payload) => void
      this.onConnectionChange = null; // (connected) => void
      this._backoff = 1000;
    }

    start() {
      this._connect();
    }

    _connect() {
      const ws = new WebSocket(this.wsUrl);
      this.ws = ws;
      ws.onopen = async () => {
        ws.send(
          JSON.stringify({
            type: "register_init",
            identity_pub: H.bytesToHex(this.identity.publicBytes),
            username: this.username,
          })
        );
      };
      ws.onmessage = async (event) => {
        const frame = JSON.parse(event.data);
        if (frame.type === "challenge") {
          const serverEphemeralPub = H.hexToBytes(frame.server_ephemeral_pub);
          const nonce = H.hexToBytes(frame.nonce);
          const proof = await H.dhProof(this.identity.privateKey, serverEphemeralPub, nonce);
          ws.send(JSON.stringify({ type: "register", proof }));
        } else if (frame.type === "registered") {
          this.connected = true;
          this._backoff = 1000;
          if (this.onConnectionChange) this.onConnectionChange(true);
        } else if (frame.type === "relay") {
          if (this.onDeliver) await this.onDeliver(frame.from, frame.payload);
          ws.send(JSON.stringify({ type: "ack", msg_id: frame.msg_id }));
        }
      };
      ws.onclose = () => {
        this.connected = false;
        if (this.onConnectionChange) this.onConnectionChange(false);
        setTimeout(() => this._connect(), this._backoff);
        this._backoff = Math.min(this._backoff * 2, 30000);
      };
      ws.onerror = () => ws.close();
    }

    sendTo(identityPubHex, payload) {
      if (!this.connected || this.ws.readyState !== WebSocket.OPEN) return false;
      this.ws.send(JSON.stringify({ type: "relay", to: identityPubHex, payload }));
      return true;
    }

    stop() {
      if (this.ws) {
        this.ws.onclose = null; // don't auto-reconnect after an intentional stop
        this.ws.close();
      }
    }
  }

  class NetworkManager {
    constructor(identity, username, store) {
      this.identity = identity;
      this.username = username;
      this.store = store;
      this.relay = null;
      this.connections = new Map(); // fingerprint -> {identityPubHex, username, session}
      this._pendingEphemeral = new Map(); // identityPubHex -> ephemeral keypair

      this.onMessage = null; // (fingerprint, kind, text, senderPubHex) => void
      this.onStatus = null; // (fingerprint, status) => void
      this.onConnect = null; // (conn) => void
    }

    attachRelay(relayClient) {
      this.relay = relayClient;
      this.relay.onDeliver = (senderPubHex, payload) => this._onRelayFrame(senderPubHex, payload);
    }

    isConnected(fingerprint) {
      return this.connections.has(fingerprint);
    }

    async connectRelay(identityPubBytes, usernameHint = "") {
      const identityPubHex = H.bytesToHex(identityPubBytes);
      const fp = await H.fingerprint(this.identity.publicBytes, identityPubBytes);
      if (this.connections.has(fp)) return fp;
      if (this._pendingEphemeral.has(identityPubHex)) return fp;

      const myEphemeral = await H.generateKeyPair();
      this._pendingEphemeral.set(identityPubHex, myEphemeral);
      const sent = this.relay.sendTo(identityPubHex, {
        type: "hello",
        username: this.username,
        identity_pub: H.bytesToHex(this.identity.publicBytes),
        ephemeral_pub: H.bytesToHex(myEphemeral.publicBytes),
      });
      if (!sent) {
        this._pendingEphemeral.delete(identityPubHex);
        throw new Error("relay is not currently connected");
      }
      return fp;
    }

    async _onRelayFrame(senderPubHex, payload) {
      const senderPub = H.hexToBytes(senderPubHex);
      try {
        if (payload.type === "hello") await this._handleHello(senderPub, payload);
        else if (payload.type === "hello_ack") await this._handleHelloAck(senderPub, payload);
        else if (payload.type === "msg") await this._handleMsg(senderPub, payload);
      } catch (e) {
        console.error("malformed relay frame, dropped:", e);
      }
    }

    async _deriveSession(isInitiator, myEphemeral, theirIdentityPub, theirEphemeralPub) {
      const rootKey = await H.computeSharedRootKey({
        isInitiator,
        myIdentity: this.identity,
        myEphemeral,
        theirIdentityPub,
        theirEphemeralPub,
      });
      const { send, recv } = await H.deriveChainKeys(rootKey, isInitiator);
      return new H.RatchetSession(send, recv);
    }

    async _handleHello(theirIdentityPub, hello) {
      const theirEphemeralPub = H.hexToBytes(hello.ephemeral_pub);
      const myEphemeral = await H.generateKeyPair();
      const session = await this._deriveSession(false, myEphemeral, theirIdentityPub, theirEphemeralPub);
      const fp = await H.fingerprint(this.identity.publicBytes, theirIdentityPub);
      const conn = { fingerprint: fp, username: hello.username, identityPub: theirIdentityPub, session };
      await this._registerConnection(conn);
      this.relay.sendTo(H.bytesToHex(theirIdentityPub), {
        type: "hello_ack",
        username: this.username,
        identity_pub: H.bytesToHex(this.identity.publicBytes),
        ephemeral_pub: H.bytesToHex(myEphemeral.publicBytes),
      });
    }

    async _handleHelloAck(theirIdentityPub, ack) {
      const identityPubHex = H.bytesToHex(theirIdentityPub);
      const myEphemeral = this._pendingEphemeral.get(identityPubHex);
      if (!myEphemeral) return; // unexpected/duplicate ack
      this._pendingEphemeral.delete(identityPubHex);
      const theirEphemeralPub = H.hexToBytes(ack.ephemeral_pub);
      const session = await this._deriveSession(true, myEphemeral, theirIdentityPub, theirEphemeralPub);
      const fp = await H.fingerprint(this.identity.publicBytes, theirIdentityPub);
      const conn = { fingerprint: fp, username: ack.username, identityPub: theirIdentityPub, session };
      await this._registerConnection(conn);
    }

    async _registerConnection(conn) {
      this.connections.set(conn.fingerprint, conn);
      await this.store.upsertContact(conn.fingerprint, conn.username, H.bytesToHex(conn.identityPub));
      if (this.onConnect) this.onConnect(conn);
      if (this.onStatus) this.onStatus(conn.fingerprint, "connected");
    }

    async _handleMsg(senderIdentityPub, frame) {
      const fp = await H.fingerprint(this.identity.publicBytes, senderIdentityPub);
      const conn = this.connections.get(fp);
      if (!conn) return; // message for a session we don't have — drop it
      const envelope = { index: frame.index, nonce: H.hexToBytes(frame.nonce), ciphertext: H.hexToBytes(frame.ciphertext) };
      const plaintext = await conn.session.decrypt(envelope, conn.identityPub);
      await this.store.saveSession(fp, conn.session);
      const kind = frame.kind || "text";
      const text = H.fromUtf8(plaintext);
      await this.store.saveMessage(fp, "in", text, kind);
      if (this.onMessage) this.onMessage(fp, kind, text, H.bytesToHex(senderIdentityPub));
    }

    async sendText(fingerprint, text, kind = "text") {
      const conn = this.connections.get(fingerprint);
      if (!conn) throw new Error("not connected to this peer");
      const envelope = await conn.session.encrypt(H.utf8(text), this.identity.publicBytes);
      await this.store.saveSession(fingerprint, conn.session);
      this.relay.sendTo(H.bytesToHex(conn.identityPub), {
        type: "msg",
        index: envelope.index,
        nonce: H.bytesToHex(envelope.nonce),
        ciphertext: H.bytesToHex(envelope.ciphertext),
        kind,
      });
      await this.store.saveMessage(fingerprint, "out", text, kind);
    }
  }

  return { RelayClient, NetworkManager };
})();
