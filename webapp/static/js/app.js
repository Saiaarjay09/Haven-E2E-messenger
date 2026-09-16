/**
 * Minimal Haven web client UI glue. Text chat only (Phase 7d MVP) —
 * see webapp/README.md for what's intentionally not built yet (groups,
 * calls, rich content, on-device AI in-browser).
 */

(() => {
  "use strict";
  const H = Haven;

  const state = {
    accountsClient: null,
    identity: null,
    username: null,
    net: null,
    store: null,
    relay: null,
    peers: new Map(), // fingerprint -> {username, identityPubHex}
    openFingerprint: null,
  };

  const el = (id) => document.getElementById(id);

  function defaultAccountsUrl() {
    return `${location.protocol}//${location.hostname}:8000`;
  }
  function defaultRelayWsUrl() {
    return `ws://${location.hostname}:8444`;
  }

  function showScreen(name) {
    el("login-screen").hidden = name !== "login";
    el("app-screen").hidden = name !== "app";
  }

  function setStatus(msg) {
    el("login-status").textContent = msg;
  }

  function showRecoveryPhrase(phrase) {
    return new Promise((resolve) => {
      el("recovery-phrase").textContent = phrase;
      el("recovery-overlay").classList.remove("hide");
      el("recovery-ack-btn").onclick = () => {
        el("recovery-overlay").classList.add("hide");
        resolve();
      };
    });
  }

  async function doSignup() {
    const username = el("username").value.trim();
    const password = el("password").value;
    const accountsUrl = el("accounts-url").value.trim() || defaultAccountsUrl();
    if (!username || !password) return setStatus("Enter a username and password.");
    state.accountsClient = new HavenAuth.AccountsClient(accountsUrl);
    try {
      const { identity, recoveryPhrase } = await state.accountsClient.signup(username, password);
      await showRecoveryPhrase(recoveryPhrase);
      await onLoggedIn(identity, username);
    } catch (e) {
      console.error("signup failed:", e);
      setStatus(e.message);
    }
  }

  async function doLogin() {
    const username = el("username").value.trim();
    const password = el("password").value;
    const accountsUrl = el("accounts-url").value.trim() || defaultAccountsUrl();
    if (!username || !password) return setStatus("Enter a username and password.");
    state.accountsClient = new HavenAuth.AccountsClient(accountsUrl);
    try {
      const { identity } = await state.accountsClient.login(username, password);
      await onLoggedIn(identity, username);
    } catch (e) {
      console.error("login failed:", e);
      setStatus(e.message);
    }
  }

  async function onLoggedIn(identity, username) {
    state.identity = identity;
    state.username = username;
    state.store = await HavenStorage.Store.open(username, identity.privateBytes);
    state.net = new HavenNetwork.NetworkManager(identity, username, state.store);
    state.net.onMessage = (fp, kind, text) => {
      if (fp === state.openFingerprint && kind === "text") appendLine("them", text);
      refreshPeerList();
    };
    state.net.onConnect = (conn) => {
      state.peers.set(conn.fingerprint, { username: conn.username, identityPubHex: H.bytesToHex(conn.identityPub) });
      refreshPeerList();
    };
    state.net.onStatus = () => refreshPeerList();

    const relayWsUrl = el("relay-url").value.trim() || defaultRelayWsUrl();
    state.relay = new HavenNetwork.RelayClient(identity, username, relayWsUrl);
    state.net.attachRelay(state.relay);
    state.relay.onConnectionChange = (connected) => {
      el("relay-status").textContent = connected ? "Relay: connected" : "Relay: reconnecting…";
    };
    state.relay.start();

    for (const c of await state.store.listContacts()) {
      state.peers.set(c.fingerprint, { username: c.username, identityPubHex: c.identityPubHex });
    }
    refreshPeerList();
    showScreen("app");
    el("my-username").textContent = state.username;
  }

  function refreshPeerList() {
    const list = el("peer-list");
    list.innerHTML = "";
    for (const [fp, meta] of state.peers.entries()) {
      const li = document.createElement("li");
      const online = state.net.isConnected(fp);
      li.textContent = `${meta.username} (${online ? "online" : "offline"})`;
      li.dataset.fp = fp;
      li.className = fp === state.openFingerprint ? "selected" : "";
      li.onclick = () => openChat(fp);
      list.appendChild(li);
    }
  }

  async function openChat(fingerprint) {
    state.openFingerprint = fingerprint;
    const meta = state.peers.get(fingerprint);
    el("chat-title").textContent = meta ? meta.username : fingerprint;
    refreshPeerList();

    // The fingerprint IS the safety number (same value, same function, as
    // the desktop app — see haven/crypto.py's fingerprint()): read this
    // aloud to your contact over a call and confirm it matches exactly
    // what they see for you, the same trust-on-first-use model Signal uses.
    const contact = await state.store.getContact(fingerprint);
    el("safety-number").textContent = "Safety number: " + fingerprint + (contact && contact.verified ? "  ✓ verified" : "");
    el("verify-btn").hidden = false;
    el("verify-btn").onclick = async () => {
      if (confirm(`Safety number:\n\n${fingerprint}\n\nDoes this match what your contact sees for you?`)) {
        await state.store.setVerified(fingerprint, true);
        el("safety-number").textContent = "Safety number: " + fingerprint + "  ✓ verified";
      }
    };

    const messages = el("messages");
    messages.innerHTML = "";
    for (const m of await state.store.history(fingerprint)) {
      appendLine(m.direction === "out" ? "me" : "them", m.text);
    }
    if (!state.net.isConnected(fingerprint) && meta) {
      try {
        await state.net.connectRelay(H.hexToBytes(meta.identityPubHex), meta.username);
      } catch (e) {
        console.error("connectRelay failed:", e);
        appendLine("sys", "Could not reach relay: " + e.message);
      }
    }
  }

  function appendLine(who, text) {
    const div = document.createElement("div");
    div.className = "msg " + who;
    div.textContent = (who === "me" ? "you: " : who === "them" ? "" : "* ") + text;
    el("messages").appendChild(div);
    el("messages").scrollTop = el("messages").scrollHeight;
  }

  async function sendMessage() {
    const text = el("message-input").value.trim();
    if (!text || !state.openFingerprint) return;
    el("message-input").value = "";
    if (!state.net.isConnected(state.openFingerprint)) {
      const meta = state.peers.get(state.openFingerprint);
      try {
        await state.net.connectRelay(H.hexToBytes(meta.identityPubHex), meta.username);
      } catch (e) {
        console.error("connectRelay failed:", e);
        appendLine("sys", "Not connected: " + e.message);
        return;
      }
      // give the handshake a moment; a production UI would queue-and-retry
      // (see the desktop app's pending_sends) rather than a fixed wait
      await new Promise((r) => setTimeout(r, 500));
    }
    try {
      await state.net.sendText(state.openFingerprint, text);
      appendLine("me", text);
    } catch (e) {
      console.error("sendText failed:", e);
      appendLine("sys", "Send failed: " + e.message);
    }
  }

  function openAddContact() {
    el("add-contact-row").hidden = false;
    el("add-contact-input").value = "";
    el("add-contact-input").focus();
  }

  async function confirmAddContact() {
    const card = el("add-contact-input").value.trim();
    el("add-contact-row").hidden = true;
    if (!card) return;
    const parts = card.split(":");
    if (parts[0] !== "haven1" || parts.length < 3) {
      appendLine("sys", "Invalid contact card.");
      return;
    }
    const username = parts[1];
    const identityPubHex = parts[2];
    const identityPub = H.hexToBytes(identityPubHex);
    const fp = await H.fingerprint(state.identity.publicBytes, identityPub);
    await state.store.upsertContact(fp, username, identityPubHex);
    state.peers.set(fp, { username, identityPubHex });
    refreshPeerList();
  }

  function toggleMyCard() {
    const row = el("my-card-row");
    if (row.hidden) {
      row.hidden = false;
      el("my-card-display").value = `haven1:${state.username}:${H.bytesToHex(state.identity.publicBytes)}`;
      el("my-card-display").select();
    } else {
      row.hidden = true;
    }
  }

  window.addEventListener("DOMContentLoaded", () => {
    el("accounts-url").placeholder = defaultAccountsUrl();
    el("relay-url").placeholder = defaultRelayWsUrl();
    el("signup-btn").onclick = doSignup;
    el("login-btn").onclick = doLogin;
    el("send-btn").onclick = sendMessage;
    el("message-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") sendMessage();
    });
    el("add-contact-btn").onclick = openAddContact;
    el("add-contact-confirm").onclick = confirmAddContact;
    el("add-contact-cancel").onclick = () => (el("add-contact-row").hidden = true);
    el("add-contact-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") confirmAddContact();
    });
    el("my-card-btn").onclick = toggleMyCard;
  });
})();
