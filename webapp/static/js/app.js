/**
 * Haven web client UI glue — see webapp/README.md for what's still not
 * built (calls and on-device AI in-browser; groups, attachments, and
 * emoji are now implemented, see groups.js/attachments.js).
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
    groupManager: null,
    peers: new Map(), // fingerprint -> {username, identityPubHex}
    openFingerprint: null,
    openGroupId: null,
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

  function openForgotPassword() {
    el("forgot-password-row").hidden = false;
    el("recovery-phrase-input").value = "";
    el("new-password-input").value = "";
    el("recovery-phrase-input").focus();
  }

  async function doResetPassword() {
    const username = el("username").value.trim();
    const recoveryPhrase = el("recovery-phrase-input").value.trim();
    const newPassword = el("new-password-input").value;
    const accountsUrl = el("accounts-url").value.trim() || defaultAccountsUrl();
    if (!username || !recoveryPhrase || !newPassword) {
      return setStatus("Enter your username above, plus your recovery phrase and a new password.");
    }
    state.accountsClient = new HavenAuth.AccountsClient(accountsUrl);
    try {
      const { identity } = await state.accountsClient.resetPassword(username, recoveryPhrase, newPassword);
      el("forgot-password-row").hidden = true;
      setStatus("");
      await onLoggedIn(identity, username);
    } catch (e) {
      console.error("password reset failed:", e);
      setStatus(e.message);
    }
  }

  function openRestoreBackup() {
    el("restore-backup-row").hidden = false;
    el("restore-backup-file").value = "";
    el("restore-backup-password").value = "";
  }

  async function doRestoreBackup() {
    const fileInput = el("restore-backup-file");
    const password = el("restore-backup-password").value;
    if (!fileInput.files.length || !password) {
      return setStatus("Choose a backup file and enter its password.");
    }
    try {
      const fileBytes = new Uint8Array(await fileInput.files[0].arrayBuffer());
      const bundle = await HavenBackup.restoreBackup(fileBytes, password);
      const identity = await H.keyPairFromPrivateBytes(H.hexToBytes(bundle.identity_private_key));
      const store = await HavenStorage.Store.open(bundle.username, identity.privateBytes);
      for (const c of bundle.contacts) {
        await store.upsertContact(c.fingerprint, c.username, c.identity_pub, c.verified);
      }
      for (const m of bundle.messages) {
        await store.saveMessage(m.fingerprint, m.direction, m.text, m.kind, m.ts);
      }
      el("restore-backup-row").hidden = true;
      setStatus("");
      await onLoggedIn(identity, bundle.username);
    } catch (e) {
      console.error("restore backup failed:", e);
      setStatus(e.message);
    }
  }

  function openBackup() {
    el("backup-row").hidden = false;
    el("backup-password").value = "";
  }

  async function doBackup() {
    const password = el("backup-password").value;
    if (!password) return;
    try {
      const bytes = await HavenBackup.exportBackup(state.identity, state.username, state.store, password);
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${state.username}.havenbackup`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      el("backup-row").hidden = true;
    } catch (e) {
      console.error("backup export failed:", e);
      appendLine("sys", "Backup failed: " + e.message);
    }
  }

  async function onLoggedIn(identity, username) {
    state.identity = identity;
    state.username = username;
    state.store = await HavenStorage.Store.open(username, identity.privateBytes);
    state.net = new HavenNetwork.NetworkManager(identity, username, state.store);
    state.groupManager = await HavenGroups.GroupManager.create(state.net, state.store, identity, username);
    state.groupManager.onGroupMessage = (groupId, senderUsername, text, kind) => {
      if (state.openGroupId === groupId) {
        appendLine(senderUsername === state.username ? "me" : "them", text, kind, senderUsername);
      }
      refreshPeerList();
    };
    state.groupManager.onGroupUpdate = (groupId) => {
      refreshPeerList();
      if (state.openGroupId === groupId) renderGroupHeader(groupId);
    };
    state.net.onMessage = (fp, kind, text, senderPubHex) => {
      if (kind === "group") {
        state.groupManager.handleIncoming(senderPubHex, text);
        return;
      }
      if (fp === state.openFingerprint) appendLine("them", text, kind);
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
    if (state.groupManager) {
      for (const g of state.groupManager.listGroups()) {
        const li = document.createElement("li");
        li.textContent = `👥 ${g.name}${g.removed ? " (removed)" : ""}`;
        li.className = g.groupId === state.openGroupId ? "selected" : "";
        li.onclick = () => openGroup(g.groupId);
        list.appendChild(li);
      }
    }
  }

  function renderGroupHeader(groupId) {
    const g = state.groupManager.listGroups().find((x) => x.groupId === groupId);
    if (!g) return;
    el("chat-title").textContent = g.name + (g.removed ? " (you were removed)" : "");
    el("group-controls").hidden = false;
    const label = el("group-members-label");
    label.textContent = "";
    label.appendChild(document.createTextNode("Members: "));
    for (const [pubHex, uname] of g.members) {
      const chip = document.createElement("span");
      chip.style.marginRight = "8px";
      if (pubHex === state.groupManager.myPubHex) {
        chip.textContent = uname + " (you)";
      } else {
        chip.textContent = uname + " ";
        const removeLink = document.createElement("a");
        removeLink.href = "#";
        removeLink.textContent = "[remove]";
        removeLink.onclick = async (e) => {
          e.preventDefault();
          await state.groupManager.removeMember(groupId, pubHex);
        };
        chip.appendChild(removeLink);
      }
      label.appendChild(chip);
    }
  }

  function openNewGroup() {
    const list = el("new-group-members");
    list.innerHTML = "";
    for (const meta of state.peers.values()) {
      const label = document.createElement("label");
      label.style.display = "block";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = meta.identityPubHex;
      cb.dataset.username = meta.username;
      label.appendChild(cb);
      label.appendChild(document.createTextNode(" " + meta.username));
      list.appendChild(label);
    }
    el("new-group-name").value = "";
    el("new-group-row").hidden = false;
  }

  async function confirmNewGroup() {
    const name = el("new-group-name").value.trim();
    const checked = Array.from(el("new-group-members").querySelectorAll("input:checked"));
    if (!name || checked.length === 0) {
      return alert("Enter a group name and pick at least one member.");
    }
    const members = checked.map((cb) => ({ username: cb.dataset.username, identityPubHex: cb.value }));
    el("new-group-row").hidden = true;
    const groupId = await state.groupManager.createGroup(name, members);
    refreshPeerList();
    await openGroup(groupId);
  }

  function openGroupAddMember() {
    const g = state.groupManager.listGroups().find((x) => x.groupId === state.openGroupId);
    if (!g) return;
    const list = el("group-add-member-list");
    list.innerHTML = "";
    for (const meta of state.peers.values()) {
      if (g.members.has(meta.identityPubHex)) continue;
      const label = document.createElement("label");
      label.style.display = "block";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = meta.identityPubHex;
      cb.dataset.username = meta.username;
      label.appendChild(cb);
      label.appendChild(document.createTextNode(" " + meta.username));
      list.appendChild(label);
    }
    el("group-add-member-row").hidden = false;
  }

  async function confirmGroupAddMember() {
    const checked = Array.from(el("group-add-member-list").querySelectorAll("input:checked"));
    el("group-add-member-row").hidden = true;
    for (const cb of checked) {
      await state.groupManager.addMember(state.openGroupId, cb.dataset.username, cb.value);
    }
  }

  async function openGroup(groupId) {
    state.openGroupId = groupId;
    state.openFingerprint = null;
    el("safety-number").textContent = "";
    el("verify-btn").hidden = true;
    el("group-add-member-row").hidden = true;
    refreshPeerList();
    renderGroupHeader(groupId);

    const g = state.groupManager.listGroups().find((x) => x.groupId === groupId);
    const messages = el("messages");
    messages.innerHTML = "";
    for (const m of await state.groupManager.groupHistory(groupId)) {
      const isMe = m.senderIdentityPubHex === state.groupManager.myPubHex;
      const senderLabel = isMe ? null : g.members.get(m.senderIdentityPubHex) || "unknown";
      appendLine(isMe ? "me" : "them", m.text, m.kind, senderLabel);
    }
  }

  async function openChat(fingerprint) {
    state.openFingerprint = fingerprint;
    state.openGroupId = null;
    el("group-controls").hidden = true;
    el("group-add-member-row").hidden = true;
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
      appendLine(m.direction === "out" ? "me" : "them", m.text, m.kind);
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

  function appendLine(who, text, kind = "text", senderLabel = null) {
    const div = document.createElement("div");
    div.className = "msg " + who;
    const prefix = who === "me" ? "you: " : who === "them" ? (senderLabel ? senderLabel + ": " : "") : "* ";
    if (kind === "text") {
      div.textContent = prefix + text;
    } else {
      try {
        const payload = HavenAttachments.decodeAttachment(text);
        if (prefix) div.appendChild(document.createTextNode(prefix));
        let media;
        if (kind === "image" || kind === "gif") {
          media = document.createElement("img");
          media.src = HavenAttachments.attachmentDataUrl(text);
          media.alt = payload.filename;
        } else if (kind === "audio") {
          media = document.createElement("audio");
          media.controls = true;
          media.src = HavenAttachments.attachmentDataUrl(text);
        } else if (kind === "video") {
          media = document.createElement("video");
          media.controls = true;
          media.src = HavenAttachments.attachmentDataUrl(text);
        } else {
          const blob = new Blob([payload.data], { type: payload.mime });
          media = document.createElement("a");
          media.href = URL.createObjectURL(blob);
          media.download = payload.filename;
          media.textContent = "Download " + payload.filename;
        }
        div.appendChild(media);
      } catch (e) {
        div.textContent = prefix + "[unreadable attachment]";
      }
    }
    el("messages").appendChild(div);
    el("messages").scrollTop = el("messages").scrollHeight;
  }

  async function ensureConnected(fingerprint) {
    if (state.net.isConnected(fingerprint)) return true;
    const meta = state.peers.get(fingerprint);
    try {
      await state.net.connectRelay(H.hexToBytes(meta.identityPubHex), meta.username);
    } catch (e) {
      console.error("connectRelay failed:", e);
      appendLine("sys", "Not connected: " + e.message);
      return false;
    }
    // give the handshake a moment; a production UI would queue-and-retry
    // (see the desktop app's pending_sends) rather than a fixed wait
    await new Promise((r) => setTimeout(r, 500));
    return true;
  }

  async function sendMessage() {
    const text = el("message-input").value.trim();
    if (!text || (!state.openFingerprint && !state.openGroupId)) return;
    el("message-input").value = "";
    if (state.openGroupId) {
      await state.groupManager.sendGroupMessage(state.openGroupId, text);
      appendLine("me", text);
      return;
    }
    if (!(await ensureConnected(state.openFingerprint))) return;
    try {
      await state.net.sendText(state.openFingerprint, text);
      appendLine("me", text);
    } catch (e) {
      console.error("sendText failed:", e);
      appendLine("sys", "Send failed: " + e.message);
    }
  }

  async function sendAttachment(file) {
    if (!state.openFingerprint && !state.openGroupId) return;
    let envelope, kind;
    try {
      envelope = await HavenAttachments.encodeAttachment(file);
      kind = HavenAttachments.guessKind(file);
    } catch (e) {
      appendLine("sys", "Attachment failed: " + e.message);
      return;
    }
    if (state.openGroupId) {
      await state.groupManager.sendGroupMessage(state.openGroupId, envelope, kind);
      appendLine("me", envelope, kind);
      return;
    }
    if (!(await ensureConnected(state.openFingerprint))) return;
    try {
      await state.net.sendText(state.openFingerprint, envelope, kind);
      appendLine("me", envelope, kind);
    } catch (e) {
      console.error("sendAttachment failed:", e);
      appendLine("sys", "Send failed: " + e.message);
    }
  }

  const EMOJI_LIST = [
    "😀", "😂", "😅", "😊", "🙂", "😉", "😍", "😘", "😜", "🤔",
    "😎", "🥳", "😢", "😭", "😡", "😱", "😴", "🤗", "😇", "🙄",
    "👍", "👎", "👏", "🙏", "💪", "🤝", "👋", "✌️", "🤞", "👀",
    "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "💔", "💯",
    "🎉", "🎂", "🔥", "✨", "⭐", "☕", "🍕", "🍔", "🍺", "🎁",
    "✅", "❌", "❓", "❗", "💤", "📎", "📷", "🎵", "🚀", "🌈",
  ];

  function toggleEmojiPicker() {
    const picker = el("emoji-picker");
    if (!picker.classList.contains("hide")) {
      picker.classList.add("hide");
      return;
    }
    picker.innerHTML = "";
    for (const emoji of EMOJI_LIST) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = emoji;
      btn.onclick = () => {
        el("message-input").value += emoji;
        el("message-input").focus();
      };
      picker.appendChild(btn);
    }
    picker.classList.remove("hide");
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
    el("forgot-password-link").onclick = (e) => {
      e.preventDefault();
      openForgotPassword();
    };
    el("forgot-password-cancel").onclick = () => (el("forgot-password-row").hidden = true);
    el("reset-password-btn").onclick = doResetPassword;
    el("restore-backup-link").onclick = (e) => {
      e.preventDefault();
      openRestoreBackup();
    };
    el("restore-backup-cancel").onclick = () => (el("restore-backup-row").hidden = true);
    el("restore-backup-confirm").onclick = doRestoreBackup;
    el("send-btn").onclick = sendMessage;
    el("message-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") sendMessage();
    });
    el("emoji-btn").onclick = toggleEmojiPicker;
    el("attach-btn").onclick = () => el("attach-file").click();
    el("attach-file").addEventListener("change", () => {
      const file = el("attach-file").files[0];
      el("attach-file").value = "";
      if (file) sendAttachment(file);
    });
    el("add-contact-btn").onclick = openAddContact;
    el("add-contact-confirm").onclick = confirmAddContact;
    el("add-contact-cancel").onclick = () => (el("add-contact-row").hidden = true);
    el("add-contact-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") confirmAddContact();
    });
    el("my-card-btn").onclick = toggleMyCard;
    el("backup-btn").onclick = openBackup;
    el("backup-cancel").onclick = () => (el("backup-row").hidden = true);
    el("backup-confirm").onclick = doBackup;
    el("new-group-btn").onclick = openNewGroup;
    el("new-group-cancel").onclick = () => (el("new-group-row").hidden = true);
    el("new-group-confirm").onclick = confirmNewGroup;
    el("group-add-member-btn").onclick = openGroupAddMember;
    el("group-add-member-cancel").onclick = () => (el("group-add-member-row").hidden = true);
    el("group-add-member-confirm").onclick = confirmGroupAddMember;
  });
})();
