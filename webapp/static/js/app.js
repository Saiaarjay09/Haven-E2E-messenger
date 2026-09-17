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
    callManager: null,
    peers: new Map(), // fingerprint -> {username, identityPubHex}
    openFingerprint: null,
    openGroupId: null,
  };

  const el = (id) => document.getElementById(id);

  // Hardcoded to this specific deployment (Tailscale Funnel, see
  // WEB_DEPLOYMENT.md Option C1) rather than derived from location.* —
  // this app is only ever used by one small group on one fixed host, so
  // asking every signup/login to manually paste two URLs was pure
  // friction with no actual flexibility being used. If this ever moves
  // to a different host, update these two lines (and CURRENT_LINKS.md).
  function defaultAccountsUrl() {
    return "https://haven.taila6d3cb.ts.net:8443";
  }
  function defaultRelayWsUrl() {
    return "wss://haven.taila6d3cb.ts.net:10000";
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
    const accountsUrl = defaultAccountsUrl();
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
    const accountsUrl = defaultAccountsUrl();
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
    const accountsUrl = defaultAccountsUrl();
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
    state.groupManager.onGroupMessage = (groupId, senderUsername, text, kind, senderPubHex) => {
      if (kind === "group_call") {
        state.groupCallManager.handleIncoming(groupId, senderPubHex, senderUsername, text);
        return;
      }
      if (state.openGroupId === groupId) {
        appendLine(senderUsername === state.username ? "me" : "them", text, kind, senderUsername);
      }
      refreshPeerList();
    };
    state.groupManager.onGroupUpdate = (groupId) => {
      refreshPeerList();
      if (state.openGroupId === groupId) renderGroupHeader(groupId);
    };
    state.groupCallManager = new HavenGroupCalls.GroupCallManager(state.groupManager);
    state.groupCallManager.onIncomingGroupCall = (groupId, fromUsername, hasVideo) => {
      if (groupId !== state.openGroupId) return; // known limitation: same as 1:1 calls, only surfaces for the open chat
      el("incoming-group-call-text").textContent = `📞 ${fromUsername} started a${hasVideo ? " video" : ""} group call`;
      el("incoming-group-call-banner").classList.remove("hide");
    };
    state.groupCallManager.onCallState = (groupId, callState) => {
      if (groupId !== state.openGroupId) return;
      updateGroupCallUI(callState);
    };
    state.groupCallManager.onParticipantsChanged = (groupId) => {
      if (groupId === state.openGroupId) renderGroupCallParticipants(groupId);
    };
    state.groupCallManager.onCallError = (groupId, message) => {
      if (groupId === state.openGroupId) appendLine("sys", "Group call error: " + message);
    };
    state.callManager = new HavenCalls.CallManager(state.net, identity, username);
    state.callManager.onIncomingCall = (fp, callId, hasVideo) => {
      if (fp !== state.openFingerprint) return; // known limitation: calls only surface for the currently-open chat
      const meta = state.peers.get(fp);
      el("incoming-call-text").textContent = `📞 Incoming ${hasVideo ? "video " : ""}call from ${meta ? meta.username : fp}`;
      el("incoming-call-banner").classList.remove("hide");
    };
    state.callManager.onCallState = (fp, callState) => {
      if (fp !== state.openFingerprint) return;
      updateCallUI(callState);
    };
    state.callManager.onCallError = (fp, message) => {
      if (fp === state.openFingerprint) appendLine("sys", "Call error: " + message);
    };
    state.callManager.onRemoteVideoFrame = (fp, url) => {
      if (fp !== state.openFingerprint) return;
      const img = el("remote-video-display");
      if (img.dataset.prevUrl) URL.revokeObjectURL(img.dataset.prevUrl);
      img.src = url;
      img.dataset.prevUrl = url;
      img.hidden = false;
    };
    state.callManager.onLocalVideoFrame = (fp, url) => {
      if (fp !== state.openFingerprint) return;
      const img = el("local-video-preview");
      if (img.dataset.prevUrl) URL.revokeObjectURL(img.dataset.prevUrl);
      img.src = url;
      img.dataset.prevUrl = url;
      img.hidden = false;
    };
    state.net.onMessage = (fp, kind, text, senderPubHex) => {
      if (kind === "group") {
        state.groupManager.handleIncoming(senderPubHex, text);
        return;
      }
      if (kind === "call") {
        state.callManager.handleIncoming(fp, text);
        return;
      }
      if (kind === "avatar") {
        handleIncomingAvatar(fp, text);
        return;
      }
      if (fp === state.openFingerprint) appendLine("them", text, kind);
      refreshPeerList();
    };
    state.net.onConnect = (conn) => {
      const fp = conn.fingerprint;
      const existing = state.peers.get(fp);
      state.peers.set(fp, {
        username: conn.username,
        identityPubHex: H.bytesToHex(conn.identityPub),
        avatarDataUrl: existing ? existing.avatarDataUrl : undefined,
      });
      refreshPeerList();
      if (fp === state.openFingerprint) renderChatHeaderAvatar(fp);
      sendMyAvatarTo(fp).catch((e) => console.error("send avatar failed:", e));
    };
    state.net.onStatus = () => refreshPeerList();

    const relayWsUrl = defaultRelayWsUrl();
    state.relay = new HavenNetwork.RelayClient(identity, username, relayWsUrl);
    state.net.attachRelay(state.relay);
    state.relay.onConnectionChange = (connected) => {
      el("relay-status").textContent = connected ? "Relay: connected" : "Relay: reconnecting…";
    };
    state.relay.start();

    for (const c of await state.store.listContacts()) {
      state.peers.set(c.fingerprint, { username: c.username, identityPubHex: c.identityPubHex, avatarDataUrl: c.avatarDataUrl });
    }
    refreshPeerList();
    showScreen("app");
    el("my-username").textContent = state.username;
    saveSession(username, identity.privateBytes);
    renderMyAvatar();
  }

  // "Stay signed in" support: the decrypted identity key is cached in
  // this browser's localStorage so a reload or reopened tab skips the
  // login form entirely. This is a real, deliberate tradeoff, not an
  // oversight — the key already sits in JS memory for as long as the
  // tab is open, and webapp/README.md's whole premise is that this app
  // already trusts the code the server sends on every visit, so the
  // marginal new risk is narrower: anyone with local access to THIS
  // browser profile (not just a malicious server) can now also reach
  // the account without the password. "Log out" clears it for anyone
  // who wants that reduced on a shared/public computer.
  const SESSION_KEY = "haven-session";

  function saveSession(username, privateBytes) {
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify({ username, privateBytesHex: H.bytesToHex(privateBytes) }));
    } catch (e) {
      console.error("could not save session (private/incognito mode blocks this):", e);
    }
  }

  function loadSession() {
    try {
      const raw = localStorage.getItem(SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function clearSession() {
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch (e) {
      /* ignore */
    }
  }

  function doLogout() {
    clearSession();
    location.reload();
  }

  // Returns an <img class="avatar"> if we have one, otherwise a colored
  // circle with the first letter of the name — the common "no photo yet"
  // fallback every messaging app uses.
  function avatarElement(name, dataUrl) {
    if (dataUrl) {
      const img = document.createElement("img");
      img.className = "avatar";
      img.src = dataUrl;
      img.alt = name;
      return img;
    }
    const span = document.createElement("span");
    span.className = "avatar";
    span.textContent = (name || "?").charAt(0).toUpperCase();
    let hash = 0;
    for (const ch of name || "?") hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    span.style.background = `hsl(${hash % 360}, 45%, 55%)`;
    return span;
  }

  function refreshPeerList() {
    const list = el("peer-list");
    list.innerHTML = "";
    for (const [fp, meta] of state.peers.entries()) {
      const li = document.createElement("li");
      const online = state.net.isConnected(fp);
      li.appendChild(avatarElement(meta.username, meta.avatarDataUrl));
      li.appendChild(document.createTextNode(`${meta.username} (${online ? "online" : "offline"})`));
      li.dataset.fp = fp;
      li.className = fp === state.openFingerprint ? "selected" : "";
      li.onclick = () => openChat(fp);
      list.appendChild(li);
    }
    if (state.groupManager) {
      for (const g of state.groupManager.listGroups()) {
        const li = document.createElement("li");
        li.appendChild(avatarElement(g.name, null));
        li.appendChild(document.createTextNode(`${g.name}${g.removed ? " (removed)" : ""}`));
        li.className = g.groupId === state.openGroupId ? "selected" : "";
        li.onclick = () => openGroup(g.groupId);
        list.appendChild(li);
      }
    }
  }

  function renderChatHeaderAvatar(fingerprint) {
    const meta = state.peers.get(fingerprint);
    const holder = el("chat-title-avatar");
    holder.innerHTML = "";
    if (meta) holder.appendChild(avatarElement(meta.username, meta.avatarDataUrl));
  }

  function renderMyAvatar() {
    const dataUrl = loadMyAvatar();
    const img = el("my-avatar");
    if (dataUrl) {
      img.src = dataUrl;
      img.hidden = false;
    } else {
      img.hidden = true;
    }
  }

  function myAvatarKey() {
    return `haven-avatar:${state.username}`;
  }

  function loadMyAvatar() {
    try {
      return localStorage.getItem(myAvatarKey());
    } catch (e) {
      return null;
    }
  }

  async function doSetAvatar(file) {
    try {
      const dataUrl = await HavenAvatars.fileToAvatarDataUrl(file);
      localStorage.setItem(myAvatarKey(), dataUrl);
      renderMyAvatar();
      for (const fp of state.peers.keys()) {
        sendMyAvatarTo(fp).catch((e) => console.error("send avatar failed:", e));
      }
    } catch (e) {
      console.error("set avatar failed:", e);
      appendLine("sys", "Could not set avatar: " + e.message);
    }
  }

  async function sendMyAvatarTo(fingerprint) {
    const dataUrl = loadMyAvatar();
    if (!dataUrl) return;
    if (!(await ensureConnected(fingerprint))) return;
    await state.net.sendText(fingerprint, HavenAvatars.dataUrlToPayload(dataUrl), "avatar");
  }

  async function handleIncomingAvatar(fingerprint, text) {
    let dataUrl;
    try {
      dataUrl = HavenAvatars.payloadToDataUrl(text);
    } catch (e) {
      return;
    }
    await state.store.setAvatar(fingerprint, dataUrl);
    const meta = state.peers.get(fingerprint);
    if (meta) meta.avatarDataUrl = dataUrl;
    refreshPeerList();
    if (fingerprint === state.openFingerprint) renderChatHeaderAvatar(fingerprint);
  }

  function renderGroupHeader(groupId) {
    const g = state.groupManager.listGroups().find((x) => x.groupId === groupId);
    if (!g) return;
    el("chat-title-text").textContent = g.name + (g.removed ? " (you were removed)" : "");
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
    document.body.classList.add("chat-open");
    el("safety-number").textContent = "";
    el("verify-btn").hidden = true;
    el("group-add-member-row").hidden = true;
    el("call-controls").hidden = true;
    el("incoming-call-banner").classList.add("hide");
    el("active-call-panel").classList.add("hide");
    el("incoming-group-call-banner").classList.add("hide");
    if (state.groupCallManager.isActive(groupId)) {
      el("active-group-call-panel").classList.remove("hide");
      renderGroupCallParticipants(groupId);
    } else {
      el("active-group-call-panel").classList.add("hide");
    }
    el("chat-title-avatar").innerHTML = "";
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
    document.body.classList.add("chat-open");
    el("group-controls").hidden = true;
    el("group-add-member-row").hidden = true;
    el("call-controls").hidden = false;
    el("incoming-call-banner").classList.add("hide");
    el("active-call-panel").classList.add("hide");
    const meta = state.peers.get(fingerprint);
    el("chat-title-text").textContent = meta ? meta.username : fingerprint;
    renderChatHeaderAvatar(fingerprint);
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

  // Mobile layout only (see the @media block in index.html) — desktop
  // shows the contact list and open chat side by side and this button
  // is hidden there, so it's harmless to always wire up.
  function doBackToList() {
    document.body.classList.remove("chat-open");
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

  function updateCallUI(callState) {
    const banner = el("incoming-call-banner");
    const panel = el("active-call-panel");
    if (callState === "ringing_in") {
      // handled by onIncomingCall showing the banner; nothing else to do here
    } else if (callState === "ringing_out") {
      banner.classList.add("hide");
      panel.classList.remove("hide");
      el("active-call-status").textContent = "Calling…";
      el("call-mute-btn").hidden = true;
    } else if (callState === "active") {
      banner.classList.add("hide");
      panel.classList.remove("hide");
      el("active-call-status").textContent = "Call in progress";
      el("call-mute-btn").hidden = false;
      el("call-mute-btn").textContent = "Mute";
    } else {
      // ended / rejected / error
      banner.classList.add("hide");
      panel.classList.add("hide");
      const localImg = el("local-video-preview");
      const remoteImg = el("remote-video-display");
      if (localImg.dataset.prevUrl) URL.revokeObjectURL(localImg.dataset.prevUrl);
      if (remoteImg.dataset.prevUrl) URL.revokeObjectURL(remoteImg.dataset.prevUrl);
      localImg.hidden = true;
      remoteImg.hidden = true;
      localImg.removeAttribute("src");
      remoteImg.removeAttribute("src");
      if (callState === "rejected") appendLine("sys", "Call rejected.");
      else if (callState === "ended") appendLine("sys", "Call ended.");
    }
  }

  async function doStartCall(video) {
    if (!state.openFingerprint) return;
    try {
      if (!(await ensureConnected(state.openFingerprint))) return;
      await state.callManager.startCall(state.openFingerprint, video);
    } catch (e) {
      console.error("startCall failed:", e);
      appendLine("sys", "Could not start call: " + e.message);
    }
  }

  async function doAcceptCall() {
    if (!state.openFingerprint) return;
    el("incoming-call-banner").classList.add("hide");
    try {
      await state.callManager.acceptCall(state.openFingerprint);
    } catch (e) {
      console.error("acceptCall failed:", e);
      appendLine("sys", "Could not accept call: " + e.message);
    }
  }

  async function doRejectCall() {
    if (!state.openFingerprint) return;
    el("incoming-call-banner").classList.add("hide");
    try {
      await state.callManager.rejectCall(state.openFingerprint);
    } catch (e) {
      console.error("rejectCall failed:", e);
    }
  }

  async function doHangup() {
    if (!state.openFingerprint) return;
    try {
      await state.callManager.hangup(state.openFingerprint);
    } catch (e) {
      console.error("hangup failed:", e);
    }
  }

  function doToggleMute() {
    if (!state.openFingerprint) return;
    const btn = el("call-mute-btn");
    const nowMuted = btn.textContent !== "Unmute";
    state.callManager.setMuted(state.openFingerprint, nowMuted);
    btn.textContent = nowMuted ? "Unmute" : "Mute";
  }

  function updateGroupCallUI(callState) {
    const banner = el("incoming-group-call-banner");
    const panel = el("active-group-call-panel");
    if (callState === "active") {
      banner.classList.add("hide");
      panel.classList.remove("hide");
      el("group-call-mute-btn").textContent = "Mute";
      if (state.openGroupId) renderGroupCallParticipants(state.openGroupId);
    } else {
      banner.classList.add("hide");
      panel.classList.add("hide");
      el("group-call-participants").innerHTML = "";
      if (callState === "ended") appendLine("sys", "Group call ended.");
    }
  }

  function renderGroupCallParticipants(groupId) {
    const container = el("group-call-participants");
    container.innerHTML = "";
    // Myself first, so you can always see your own mic is live.
    const meTile = document.createElement("div");
    meTile.className = "participant-tile";
    meTile.appendChild(avatarElement(state.username, loadMyAvatar()));
    const meName = document.createElement("div");
    meName.className = "participant-name";
    meName.textContent = state.username + " (you)";
    meTile.appendChild(meName);
    container.appendChild(meTile);

    for (const p of state.groupCallManager.participants(groupId).values()) {
      const tile = document.createElement("div");
      tile.className = "participant-tile" + (p.speaking ? " speaking" : "");
      tile.appendChild(avatarElement(p.username, null));
      if (p.videoUrl) {
        const img = document.createElement("img");
        img.className = "participant-video";
        img.src = p.videoUrl;
        tile.appendChild(img);
      }
      const name = document.createElement("div");
      name.className = "participant-name";
      name.textContent = p.username;
      tile.appendChild(name);
      container.appendChild(tile);
    }
  }

  async function doStartGroupCall(video) {
    if (!state.openGroupId) return;
    try {
      await state.groupCallManager.startOrJoin(state.openGroupId, video);
    } catch (e) {
      console.error("startGroupCall failed:", e);
      appendLine("sys", "Could not start group call: " + e.message);
    }
  }

  async function doJoinGroupCall() {
    if (!state.openGroupId) return;
    el("incoming-group-call-banner").classList.add("hide");
    try {
      await state.groupCallManager.startOrJoin(state.openGroupId, false);
    } catch (e) {
      console.error("joinGroupCall failed:", e);
      appendLine("sys", "Could not join group call: " + e.message);
    }
  }

  function doDismissGroupCall() {
    el("incoming-group-call-banner").classList.add("hide");
  }

  async function doLeaveGroupCall() {
    if (!state.openGroupId) return;
    try {
      await state.groupCallManager.leave(state.openGroupId);
    } catch (e) {
      console.error("leaveGroupCall failed:", e);
    }
  }

  function doToggleGroupCallMute() {
    if (!state.openGroupId) return;
    const btn = el("group-call-mute-btn");
    const nowMuted = btn.textContent !== "Unmute";
    state.groupCallManager.setMuted(state.openGroupId, nowMuted);
    btn.textContent = nowMuted ? "Unmute" : "Mute";
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

  function toggleGifPicker() {
    const picker = el("gif-picker");
    if (picker.classList.contains("show")) {
      picker.classList.remove("show");
      return;
    }
    if (!HavenGiphy.configured) {
      appendLine(
        "sys",
        "GIF search needs a free Giphy API key — get one at developers.giphy.com and paste it into webapp/static/js/giphy.js."
      );
      return;
    }
    el("gif-search").value = "";
    el("gif-results").innerHTML = "";
    picker.classList.add("show");
    el("gif-search").focus();
  }

  let gifSearchDebounce = null;
  function onGifSearchInput() {
    clearTimeout(gifSearchDebounce);
    const query = el("gif-search").value.trim();
    if (!query) {
      el("gif-results").innerHTML = "";
      return;
    }
    gifSearchDebounce = setTimeout(() => doGifSearch(query), 350);
  }

  async function doGifSearch(query) {
    const results = el("gif-results");
    try {
      const gifs = await HavenGiphy.search(query);
      results.innerHTML = "";
      for (const gif of gifs) {
        const img = document.createElement("img");
        img.src = gif.previewUrl;
        img.alt = gif.title;
        img.onclick = () => pickGif(gif);
        results.appendChild(img);
      }
    } catch (e) {
      console.error("Giphy search failed:", e);
      results.innerHTML = "";
      appendLine("sys", "GIF search failed: " + e.message);
    }
  }

  async function pickGif(gif) {
    el("gif-picker").classList.remove("show");
    if (!state.openFingerprint && !state.openGroupId) return;
    try {
      const bytes = await HavenGiphy.fetchGifBytes(gif.fullUrl);
      const file = new File([bytes], `${gif.id}.gif`, { type: "image/gif" });
      await sendAttachment(file);
    } catch (e) {
      console.error("send GIF failed:", e);
      appendLine("sys", "Could not send GIF: " + e.message);
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

  window.addEventListener("DOMContentLoaded", async () => {
    const saved = loadSession();
    if (saved) {
      try {
        const identity = H.keyPairFromPrivateBytes(H.hexToBytes(saved.privateBytesHex));
        await onLoggedIn(identity, saved.username);
      } catch (e) {
        console.error("auto-login from saved session failed:", e);
        clearSession();
      }
    }

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
    el("call-voice-btn").onclick = () => doStartCall(false);
    el("call-video-btn").onclick = () => doStartCall(true);
    el("incoming-call-accept").onclick = doAcceptCall;
    el("incoming-call-reject").onclick = doRejectCall;
    el("call-hangup-btn").onclick = doHangup;
    el("call-mute-btn").onclick = doToggleMute;
    el("group-call-voice-btn").onclick = () => doStartGroupCall(false);
    el("group-call-video-btn").onclick = () => doStartGroupCall(true);
    el("incoming-group-call-join").onclick = doJoinGroupCall;
    el("incoming-group-call-dismiss").onclick = doDismissGroupCall;
    el("group-call-leave-btn").onclick = doLeaveGroupCall;
    el("group-call-mute-btn").onclick = doToggleGroupCallMute;
    el("logout-link").onclick = (e) => {
      e.preventDefault();
      doLogout();
    };
    el("back-to-list-btn").onclick = doBackToList;
    el("set-avatar-btn").onclick = () => el("avatar-file").click();
    el("avatar-file").addEventListener("change", () => {
      const file = el("avatar-file").files[0];
      el("avatar-file").value = "";
      if (file) doSetAvatar(file);
    });
    el("gif-btn").onclick = toggleGifPicker;
    el("gif-search").addEventListener("input", onGifSearchInput);
  });
})();
