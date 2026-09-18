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
    peers: new Map(), // fingerprint -> {username, identityPubHex, avatarDataUrl, status: "accepted"|"pending_out"|"pending_in"}
    peerPresence: new Map(), // fingerprint -> "online" | "hidden" — see settings' online-status toggle
    openFingerprint: null,
    openGroupId: null,
    replyTarget: null, // {id, who, senderName, kind, text} of the message being replied to, or null
    translationBuffers: new Map(), // "1:1:<fp>" | "group:<groupId>:<pubHex>" -> HavenTranslation.SpeakerBuffer
  };

  const el = (id) => document.getElementById(id);

  // Per-account local settings (privacy toggles) — same localStorage
  // pattern as myAvatarKey(), namespaced per username since one browser
  // profile can be used for more than one account over time.
  function getSetting(name, def) {
    try {
      const raw = localStorage.getItem(`haven-setting-${name}:${state.username}`);
      return raw === null ? def : raw === "true";
    } catch (e) {
      return def;
    }
  }
  function setSetting(name, value) {
    try {
      localStorage.setItem(`haven-setting-${name}:${state.username}`, String(value));
    } catch (e) {
      /* ignore (private/incognito mode) */
    }
  }

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
    el("login-page").hidden = name !== "login";
    el("app-screen").hidden = name !== "app";
  }

  function setStatus(msg) {
    el("login-status").textContent = msg;
  }

  // Shows a spinner in place of the button's own label and disables it
  // — disabling doubles as the guard against a repeated click re-firing
  // the same signup/login/etc. while one is already in flight, which
  // nothing here previously prevented.
  function setButtonLoading(btn, loading) {
    btn.classList.toggle("loading", loading);
    btn.disabled = loading;
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
    setButtonLoading(el("signup-btn"), true);
    try {
      const { identity, recoveryPhrase } = await state.accountsClient.signup(username, password);
      await showRecoveryPhrase(recoveryPhrase);
      await onLoggedIn(identity, username);
    } catch (e) {
      console.error("signup failed:", e);
      setStatus(e.message);
    } finally {
      setButtonLoading(el("signup-btn"), false);
    }
  }

  async function doLogin() {
    const username = el("username").value.trim();
    const password = el("password").value;
    const accountsUrl = defaultAccountsUrl();
    if (!username || !password) return setStatus("Enter a username and password.");
    state.accountsClient = new HavenAuth.AccountsClient(accountsUrl);
    setButtonLoading(el("login-btn"), true);
    try {
      const { identity } = await state.accountsClient.login(username, password);
      await onLoggedIn(identity, username);
    } catch (e) {
      console.error("login failed:", e);
      setStatus(e.message);
    } finally {
      setButtonLoading(el("login-btn"), false);
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
    setButtonLoading(el("reset-password-btn"), true);
    try {
      const { identity } = await state.accountsClient.resetPassword(username, recoveryPhrase, newPassword);
      el("forgot-password-row").hidden = true;
      setStatus("");
      await onLoggedIn(identity, username);
    } catch (e) {
      console.error("password reset failed:", e);
      setStatus(e.message);
    } finally {
      setButtonLoading(el("reset-password-btn"), false);
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
    setButtonLoading(el("restore-backup-confirm"), true);
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
    } finally {
      setButtonLoading(el("restore-backup-confirm"), false);
    }
  }

  // Triggered from a chat's 3-dot menu, but exports the WHOLE account
  // (every contact, every chat's history) — there's no per-chat backup
  // format, and building one wasn't asked for; the modal text says so
  // explicitly since "Backup…" living on one specific chat's menu could
  // otherwise read as scoped to just that chat.
  function openBackup() {
    el("chat-menu-popup").classList.add("hide");
    el("backup-password").value = "";
    el("backup-overlay").classList.remove("hide");
  }

  async function doBackup() {
    const password = el("backup-password").value;
    if (!password) return;
    setButtonLoading(el("backup-confirm"), true);
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
      el("backup-overlay").classList.add("hide");
    } catch (e) {
      console.error("backup export failed:", e);
      appendLine("sys", "Backup failed: " + e.message);
    } finally {
      setButtonLoading(el("backup-confirm"), false);
    }
  }

  async function onLoggedIn(identity, username) {
    // The auto-login-from-saved-session path (see loadSession below)
    // skips doLogin entirely, so it never gets an accountsClient the
    // normal login flow would have set — people-search needs one
    // regardless of which path got us here.
    if (!state.accountsClient) state.accountsClient = new HavenAuth.AccountsClient(defaultAccountsUrl());
    state.identity = identity;
    state.username = username;
    state.store = await HavenStorage.Store.open(username, identity.privateBytes);
    state.net = new HavenNetwork.NetworkManager(identity, username, state.store);
    state.groupManager = await HavenGroups.GroupManager.create(state.net, state.store, identity, username);
    state.groupManager.onGroupMessage = (groupId, senderUsername, text, kind, senderPubHex, id) => {
      if (kind === "group_call") {
        state.groupCallManager.handleIncoming(groupId, senderPubHex, senderUsername, text);
        return;
      }
      if (kind === "typing") {
        if (groupId === state.openGroupId && senderUsername !== state.username) showTypingIndicator(senderUsername);
        return;
      }
      if (state.openGroupId === groupId) {
        const isMe = senderUsername === state.username;
        appendLine(isMe ? "me" : "them", text, kind, { id, context: "group", senderLabel: isMe ? null : senderUsername });
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
      el("incoming-group-call-text").textContent = `${fromUsername} started a${hasVideo ? " video" : ""} group call`;
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
    state.groupCallManager.onAudioChunk = (groupId, senderPubHex, int16) => {
      if (groupId !== state.openGroupId) return; // only translate for the call you're actually looking at
      const participant = state.groupCallManager.participants(groupId).get(senderPubHex);
      const name = participant ? participant.username : senderPubHex.slice(0, 8);
      const buf = getTranslationBuffer(`group:${groupId}:${senderPubHex}`, (text, language) =>
        appendCaption("group-call-captions", name, text, language)
      );
      if (buf) buf.push(int16);
    };
    state.callManager = new HavenCalls.CallManager(state.net, identity, username);
    state.callManager.onIncomingCall = (fp, callId, hasVideo) => {
      if (fp !== state.openFingerprint) return; // known limitation: calls only surface for the currently-open chat
      const meta = state.peers.get(fp);
      el("incoming-call-text").textContent = `Incoming ${hasVideo ? "video " : ""}call from ${meta ? meta.username : fp}`;
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
    state.callManager.onAudioChunk = (fp, int16) => {
      if (fp !== state.openFingerprint) return; // only translate for the call you're actually looking at
      const name = state.peers.get(fp) ? state.peers.get(fp).username : fp;
      const buf = getTranslationBuffer(`1:1:${fp}`, (text, language) => appendCaption("call-captions", name, text, language));
      if (buf) buf.push(int16);
    };
    state.net.onMessage = (fp, kind, text, senderPubHex, id) => {
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
      if (kind === "presence") {
        try {
          state.peerPresence.set(fp, JSON.parse(text).status);
        } catch (e) {
          /* ignore malformed presence frame */
        }
        refreshPeerList();
        return;
      }
      if (kind === "read") {
        let upTo = -1;
        try {
          upTo = JSON.parse(text).upTo;
        } catch (e) {
          /* ignore malformed read-receipt frame */
        }
        if (typeof upTo === "number" && upTo >= 0) {
          state.store.markSeenUpTo(fp, upTo).then(() => {
            if (fp === state.openFingerprint) renderMessagesFor({ type: "chat", fingerprint: fp });
          });
        }
        return;
      }
      if (kind === "typing") {
        if (fp === state.openFingerprint) {
          const meta = state.peers.get(fp);
          showTypingIndicator(meta ? meta.username : "Someone");
        }
        return;
      }
      if (fp === state.openFingerprint) {
        appendLine("them", text, kind, { id, context: "chat" });
        sendReadReceiptIfNeeded(fp);
      }
      refreshPeerList();
    };
    state.net.onConnect = (conn) => {
      const fp = conn.fingerprint;
      const existing = state.peers.get(fp);
      state.peers.set(fp, {
        username: conn.username,
        identityPubHex: H.bytesToHex(conn.identityPub),
        avatarDataUrl: existing ? existing.avatarDataUrl : undefined,
        status: "accepted",
      });
      refreshPeerList();
      renderRequests();
      if (fp === state.openFingerprint) renderChatHeaderAvatar(fp);
      sendMyAvatarTo(fp).catch((e) => console.error("send avatar failed:", e));
      sendPresenceTo(fp).catch((e) => console.error("send presence failed:", e));
    };
    state.net.onStatus = () => refreshPeerList();
    // Someone we don't yet trust said hello — park them as a pending
    // request (see network.js's _handleHello) instead of opening a
    // session, and surface them in the Requests tab for an explicit
    // accept/decline.
    state.net.onContactRequest = (fp, username, identityPubHex) => {
      const existing = state.peers.get(fp);
      state.peers.set(fp, {
        username,
        identityPubHex,
        avatarDataUrl: existing ? existing.avatarDataUrl : undefined,
        status: "pending_in",
      });
      renderRequests();
    };

    const relayWsUrl = defaultRelayWsUrl();
    state.relay = new HavenNetwork.RelayClient(identity, username, relayWsUrl);
    state.net.attachRelay(state.relay);
    state.relay.onConnectionChange = (connected) => {
      el("relay-status").textContent = connected ? "Relay: connected" : "Relay: reconnecting…";
    };
    state.relay.start();

    for (const c of await state.store.listContacts()) {
      state.peers.set(c.fingerprint, {
        username: c.username,
        identityPubHex: c.identityPubHex,
        avatarDataUrl: c.avatarDataUrl,
        status: c.status || "accepted",
      });
    }
    refreshPeerList();
    renderRequests();
    showScreen("app");
    el("my-username").textContent = state.username;
    saveSession(username, identity.privateBytes);
    renderMyAvatar();
    el("setting-online-status").checked = getSetting("online-status", true);
    el("setting-read-receipts").checked = getSetting("read-receipts", true);
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
      // Requests awaiting OUR decision live in the Requests tab, not
      // here — an incoming request isn't a chat until it's accepted.
      if (meta.status === "pending_in") continue;
      const li = document.createElement("li");
      li.appendChild(avatarElement(meta.username, meta.avatarDataUrl));
      if (meta.status === "pending_out") {
        // We sent this request and are waiting on them — nothing to
        // open yet, so this row is a status line, not a clickable chat.
        li.appendChild(document.createTextNode(`${meta.username} (request sent)`));
        li.className = "peer-pending";
      } else {
        // A contact can be technically connected but have told us (via
        // a "presence" frame) they'd rather appear offline — see the
        // Settings tab's "Share online status" toggle, the local half
        // of this same mechanism.
        const presence = state.peerPresence.get(fp) || "online";
        const online = state.net.isConnected(fp) && presence !== "hidden";
        li.appendChild(document.createTextNode(`${meta.username} (${online ? "online" : "offline"})`));
        li.className = fp === state.openFingerprint ? "selected" : "";
        li.onclick = () => openChat(fp);
      }
      li.dataset.fp = fp;
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
      if (meta.status && meta.status !== "accepted") continue; // can't message a pending contact yet, so can't group them
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
      return showAlert("Enter a group name and pick at least one member.");
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
      if (meta.status && meta.status !== "accepted") continue;
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
    hideTypingIndicator();
    clearReplyTarget();
    el("safety-number").textContent = "";
    el("verify-btn").hidden = true;
    el("group-add-member-row").hidden = true;
    el("call-controls").hidden = true;
    el("chat-menu-wrap").hidden = false;
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
    await renderMessagesFor({ type: "group", groupId });
  }

  async function openChat(fingerprint) {
    state.openFingerprint = fingerprint;
    state.openGroupId = null;
    document.body.classList.add("chat-open");
    hideTypingIndicator();
    clearReplyTarget();
    el("group-controls").hidden = true;
    el("group-add-member-row").hidden = true;
    el("call-controls").hidden = false;
    el("chat-menu-wrap").hidden = false;
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
      const matches = await showConfirm(`Safety number:\n\n${fingerprint}\n\nDoes this match what your contact sees for you?`, {
        okLabel: "It matches",
        cancelLabel: "Not yet",
      });
      if (matches) {
        await state.store.setVerified(fingerprint, true);
        el("safety-number").textContent = "Safety number: " + fingerprint + "  ✓ verified";
      }
    };

    await renderMessagesFor({ type: "chat", fingerprint });
    if (!state.net.isConnected(fingerprint) && meta) {
      try {
        await state.net.connectRelay(H.hexToBytes(meta.identityPubHex), meta.username);
      } catch (e) {
        console.error("connectRelay failed:", e);
        appendLine("sys", "Could not reach relay: " + e.message);
      }
    }
    await sendReadReceiptIfNeeded(fingerprint);
  }

  // Mobile layout only (see the @media block in index.html) — desktop
  // shows the contact list and open chat side by side and this button
  // is hidden there, so it's harmless to always wire up.
  function doBackToList() {
    document.body.classList.remove("chat-open");
  }

  // A short, human label for a message — used for reply quotes and the
  // pinned-messages bar, neither of which want to try to render a whole
  // attachment inline. kind="reply" recurses into the ORIGINAL kind a
  // reply payload wraps (see the "reply" branch in appendLine below),
  // so quoting a reply-to-a-reply still shows real content, not "[object]".
  function snippetForKind(kind, text) {
    if (kind === "reply") {
      try {
        const p = JSON.parse(text);
        return snippetForKind(p.origKind || "text", p.body);
      } catch (e) {
        return "message";
      }
    }
    if (kind === "image") return "Photo";
    if (kind === "gif") return "GIF";
    if (kind === "audio") return "Voice message";
    if (kind === "video") return "Video";
    if (kind !== "text") return "Attachment";
    return text.length > 60 ? text.slice(0, 60) + "…" : text;
  }

  // Replaces window.confirm/alert everywhere in this app. Two real
  // reasons, not just a style preference: native dialogs are silently
  // a no-op in an iOS "Add to Home Screen" web app (exactly how this
  // app is meant to be used day to day) — window.confirm() just
  // returns without ever showing anything, which is why "Clear chat"/
  // "Delete chat" could look broken — and a browser-chrome dialog box
  // clashes with a custom-themed UI anyway.
  function showConfirm(message, { okLabel = "OK", cancelLabel = "Cancel", danger = false } = {}) {
    return new Promise((resolve) => {
      el("confirm-message").textContent = message;
      const okBtn = el("confirm-ok-btn");
      const cancelBtn = el("confirm-cancel-btn");
      okBtn.textContent = okLabel;
      okBtn.className = danger ? "danger" : "primary";
      cancelBtn.hidden = false;
      cancelBtn.textContent = cancelLabel;
      el("confirm-overlay").classList.remove("hide");
      const cleanup = (result) => {
        el("confirm-overlay").classList.add("hide");
        okBtn.onclick = null;
        cancelBtn.onclick = null;
        resolve(result);
      };
      okBtn.onclick = () => cleanup(true);
      cancelBtn.onclick = () => cleanup(false);
    });
  }

  function showAlert(message) {
    return new Promise((resolve) => {
      el("confirm-message").textContent = message;
      const okBtn = el("confirm-ok-btn");
      const cancelBtn = el("confirm-cancel-btn");
      okBtn.textContent = "OK";
      okBtn.className = "primary";
      cancelBtn.hidden = true;
      el("confirm-overlay").classList.remove("hide");
      okBtn.onclick = () => {
        el("confirm-overlay").classList.add("hide");
        okBtn.onclick = null;
        resolve();
      };
    });
  }

  function setReplyTarget(info) {
    // info: {id, who, senderName, kind, text} — kind/text are the
    // ORIGINAL (still-wrapped-if-reply) values, so quoting a reply
    // works the same way snippetForKind's recursion does.
    state.replyTarget = info;
    el("reply-preview-label").textContent = "Replying to " + (info.who === "me" ? "yourself" : info.senderName || "them");
    el("reply-preview-snippet").textContent = snippetForKind(info.kind, info.text);
    el("reply-preview-row").classList.remove("hide");
  }

  function clearReplyTarget() {
    state.replyTarget = null;
    el("reply-preview-row").classList.add("hide");
  }

  function closeAllMsgMenus() {
    document.querySelectorAll(".msg-menu-popup").forEach((p) => p.classList.add("hide"));
  }

  async function togglePin(info) {
    // info.id belongs to whichever chat is currently open — pin/unpin
    // is only ever triggered from a menu on a message that's on screen.
    if (state.openFingerprint) {
      await state.store.setPinned(info.id, !info.pinned);
      await renderMessagesFor({ type: "chat", fingerprint: state.openFingerprint });
    } else if (state.openGroupId) {
      await state.store.setGroupMessagePinned(info.id, !info.pinned);
      await renderMessagesFor({ type: "group", groupId: state.openGroupId });
    }
  }

  // Wires up the web 3-dot menu (reply/pin) and the mobile swipe-to-
  // reply gesture on a rendered message bubble. Skipped for "sys" lines
  // and for anything that was never persisted (id undefined — a
  // NON_MESSAGE_KINDS control frame slipping through would have nothing
  // to reply-to or pin).
  function attachMsgInteractions(div, info) {
    if (info.who === "sys" || info.id === undefined) return;
    div.dataset.msgId = String(info.id);

    const menuBtn = document.createElement("button");
    menuBtn.type = "button";
    menuBtn.className = "msg-menu-btn";
    menuBtn.title = "Message options";
    menuBtn.textContent = "⋮";

    const popup = document.createElement("div");
    popup.className = "msg-menu-popup hide";

    const replyBtn = document.createElement("button");
    replyBtn.type = "button";
    replyBtn.textContent = "Reply";
    replyBtn.onclick = (e) => {
      e.stopPropagation();
      popup.classList.add("hide");
      setReplyTarget({ id: info.id, who: info.who, senderName: info.senderLabel, kind: info.kind, text: info.text });
      el("message-input").focus();
    };

    const pinBtn = document.createElement("button");
    pinBtn.type = "button";
    pinBtn.textContent = info.pinned ? "Unpin" : "Pin";
    pinBtn.onclick = async (e) => {
      e.stopPropagation();
      popup.classList.add("hide");
      await togglePin(info);
    };

    popup.appendChild(replyBtn);
    popup.appendChild(pinBtn);
    menuBtn.onclick = (e) => {
      e.stopPropagation();
      const wasHidden = popup.classList.contains("hide");
      closeAllMsgMenus();
      if (wasHidden) popup.classList.remove("hide");
    };
    div.appendChild(menuBtn);
    div.appendChild(popup);

    // Swipe-to-reply: touch-only (mouse users get the 3-dot menu above).
    // Tracks a horizontal drag and, past a threshold on release, sets
    // the same reply target the menu's Reply button does.
    let startX = null;
    let dx = 0;
    div.addEventListener(
      "touchstart",
      (e) => {
        startX = e.touches[0].clientX;
        dx = 0;
      },
      { passive: true }
    );
    div.addEventListener(
      "touchmove",
      (e) => {
        if (startX === null) return;
        dx = Math.max(0, Math.min(70, e.touches[0].clientX - startX));
        div.style.transform = dx ? `translateX(${dx}px)` : "";
      },
      { passive: true }
    );
    div.addEventListener("touchend", () => {
      if (dx > 50) {
        setReplyTarget({ id: info.id, who: info.who, senderName: info.senderLabel, kind: info.kind, text: info.text });
      }
      div.style.transform = "";
      startX = null;
      dx = 0;
    });
  }

  function appendLine(who, text, kind = "text", opts = {}) {
    const div = document.createElement("div");
    div.className = "msg " + who + (opts.pinned ? " pinned" : "");
    const senderLabel = opts.senderLabel || null;
    const prefix = who === "me" ? "you: " : who === "them" ? (senderLabel ? senderLabel + ": " : "") : "* ";

    // The REAL username behind this bubble, regardless of who's looking
    // at it — used for reply targets/quotes, which travel over the wire
    // to the other side and so can't bake in a viewer-relative "You"
    // (see the quote rendering below, which does that localization at
    // display time instead, once per viewer).
    const resolvedSenderName =
      who === "me" ? state.username : senderLabel || (state.peers.get(state.openFingerprint) || {}).username || "them";

    // kind="reply" wraps an original message (of ANY kind, including
    // another reply, or an attachment) with a quoted snippet of what
    // it's replying to — see sendMessage/sendAttachment for how it's
    // built. Unwrap it here so the body renders exactly like a normal
    // message of its original kind, just with a quote box on top.
    let bodyKind = kind;
    let bodyText = text;
    let replyQuote = null;
    if (kind === "reply") {
      try {
        const parsed = JSON.parse(text);
        bodyText = parsed.body;
        bodyKind = parsed.origKind || "text";
        replyQuote = { sender: parsed.rSender, snippet: parsed.rSnippet };
      } catch (e) {
        bodyText = text;
        bodyKind = "text";
      }
    }

    if (replyQuote) {
      const quote = document.createElement("div");
      quote.className = "msg-reply-quote";
      const senderSpan = document.createElement("span");
      senderSpan.className = "msg-reply-sender";
      // replyQuote.sender is always the real username (see
      // applyReplyTarget) — "You" only ever applies to THIS viewer's
      // own messages, so it's resolved here rather than baked into the
      // payload, where it would be wrong for whichever side didn't send it.
      senderSpan.textContent = (replyQuote.sender === state.username ? "You" : replyQuote.sender) + ": ";
      quote.appendChild(senderSpan);
      quote.appendChild(document.createTextNode(replyQuote.snippet));
      div.appendChild(quote);
    }

    if (bodyKind === "text") {
      div.appendChild(document.createTextNode(prefix + bodyText));
    } else {
      try {
        const payload = HavenAttachments.decodeAttachment(bodyText);
        if (prefix) div.appendChild(document.createTextNode(prefix));
        let media;
        if (bodyKind === "image" || bodyKind === "gif") {
          media = document.createElement("img");
          media.src = HavenAttachments.attachmentDataUrl(bodyText);
          media.alt = payload.filename;
        } else if (bodyKind === "audio") {
          media = document.createElement("audio");
          media.controls = true;
          media.src = HavenAttachments.attachmentDataUrl(bodyText);
        } else if (bodyKind === "video") {
          media = document.createElement("video");
          media.controls = true;
          media.src = HavenAttachments.attachmentDataUrl(bodyText);
        } else {
          const blob = new Blob([payload.data], { type: payload.mime });
          media = document.createElement("a");
          media.href = URL.createObjectURL(blob);
          media.download = payload.filename;
          media.textContent = "Download " + payload.filename;
        }
        div.appendChild(media);
      } catch (e) {
        div.appendChild(document.createTextNode(prefix + "[unreadable attachment]"));
      }
    }

    // Read-receipt ticks only ever apply to my own outgoing 1:1
    // messages — group chats don't track per-message seen state (see
    // groups.js's module docstring: no per-recipient delivery tracking
    // exists there), and an incoming message obviously has nothing of
    // MINE for the other side to have seen.
    if (who === "me" && opts.context === "chat") {
      const ticks = document.createElement("span");
      ticks.className = "msg-ticks" + (opts.seen ? " seen" : "");
      ticks.textContent = opts.seen ? "✓✓" : "✓";
      div.appendChild(ticks);
    }

    el("messages").appendChild(div);
    el("messages").scrollTop = el("messages").scrollHeight;

    if (who !== "sys") {
      attachMsgInteractions(div, { id: opts.id, who, kind, text, senderLabel: resolvedSenderName, pinned: !!opts.pinned });
    }
    return div;
  }

  // Re-renders the entire message pane for whichever chat/group is
  // currently open, from persisted storage — used for the initial open
  // AND to refresh ticks/pins after something changes them out from
  // under the currently-visible messages (a read receipt arriving, a
  // pin toggled, a chat cleared).
  async function renderMessagesFor(ctx) {
    el("messages").innerHTML = "";
    let rows;
    let context;
    if (ctx.type === "chat") {
      rows = (await state.store.history(ctx.fingerprint)).map((m) => ({
        who: m.direction === "out" ? "me" : "them",
        text: m.text,
        kind: m.kind,
        id: m.id,
        seen: m.seen,
        pinned: m.pinned,
        senderLabel: null,
      }));
      context = "chat";
    } else {
      const g = state.groupManager.listGroups().find((x) => x.groupId === ctx.groupId);
      rows = (await state.groupManager.groupHistory(ctx.groupId)).map((m) => {
        const isMe = m.senderIdentityPubHex === state.groupManager.myPubHex;
        return {
          who: isMe ? "me" : "them",
          text: m.text,
          kind: m.kind,
          id: m.id,
          pinned: m.pinned,
          senderLabel: isMe ? null : (g && g.members.get(m.senderIdentityPubHex)) || "unknown",
        };
      });
      context = "group";
    }
    for (const row of rows) appendLine(row.who, row.text, row.kind, { ...row, context });
    renderPinnedBar(rows.filter((r) => r.pinned));
  }

  function renderPinnedBar(pinnedRows) {
    const bar = el("pinned-bar");
    bar.innerHTML = "";
    if (!pinnedRows.length) {
      bar.classList.add("hide");
      return;
    }
    bar.classList.remove("hide");
    for (const row of pinnedRows) {
      const chip = document.createElement("div");
      chip.className = "pinned-chip";
      const text = document.createElement("span");
      text.className = "pinned-chip-text";
      text.textContent = snippetForKind(row.kind, row.text);
      text.onclick = () => {
        const target = document.querySelector(`.msg[data-msg-id="${row.id}"]`);
        if (!target) return;
        target.scrollIntoView({ behavior: "smooth", block: "center" });
        target.style.outline = "2px solid #e0c860";
        setTimeout(() => (target.style.outline = ""), 1200);
      };
      const unpinBtn = document.createElement("button");
      unpinBtn.className = "pinned-chip-unpin";
      unpinBtn.title = "Unpin";
      unpinBtn.textContent = "✕";
      unpinBtn.onclick = async (e) => {
        e.stopPropagation();
        await togglePin(row);
      };
      chip.appendChild(text);
      chip.appendChild(unpinBtn);
      bar.appendChild(chip);
    }
  }

  async function sendReadReceiptIfNeeded(fingerprint) {
    if (!getSetting("read-receipts", true)) return;
    if (!state.net.isConnected(fingerprint)) return;
    const upTo = state.net.getRecvIndex(fingerprint);
    if (upTo < 0) return;
    try {
      await state.net.sendText(fingerprint, JSON.stringify({ upTo }), "read");
    } catch (e) {
      console.error("read receipt failed:", e);
    }
  }

  async function sendPresenceTo(fingerprint) {
    const status = getSetting("online-status", true) ? "online" : "hidden";
    await state.net.sendText(fingerprint, JSON.stringify({ status }), "presence");
  }

  let typingHideTimer = null;
  function showTypingIndicator(name) {
    el("typing-indicator-text").textContent = `${name} is typing`;
    el("typing-indicator").classList.remove("hide");
    clearTimeout(typingHideTimer);
    typingHideTimer = setTimeout(() => el("typing-indicator").classList.add("hide"), 3000);
  }
  function hideTypingIndicator() {
    clearTimeout(typingHideTimer);
    el("typing-indicator").classList.add("hide");
  }

  let lastTypingPingAt = 0;
  function maybeSendTypingPing() {
    const now = Date.now();
    if (now - lastTypingPingAt < 2500) return;
    lastTypingPingAt = now;
    if (state.openFingerprint) {
      if (state.net.isConnected(state.openFingerprint)) {
        state.net.sendText(state.openFingerprint, "", "typing").catch(() => {});
      }
    } else if (state.openGroupId) {
      state.groupManager.sendGroupMessage(state.openGroupId, "", "typing").catch(() => {});
    }
  }

  function switchSidebarTab(name) {
    el("tab-chats-btn").classList.toggle("active", name === "chats");
    el("tab-requests-btn").classList.toggle("active", name === "requests");
    el("tab-settings-btn").classList.toggle("active", name === "settings");
    el("peer-list").hidden = name !== "chats";
    el("sidebar-footer").hidden = name !== "chats";
    el("requests-list").hidden = name !== "requests";
    el("settings-panel").hidden = name !== "settings";
  }

  // The Requests tab: incoming contact requests (see network.js's
  // onContactRequest) that need an explicit accept or decline before any
  // messaging can happen. Badges the tab with a count so a new request
  // doesn't go unnoticed while sitting on the Chats tab.
  function renderRequests() {
    const list = el("requests-list");
    const pending = Array.from(state.peers.entries()).filter(([, meta]) => meta.status === "pending_in");
    const badge = el("requests-badge");
    badge.textContent = String(pending.length);
    badge.hidden = pending.length === 0;
    list.innerHTML = "";
    if (!pending.length) {
      const note = document.createElement("div");
      note.className = "user-search-note";
      note.textContent = "No pending requests.";
      list.appendChild(note);
      return;
    }
    for (const [fp, meta] of pending) {
      const row = document.createElement("li");
      row.className = "request-row";
      row.appendChild(avatarElement(meta.username, meta.avatarDataUrl));
      const nameSpan = document.createElement("span");
      nameSpan.className = "request-name";
      nameSpan.textContent = meta.username;
      row.appendChild(nameSpan);
      const acceptBtn = document.createElement("button");
      acceptBtn.className = "primary";
      acceptBtn.textContent = "Accept";
      acceptBtn.onclick = () => doAcceptContactRequest(fp);
      row.appendChild(acceptBtn);
      const declineBtn = document.createElement("button");
      declineBtn.textContent = "Decline";
      declineBtn.onclick = () => doDeclineContactRequest(fp);
      row.appendChild(declineBtn);
      list.appendChild(row);
    }
  }

  async function doAcceptContactRequest(fingerprint) {
    try {
      await state.net.acceptContactRequest(fingerprint);
    } catch (e) {
      console.error("accept contact request failed:", e);
      showAlert("Could not accept: " + e.message);
      return;
    }
    refreshPeerList();
    renderRequests();
  }

  async function doDeclineContactRequest(fingerprint) {
    await state.net.declineContactRequest(fingerprint);
    state.peers.delete(fingerprint);
    renderRequests();
  }

  function closeOpenChatView() {
    el("messages").innerHTML = "";
    el("chat-title-text").textContent = "Select a contact";
    el("chat-title-avatar").innerHTML = "";
    el("chat-menu-wrap").hidden = true;
    el("pinned-bar").classList.add("hide");
    el("safety-number").textContent = "";
    el("verify-btn").hidden = true;
    el("group-controls").hidden = true;
    el("call-controls").hidden = true;
    hideTypingIndicator();
    clearReplyTarget();
  }

  async function doClearChat() {
    el("chat-menu-popup").classList.add("hide");
    const ok = await showConfirm("Clear all messages in this chat? This can't be undone.", { okLabel: "Clear", danger: true });
    if (!ok) return;
    if (state.openFingerprint) {
      await state.store.clearMessages(state.openFingerprint);
      await renderMessagesFor({ type: "chat", fingerprint: state.openFingerprint });
    } else if (state.openGroupId) {
      await state.store.clearGroupMessages(state.openGroupId);
      await renderMessagesFor({ type: "group", groupId: state.openGroupId });
    }
  }

  // Both branches are local-only (see storage.js's deleteContact /
  // groups.js's forgetGroup): nothing is sent to the other side. They
  // just stop appearing as a contact/group on THIS device; if they
  // message you again, a 1:1 contact simply reappears via a fresh
  // session handshake.
  async function doDeleteChat() {
    el("chat-menu-popup").classList.add("hide");
    if (state.openFingerprint) {
      const ok = await showConfirm("Delete this chat? This removes the contact and all messages from this device.", {
        okLabel: "Delete",
        danger: true,
      });
      if (!ok) return;
      const fp = state.openFingerprint;
      await state.store.deleteContact(fp);
      state.peers.delete(fp);
      state.net.disconnect(fp);
      state.openFingerprint = null;
      closeOpenChatView();
    } else if (state.openGroupId) {
      const ok = await showConfirm("Delete this chat? This removes the group and all messages from this device.", {
        okLabel: "Delete",
        danger: true,
      });
      if (!ok) return;
      await state.groupManager.forgetGroup(state.openGroupId);
      state.openGroupId = null;
      closeOpenChatView();
    }
    refreshPeerList();
  }

  function getTranslationBuffer(key, onCaption) {
    if (!HavenTranslation.configured) return null;
    let buf = state.translationBuffers.get(key);
    if (!buf) {
      buf = new HavenTranslation.SpeakerBuffer(onCaption, (e) => console.error("translation failed:", e));
      state.translationBuffers.set(key, buf);
    }
    return buf;
  }

  function appendCaption(elementId, speakerName, text, language) {
    const box = el(elementId);
    box.classList.remove("hide");
    const line = document.createElement("div");
    line.className = "caption-line";
    const langLabel = document.createElement("span");
    langLabel.className = "caption-lang";
    langLabel.textContent = `[${language}] `;
    line.appendChild(langLabel);
    const strong = document.createElement("b");
    strong.textContent = speakerName + ": ";
    line.appendChild(strong);
    line.appendChild(document.createTextNode(text));
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
    while (box.children.length > 20) box.removeChild(box.firstChild); // keep it from growing forever
  }

  function clearCaptions(elementId) {
    const box = el(elementId);
    box.innerHTML = "";
    box.classList.add("hide");
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
      clearCaptions("call-captions");
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
      clearCaptions("call-captions");
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
      clearCaptions("group-call-captions");
      if (state.openGroupId) renderGroupCallParticipants(state.openGroupId);
    } else {
      banner.classList.add("hide");
      panel.classList.add("hide");
      el("group-call-participants").innerHTML = "";
      clearCaptions("group-call-captions");
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

  // Wraps `body`/`kind` in a kind="reply" envelope quoting state.replyTarget,
  // if one is set — shared by sendMessage and sendAttachment so replying
  // works the same way whether you're replying WITH text or an attachment
  // (you can reply to anything, but see snippetForKind for how each
  // original kind gets quoted).
  function applyReplyTarget(body, kind) {
    const reply = state.replyTarget;
    if (!reply) return { body, kind };
    return {
      kind: "reply",
      body: JSON.stringify({
        body,
        origKind: kind,
        // Always the real username (see appendLine's resolvedSenderName)
        // — "You" is never sent over the wire, only shown to whichever
        // viewer it's actually true for, at render time.
        rSender: reply.senderName || "them",
        rSnippet: snippetForKind(reply.kind, reply.text),
      }),
    };
  }

  async function sendMessage() {
    const text = el("message-input").value.trim();
    if (!text || (!state.openFingerprint && !state.openGroupId)) return;
    el("message-input").value = "";
    const wrapped = applyReplyTarget(text, "text");
    clearReplyTarget();
    if (state.openGroupId) {
      const id = await state.groupManager.sendGroupMessage(state.openGroupId, wrapped.body, wrapped.kind);
      appendLine("me", wrapped.body, wrapped.kind, { id, context: "group" });
      return;
    }
    if (!(await ensureConnected(state.openFingerprint))) return;
    try {
      const id = await state.net.sendText(state.openFingerprint, wrapped.body, wrapped.kind);
      appendLine("me", wrapped.body, wrapped.kind, { id, context: "chat", seen: false });
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
    const wrapped = applyReplyTarget(envelope, kind);
    clearReplyTarget();
    if (state.openGroupId) {
      const id = await state.groupManager.sendGroupMessage(state.openGroupId, wrapped.body, wrapped.kind);
      appendLine("me", wrapped.body, wrapped.kind, { id, context: "group" });
      return;
    }
    if (!(await ensureConnected(state.openFingerprint))) return;
    try {
      const id = await state.net.sendText(state.openFingerprint, wrapped.body, wrapped.kind);
      appendLine("me", wrapped.body, wrapped.kind, { id, context: "chat", seen: false });
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
      showAlert("Invalid contact card.");
      return;
    }
    await sendContactRequest(parts[1], parts[2]);
  }

  // Requests a person as a contact — used by both the search results and
  // the manual "paste a contact card" fallback. Never opens a chat or
  // adds a live contact on its own: this just sends a hello (see
  // network.js's connectRelay) and marks them "pending_out" locally,
  // same as they'll see it as a request to accept or decline. If they're
  // already a mutual contact, clicking through search is just a shortcut
  // to open the existing chat instead.
  async function sendContactRequest(username, identityPubHex) {
    const identityPub = H.hexToBytes(identityPubHex);
    const fp = await H.fingerprint(state.identity.publicBytes, identityPub);
    el("user-search-input").value = "";
    el("user-search-results").classList.add("hide");
    const existing = state.peers.get(fp);
    if (existing && existing.status === "accepted") {
      switchSidebarTab("chats");
      await openChat(fp);
      return;
    }
    if (existing && existing.status === "pending_out") {
      showAlert(`Already waiting on ${username} to accept.`);
      return;
    }
    await state.store.upsertContact(fp, username, identityPubHex, undefined, "pending_out");
    state.peers.set(fp, { username, identityPubHex, status: "pending_out" });
    refreshPeerList();
    try {
      await state.net.connectRelay(identityPub, username);
      showAlert(`Request sent to ${username}. You'll be able to message once they accept.`);
    } catch (e) {
      console.error("send contact request failed:", e);
      showAlert("Could not reach the relay to send the request: " + e.message);
    }
  }

  let userSearchDebounce = null;
  function onUserSearchInput() {
    clearTimeout(userSearchDebounce);
    const query = el("user-search-input").value.trim();
    if (!query) {
      el("user-search-results").classList.add("hide");
      return;
    }
    userSearchDebounce = setTimeout(() => doUserSearch(query), 300);
  }

  async function doUserSearch(query) {
    let matches;
    try {
      matches = await state.accountsClient.searchUsers(query, state.username);
    } catch (e) {
      console.error("user search failed:", e);
      matches = [];
    }
    // The box may have changed (or been cleared) while this request was
    // in flight — a stale response landing after that would otherwise
    // show results for a query that's no longer in the box.
    if (el("user-search-input").value.trim() !== query) return;
    const results = el("user-search-results");
    results.innerHTML = "";
    if (!matches.length) {
      const note = document.createElement("div");
      note.className = "user-search-note";
      note.textContent = "No one found.";
      results.appendChild(note);
    } else {
      for (const m of matches) {
        const item = document.createElement("div");
        item.className = "user-search-item";
        item.appendChild(avatarElement(m.username, null));
        const nameSpan = document.createElement("span");
        nameSpan.className = "user-search-name";
        nameSpan.textContent = m.username;
        item.appendChild(nameSpan);
        const actionSpan = document.createElement("span");
        actionSpan.className = "user-search-action";
        actionSpan.textContent = "Request";
        item.appendChild(actionSpan);
        item.onclick = () => sendContactRequest(m.username, m.identity_pub);
        results.appendChild(item);
      }
    }
    results.classList.remove("hide");
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
    el("backup-cancel").onclick = () => el("backup-overlay").classList.add("hide");
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

    el("tab-chats-btn").onclick = () => switchSidebarTab("chats");
    el("tab-requests-btn").onclick = () => switchSidebarTab("requests");
    el("tab-settings-btn").onclick = () => switchSidebarTab("settings");
    el("setting-online-status").addEventListener("change", (e) => {
      setSetting("online-status", e.target.checked);
      for (const fp of state.peers.keys()) {
        sendPresenceTo(fp).catch((err) => console.error("send presence failed:", err));
      }
    });
    el("setting-read-receipts").addEventListener("change", (e) => setSetting("read-receipts", e.target.checked));

    el("chat-menu-btn").onclick = (e) => {
      e.stopPropagation();
      const popup = el("chat-menu-popup");
      const wasHidden = popup.classList.contains("hide");
      closeAllMsgMenus();
      popup.classList.toggle("hide", !wasHidden);
    };
    el("chat-backup-btn").onclick = openBackup;
    el("chat-clear-btn").onclick = doClearChat;
    el("chat-delete-btn").onclick = doDeleteChat;
    document.addEventListener("click", (e) => {
      closeAllMsgMenus();
      el("chat-menu-popup").classList.add("hide");
      if (!el("user-search-row").contains(e.target)) el("user-search-results").classList.add("hide");
    });

    el("user-search-input").addEventListener("input", onUserSearchInput);
    el("user-search-input").addEventListener("focus", () => {
      if (el("user-search-input").value.trim()) el("user-search-results").classList.remove("hide");
    });

    el("reply-preview-cancel").onclick = clearReplyTarget;
    el("message-input").addEventListener("input", () => {
      if (el("message-input").value) maybeSendTypingPing();
    });
  });
})();
