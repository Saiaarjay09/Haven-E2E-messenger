"""Tkinter desktop UI: sign in/up, LAN contact list, and chat windows."""

from __future__ import annotations

import io
import os
import queue
import re
import shutil
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import ai, attachments, backup, calls, config, crypto, discovery, groups, identity, network, relay_client, storage

try:
    from PIL import Image, ImageSequence, ImageTk

    HAS_PIL = True
except ImportError:
    HAS_PIL = False

AVATAR_SIZE = 40
ATTACHMENT_MAX_DIM = 280  # max width/height a received image/GIF is scaled to in the chat view
STICKER_MAX_DIM = 140
URL_RE = re.compile(r"https?://\S+")


def _load_avatar_image(path, size=AVATAR_SIZE):
    if not path:
        return None
    if HAS_PIL:
        try:
            img = Image.open(path).convert("RGB").resize((size, size))
            return ImageTk.PhotoImage(img)
        except Exception:
            return None
    try:
        return tk.PhotoImage(file=str(path))
    except Exception:
        return None


# --------------------------------------------------------------------------
# Login / account creation screen
# --------------------------------------------------------------------------


class LoginScreen(ttk.Frame):
    def __init__(self, master, on_success):
        super().__init__(master, padding=24)
        self.on_success = on_success
        self.pack(fill="both", expand=True)

        ttk.Label(self, text="Haven", font=("Helvetica", 22, "bold")).pack(pady=(0, 4))
        ttk.Label(
            self, text="Local, end-to-end encrypted LAN messenger", foreground="#666"
        ).pack(pady=(0, 20))

        form = ttk.Frame(self)
        form.pack()

        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="w", pady=4)
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(form, textvariable=self.username_var, width=28)
        username_entry.grid(row=0, column=1, pady=4)

        ttk.Label(form, text="Password").grid(row=1, column=0, sticky="w", pady=4)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(form, textvariable=self.password_var, show="*", width=28)
        password_entry.grid(row=1, column=1, pady=4)

        # Enter in either field submits like a normal login form would.
        username_entry.bind("<Return>", lambda e: self._sign_in())
        password_entry.bind("<Return>", lambda e: self._sign_in())
        username_entry.focus_set()

        btns = ttk.Frame(self)
        btns.pack(pady=16)
        ttk.Button(btns, text="Sign in", command=self._sign_in).grid(row=0, column=0, padx=4)
        ttk.Button(btns, text="Create account", command=self._create).grid(
            row=0, column=1, padx=4
        )
        ttk.Button(btns, text="Restore from backup…", command=self._restore).grid(
            row=0, column=2, padx=4
        )

        existing = identity.list_accounts()
        if existing:
            ttk.Label(self, text=f"Existing local accounts: {', '.join(existing)}").pack(
                pady=(8, 0)
            )

        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, foreground="#b00").pack(pady=(12, 0))

    def _sign_in(self):
        u, p = self.username_var.get().strip(), self.password_var.get()
        if not u and not p:
            self.status_var.set("Enter a username and password. (Click into the window first — "
                                 "if you just launched Haven, the terminal may still have focus.)")
            return
        if not u:
            self.status_var.set("Enter a username.")
            return
        if not p:
            self.status_var.set("Enter a password.")
            return
        try:
            acct = identity.sign_in(u, p)
        except identity.NoSuchAccount:
            self.status_var.set("No such account on this machine. Create one instead.")
            return
        except identity.WrongPassword:
            self.status_var.set("Wrong password.")
            return
        self.on_success(acct)

    def _create(self):
        u, p = self.username_var.get().strip(), self.password_var.get()
        if not u and not p:
            self.status_var.set("Enter a username and password. (Click into the window first — "
                                 "if you just launched Haven, the terminal may still have focus.)")
            return
        if not u:
            self.status_var.set("Enter a username.")
            return
        if not p:
            self.status_var.set("Enter a password.")
            return
        if len(p) < 6:
            self.status_var.set("Use a password of at least 6 characters.")
            return
        try:
            acct = identity.create_account(u, p)
        except identity.AccountExists:
            self.status_var.set("That username already exists on this machine. Sign in instead.")
            return
        self.on_success(acct)

    def _restore(self):
        path = filedialog.askopenfilename(
            title="Select a Haven backup file", filetypes=[("Haven backup", "*.havenbackup *.*")]
        )
        if not path:
            return
        pw = simpledialog.askstring("Backup password", "Password for this backup:", show="*")
        if pw is None:
            return
        try:
            bundle = backup.restore_backup(path, pw)
        except backup.RestoreFailed as exc:
            self.status_var.set(str(exc))
            return
        new_pw = simpledialog.askstring(
            "Set local password",
            f"Restoring '{bundle['username']}'. Set a local sign-in password:",
            show="*",
        )
        if not new_pw:
            return
        acct = backup.apply_restored_bundle(bundle, new_pw)
        messagebox.showinfo("Restored", f"Account '{acct.username}' restored. Sign in now.")


# --------------------------------------------------------------------------
# Main chat application
# --------------------------------------------------------------------------


class ChatApp(ttk.Frame):
    def __init__(self, master, account: identity.Account):
        super().__init__(master)
        self.account = account
        self.pack(fill="both", expand=True)

        self.store = storage.Store(account.data_dir, account.identity)
        self.net = network.NetworkManager(account.identity, account.username, self.store)
        self.net.on_message = self._on_message_threaded
        self.net.on_status = self._on_status_threaded
        self.net.on_connect = self._on_connect_threaded
        port = self.net.start_server()

        self.disc = discovery.Discovery(account.username, account.identity.public_bytes, port)
        self.disc.start()

        self.event_queue: "queue.Queue" = queue.Queue()
        self.open_fingerprint: str | None = None
        self.open_group_id: str | None = None
        self.peer_meta: dict[str, dict] = {}  # fingerprint -> {username, host, tcp_port, identity_pub, relay_key}
        self.pending_sends: dict[str, list[tuple[str, str]]] = {}  # fp -> [(text, kind), ...]
        self._link_counter = 0
        self.relays: dict[str, relay_client.RelayClient] = {}  # relay_key ("host:port") -> client
        self.relay_connected: dict[str, bool] = {}  # relay_key -> is currently connected
        self.relay_status_var = tk.StringVar(value="Relays: none configured")

        self.group_mgr = groups.GroupManager(
            self.net, self.store, account.identity, account.username, resolve_route=self._resolve_route
        )
        self.group_mgr.on_group_message = self._on_group_message_threaded
        self.group_mgr.on_group_update = self._on_group_update_threaded

        self.call_mgr = calls.CallManager(self.net, account.identity, account.username)
        self.call_mgr.on_incoming_call = self._on_incoming_call_threaded
        self.call_mgr.on_call_state = self._on_call_state_threaded
        self.call_mgr.on_call_error = self._on_call_error_threaded
        self.call_mgr.on_remote_video_frame = self._on_remote_video_frame_threaded
        self.call_mgr.on_local_video_frame = self._on_local_video_frame_threaded
        self.call_windows: dict[str, tk.Toplevel] = {}  # fingerprint -> active call window
        self.call_started_at: dict[str, float] = {}

        ai_cfg = config.load(account.data_dir)
        self.assistant = ai.LocalAssistant(ai_cfg.get("ai_model_path"))
        self.translate_target_lang = ai_cfg.get("translate_target_lang")
        self.transcriber = ai.Transcriber()
        self.captioner = ai.LiveCallCaptioner(self.transcriber, self.translate_target_lang)
        self.captioner.on_caption = self._on_caption_threaded
        self.call_mgr.on_remote_audio_chunk = self._on_remote_audio_chunk_threaded
        self.captions_enabled_for: set[str] = set()

        self._build_layout()
        self._refresh_contacts()
        self._maybe_start_relay()
        self.after(200, self._poll_events)
        self.after(1000, self._refresh_peer_list)

    def _resolve_route(self, identity_pub_hex: str) -> dict | None:
        for meta in self.peer_meta.values():
            if meta.get("identity_pub") == identity_pub_hex:
                return {
                    "host": meta.get("host"),
                    "tcp_port": meta.get("tcp_port"),
                    "relay_key": meta.get("relay_key"),
                }
        return None

    # -- relays (Phase 2, multi-relay) -----------------------------------------

    def _maybe_start_relay(self):
        for key, entry in config.list_relays(self.account.data_dir).items():
            self._start_relay(key, entry["name"], entry["host"], entry["port"])

    def _start_relay(self, key: str, name: str, host: str, port: int):
        existing = self.relays.get(key)
        if existing is not None:
            existing.stop()
        client = relay_client.RelayClient(self.account.identity, self.account.username, host, port)
        client.on_connection_change = lambda connected: self._on_relay_connection_threaded(key, connected)
        self.relays[key] = client
        self.relay_connected[key] = False
        self.net.attach_relay(key, client)
        client.start()
        self._update_relay_status_var()

    def _stop_relay(self, key: str):
        client = self.relays.pop(key, None)
        self.relay_connected.pop(key, None)
        self.net.detach_relay(key)
        if client is not None:
            client.stop()
        self._update_relay_status_var()

    def _update_relay_status_var(self):
        if not self.relays:
            self.relay_status_var.set("Relays: none configured")
            return
        connected = sum(1 for v in self.relay_connected.values() if v)
        self.relay_status_var.set(f"Relays: {connected}/{len(self.relays)} connected")

    def _on_relay_connection_threaded(self, relay_key: str, connected: bool):
        self.event_queue.put(("relay_status", relay_key, connected))

    def _relay_settings(self):
        """'Manage relays…' — you can configure several self-hosted relays
        (e.g. one your family uses, one a different friend group runs) and
        each contact remembers which one reaches them (see 'Assign
        relay…' on a contact, or embed one in your contact card)."""
        top = tk.Toplevel(self)
        top.title("Manage relays")
        ttk.Label(top, text="Relays this account connects to:").pack(anchor="w", padx=12, pady=(12, 4))

        listbox = tk.Listbox(top, width=50, height=6)
        listbox.pack(padx=12, fill="both", expand=True)
        keys = []

        def refresh_list():
            listbox.delete(0, "end")
            keys.clear()
            for key, entry in config.list_relays(self.account.data_dir).items():
                status = "connected" if self.relay_connected.get(key) else "reconnecting…"
                listbox.insert("end", f"{entry['name']}  ({key})  — {status}")
                keys.append(key)

        refresh_list()

        def do_add():
            name = simpledialog.askstring("Add relay", "A name for this relay (e.g. 'Home relay'):", parent=top)
            if not name:
                return
            host = simpledialog.askstring(
                "Add relay", "Relay host (the machine it's running on):", parent=top
            )
            if not host:
                return
            port_str = simpledialog.askstring("Add relay", "Relay port:", initialvalue="8443", parent=top)
            if not port_str:
                return
            try:
                port = int(port_str)
            except ValueError:
                messagebox.showerror("Invalid port", "Port must be a number.")
                return
            key = config.add_relay(self.account.data_dir, name, host, port)
            self._start_relay(key, name, host, port)
            refresh_list()

        def do_remove():
            sel = listbox.curselection()
            if not sel:
                return
            key = keys[sel[0]]
            if not messagebox.askyesno("Remove relay", "Remove this relay? Contacts assigned to it won't be reachable until you set them to a different one."):
                return
            self._stop_relay(key)
            config.remove_relay(self.account.data_dir, key)
            refresh_list()

        btns = ttk.Frame(top)
        btns.pack(pady=(4, 12))
        ttk.Button(btns, text="Add relay…", command=do_add).pack(side="left", padx=4)
        ttk.Button(btns, text="Remove selected", command=do_remove).pack(side="left", padx=4)

    def _assign_relay_to_current(self):
        """Pick which of your configured relays reaches the currently open
        DM contact — remembered persistently, same as everything else about
        a contact. A contact usually gets this automatically from a card
        that embedded a relay; this is for setting/changing it by hand."""
        fp = self.open_fingerprint
        if not fp:
            return
        relays = config.list_relays(self.account.data_dir)
        if not relays:
            messagebox.showinfo("No relays configured", "Add a relay first via 'Manage relays…'.")
            return
        meta = self.peer_meta.get(fp, {})
        names = ["(none — LAN/direct only)"] + [f"{e['name']} ({k})" for k, e in relays.items()]
        keys = [None] + list(relays.keys())
        current_idx = keys.index(meta.get("relay_key")) if meta.get("relay_key") in keys else 0

        top = tk.Toplevel(self)
        top.title(f"Assign relay for {meta.get('username', fp[:8])}")
        var = tk.StringVar(value=names[current_idx])
        ttk.Label(top, text="Reach this contact through:").pack(padx=12, pady=(12, 4), anchor="w")
        ttk.Combobox(top, textvariable=var, values=names, state="readonly", width=40).pack(padx=12, pady=(0, 8))

        def do_save():
            idx = names.index(var.get())
            key = keys[idx]
            if key:
                relay_host, relay_port = relays[key]["host"], relays[key]["port"]
            else:
                relay_host, relay_port = None, None
            self.store.set_contact_relay(fp, relay_host, relay_port)
            self.peer_meta[fp]["relay_key"] = key
            self._redraw_peer_list()
            top.destroy()

        ttk.Button(top, text="Save", command=do_save).pack(pady=(0, 12))

    def _ai_settings(self):
        cfg = config.load(self.account.data_dir)
        top = tk.Toplevel(self)
        top.title("AI settings")
        ttk.Label(
            top,
            text="Everything below runs entirely on this device. Nothing is ever\n"
            "sent to a cloud service — model files just need a one-time\n"
            "download, the same as installing any offline app feature.",
            justify="left",
        ).pack(padx=12, pady=(12, 8), anchor="w")

        form = ttk.Frame(top)
        form.pack(padx=12, pady=4, fill="x")

        ttk.Label(form, text="Local AI model (.gguf):").grid(row=0, column=0, sticky="w")
        model_var = tk.StringVar(value=cfg.get("ai_model_path", ""))
        ttk.Entry(form, textvariable=model_var, width=42).grid(row=1, column=0, columnspan=2, sticky="we", pady=(2, 6))

        def browse_model():
            path = filedialog.askopenfilename(title="Choose a .gguf model file", filetypes=[("GGUF models", "*.gguf")])
            if path:
                model_var.set(path)

        ttk.Button(form, text="Browse…", command=browse_model).grid(row=0, column=1, sticky="e")

        progress_var = tk.DoubleVar(value=0.0)
        progress = ttk.Progressbar(form, variable=progress_var, maximum=1.0)

        def do_download():
            dest = self.account.data_dir / "ai_model.gguf"
            if not messagebox.askyesno(
                "Download model",
                f"Download a small (~{ai.DEFAULT_MODEL_SIZE_MB} MB) local AI model now? "
                "This needs an internet connection for this one-time download only.",
            ):
                return
            progress.grid(row=2, column=0, columnspan=2, sticky="we", pady=4)
            progress_q: "queue.Queue" = queue.Queue()

            def bg():
                try:
                    ai.download_default_model(str(dest), on_progress=lambda f: progress_q.put(f))
                    progress_q.put("done")
                except Exception as exc:
                    progress_q.put(("error", str(exc)))

            threading.Thread(target=bg, daemon=True).start()

            def poll():
                try:
                    while True:
                        item = progress_q.get_nowait()
                        if item == "done":
                            model_var.set(str(dest))
                            messagebox.showinfo("Downloaded", "Model downloaded. Click Save to use it.")
                            return
                        if isinstance(item, tuple) and item[0] == "error":
                            messagebox.showerror("Download failed", item[1])
                            return
                        progress_var.set(item)
                except queue.Empty:
                    pass
                top.after(200, poll)

            top.after(200, poll)

        ttk.Button(form, text="Download a small model…", command=do_download).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(4, 8)
        )

        ttk.Label(form, text="Translate live call captions to:").grid(row=4, column=0, sticky="w", pady=(8, 0))
        lang_var = tk.StringVar(value=cfg.get("translate_target_lang", ""))
        lang_choices = ["", "es", "fr", "de", "hi", "zh", "ja", "ko", "ar", "pt", "ru", "it"]
        ttk.Combobox(form, textvariable=lang_var, values=lang_choices, width=10).grid(
            row=5, column=0, sticky="w", pady=(2, 8)
        )
        ttk.Label(form, text="(ISO code, e.g. 'es' for Spanish; blank disables captions)", foreground="#666").grid(
            row=6, column=0, columnspan=2, sticky="w"
        )

        def do_save():
            config.save(
                self.account.data_dir,
                {"ai_model_path": model_var.get().strip(), "translate_target_lang": lang_var.get().strip()},
            )
            self.assistant = ai.LocalAssistant(model_var.get().strip() or None)
            self.translate_target_lang = lang_var.get().strip() or None
            self.captioner.target_lang = self.translate_target_lang
            top.destroy()

        ttk.Button(top, text="Save", command=do_save).pack(pady=(4, 12))

    def _show_contact_card(self):
        relays = config.list_relays(self.account.data_dir)
        top = tk.Toplevel(self)
        top.title("My contact card")

        relay_names = ["(no relay)"] + [f"{e['name']} ({k})" for k, e in relays.items()]
        relay_keys = [None] + list(relays.keys())
        relay_var = tk.StringVar(value=relay_names[0])

        entry = ttk.Entry(top, width=60)

        def rebuild_card():
            idx = relay_names.index(relay_var.get())
            key = relay_keys[idx]
            if key:
                entry_host, entry_port = relays[key]["host"], relays[key]["port"]
                card = identity.make_contact_card(self.account, entry_host, entry_port)
            else:
                card = identity.make_contact_card(self.account)
            entry.configure(state="normal")
            entry.delete(0, "end")
            entry.insert(0, card)
            entry.configure(state="readonly")
            entry.selection_range(0, "end")

        ttk.Label(
            top,
            text="Share this with a friend (over any existing app) so they can add you\n"
            "even when you're not on the same Wi-Fi/LAN:",
        ).pack(padx=12, pady=(12, 6))

        if relays:
            ttk.Label(top, text="Include a relay so they auto-connect through it:").pack(anchor="w", padx=12)
            ttk.Combobox(top, textvariable=relay_var, values=relay_names, state="readonly", width=40).pack(
                padx=12, pady=(2, 8)
            )
            relay_var.trace_add("write", lambda *a: rebuild_card())

        entry.pack(padx=12, pady=(0, 12))
        rebuild_card()

    def _add_contact_by_card(self):
        card = simpledialog.askstring("Add contact", "Paste their contact card:")
        if not card:
            return
        try:
            username, identity_pub, relay_host, relay_port = identity.parse_contact_card(card)
        except identity.InvalidContactCard as exc:
            messagebox.showerror("Invalid card", str(exc))
            return
        fp = crypto.fingerprint(self.account.identity.public_bytes, identity_pub)
        relay_key = None
        if relay_host and relay_port:
            relay_key = config.relay_key(relay_host, relay_port)
            if relay_key not in config.list_relays(self.account.data_dir):
                if messagebox.askyesno(
                    "Add their relay too?",
                    f"This card includes a relay ({relay_host}:{relay_port}) you don't have configured yet. "
                    "Add and connect to it now so you can reach them?",
                ):
                    config.add_relay(self.account.data_dir, f"{username}'s relay", relay_host, relay_port)
                    self._start_relay(relay_key, f"{username}'s relay", relay_host, relay_port)
                else:
                    relay_key = None
        self.store.upsert_contact(fp, username, identity_pub, "", 0, relay_host, relay_port)
        self.peer_meta[fp] = {
            "username": username,
            "host": "",
            "tcp_port": 0,
            "verified": False,
            "known": True,
            "identity_pub": identity_pub.hex(),
            "relay_key": relay_key,
        }
        self._redraw_peer_list()
        messagebox.showinfo(
            "Contact added",
            f"Added {username}. They'll show up as reachable once you're both online "
            "(same LAN, or both connected to their assigned relay).",
        )

    # -- layout ------------------------------------------------------------

    def _build_layout(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text=f"Signed in as {self.account.username}", font=("Helvetica", 12, "bold")).pack(
            side="left"
        )
        ttk.Label(top, textvariable=self.relay_status_var, foreground="#666").pack(side="left", padx=(16, 0))

        ttk.Button(top, text="My safety number", command=self._show_my_fingerprint).pack(
            side="right", padx=2
        )
        ttk.Button(top, text="Set avatar…", command=self._set_avatar).pack(side="right", padx=2)
        ttk.Button(top, text="Export backup…", command=self._export_backup).pack(
            side="right", padx=2
        )
        ttk.Button(top, text="Manage relays…", command=self._relay_settings).pack(side="right", padx=2)
        ttk.Button(top, text="Add contact…", command=self._add_contact_by_card).pack(side="right", padx=2)
        ttk.Button(top, text="My contact card", command=self._show_contact_card).pack(side="right", padx=2)
        ttk.Button(top, text="Create group…", command=self._create_group).pack(side="right", padx=2)
        ttk.Button(top, text="AI settings…", command=self._ai_settings).pack(side="right", padx=2)

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        left = ttk.Frame(body, width=220)
        body.add(left, weight=1)
        ttk.Label(left, text="Nearby & contacts", font=("Helvetica", 10, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        self.peer_list = tk.Listbox(left, activestyle="none")
        self.peer_list.pack(fill="both", expand=True)
        self.peer_list.bind("<<ListboxSelect>>", self._on_select_peer)
        self._peer_rows: list[dict] = []

        right = ttk.Frame(body)
        body.add(right, weight=3)

        header = ttk.Frame(right)
        header.pack(fill="x")
        self.chat_title_var = tk.StringVar(value="Select a contact to start chatting")
        ttk.Label(header, textvariable=self.chat_title_var, font=("Helvetica", 11, "bold")).pack(
            side="left"
        )
        self.verify_btn = ttk.Button(
            header, text="Verify safety number…", command=self._verify_current, state="disabled"
        )
        self.verify_btn.pack(side="right")
        self.manage_members_btn = ttk.Button(
            header, text="Manage members…", command=self._manage_members, state="disabled"
        )
        self.manage_members_btn.pack(side="right", padx=(0, 4))
        self.video_call_btn = ttk.Button(
            header, text="🎥 Video call", command=lambda: self._start_call(video=True), state="disabled"
        )
        self.video_call_btn.pack(side="right", padx=(0, 4))
        self.audio_call_btn = ttk.Button(
            header, text="📞 Call", command=lambda: self._start_call(video=False), state="disabled"
        )
        self.audio_call_btn.pack(side="right", padx=(0, 4))
        self.assign_relay_btn = ttk.Button(
            header, text="Assign relay…", command=self._assign_relay_to_current, state="disabled"
        )
        self.assign_relay_btn.pack(side="right", padx=(0, 4))

        self.chat_text = tk.Text(right, state="disabled", wrap="word", height=20)
        self.chat_text.pack(fill="both", expand=True, pady=6)
        self.chat_text.tag_configure("me", foreground="#0a5")
        self.chat_text.tag_configure("them", foreground="#05a")
        self.chat_text.tag_configure("sys", foreground="#888", font=("Helvetica", 9, "italic"))
        self.chat_text.tag_configure("link", foreground="#06c", underline=True)

        entry_row = ttk.Frame(right)
        entry_row.pack(fill="x")
        self.entry_var = tk.StringVar()
        entry = ttk.Entry(entry_row, textvariable=self.entry_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self._send())
        ttk.Button(entry_row, text="Send", command=self._send).pack(side="left", padx=4)
        ttk.Button(entry_row, text="🖼 Image/GIF…", command=self._send_image_dialog).pack(side="left", padx=2)
        ttk.Button(entry_row, text="😀 Stickers…", command=self._open_sticker_picker).pack(side="left", padx=2)

    # -- contacts / discovery -----------------------------------------------

    def _refresh_contacts(self):
        for row in self.store.list_contacts():
            relay_key = None
            if row["relay_host"] and row["relay_port"]:
                relay_key = config.relay_key(row["relay_host"], row["relay_port"])
            self.peer_meta[row["fingerprint"]] = {
                "username": row["username"],
                "host": row["host"],
                "tcp_port": row["port"],
                "verified": bool(row["verified"]),
                "known": True,
                "identity_pub": row["identity_pub"].hex(),
                "relay_key": relay_key,
            }
        self._redraw_peer_list()

    def _refresh_peer_list(self):
        for p in self.disc.snapshot():
            fp = crypto.fingerprint(self.account.identity.public_bytes, bytes.fromhex(p["identity_pub"]))
            existing = self.peer_meta.get(fp, {})
            self.peer_meta[fp] = {
                "username": p["username"],
                "host": p["host"],
                "tcp_port": p["tcp_port"],
                "verified": existing.get("verified", False),
                "known": True,
                "online": True,
                "identity_pub": p["identity_pub"],
            }
        self._redraw_peer_list()
        self.after(2000, self._refresh_peer_list)

    def _selected_row_key(self, row: dict):
        return ("group", row["group_id"]) if row.get("is_group") else ("dm", row["fingerprint"])

    def _redraw_peer_list(self):
        selected_key = None
        sel = self.peer_list.curselection()
        if sel:
            selected_key = self._selected_row_key(self._peer_rows[sel[0]])

        self.peer_list.delete(0, "end")
        self._peer_rows = []
        for fp, meta in sorted(self.peer_meta.items(), key=lambda kv: kv[1]["username"].lower()):
            online = self.net.is_connected(fp) or meta.get("online")
            badge = "✓" if meta.get("verified") else "?"
            status = "online" if online else "offline"
            label = f"[{badge}] {meta['username']}  ({status})"
            self.peer_list.insert("end", label)
            row = {"fingerprint": fp, "is_group": False, **meta}
            self._peer_rows.append(row)
            if self._selected_row_key(row) == selected_key:
                self.peer_list.selection_set(len(self._peer_rows) - 1)

        for info in sorted(self.group_mgr.list_groups(), key=lambda g: g["name"].lower()):
            status = "removed" if info["removed"] else f"{len(info['members'])} members"
            label = f"# {info['name']}  ({status})"
            self.peer_list.insert("end", label)
            row = {"is_group": True, "group_id": info["group_id"], "username": info["name"]}
            self._peer_rows.append(row)
            if self._selected_row_key(row) == selected_key:
                self.peer_list.selection_set(len(self._peer_rows) - 1)

    def _on_select_peer(self, _event):
        sel = self.peer_list.curselection()
        if not sel:
            return
        row = self._peer_rows[sel[0]]
        if row.get("is_group"):
            self._open_group(row["group_id"])
        else:
            self._open_chat(row["fingerprint"])

    # -- chat ---------------------------------------------------------------

    def _open_chat(self, fingerprint: str):
        self.open_fingerprint = fingerprint
        self.open_group_id = None
        meta = self.peer_meta[fingerprint]
        self.chat_title_var.set(f"{meta['username']}  —  {fingerprint}")
        self.verify_btn.configure(state="normal")
        self.manage_members_btn.configure(state="disabled")
        self.audio_call_btn.configure(state="normal")
        self.video_call_btn.configure(state="normal")
        self.assign_relay_btn.configure(state="normal")

        self.chat_text.configure(state="normal")
        self.chat_text.delete("1.0", "end")
        # "group" kind rows are group-protocol control traffic that happens
        # to ride over this same 1:1 channel (see groups.py) — not part of
        # this contact's own conversation with you, so they're filtered out
        # of the DM view the same way you wouldn't want to see raw TCP
        # handshake bytes in a chat window.
        for m in self.store.history(fingerprint):
            if m["kind"] == "group":
                continue
            self._render_history_row(m["direction"], m["kind"], m["text"], m["ts"])
        self.chat_text.configure(state="disabled")

        if not self.net.is_connected(fingerprint):
            self._attempt_connect(fingerprint)

    def _attempt_connect(self, fingerprint: str):
        """Try direct LAN first if we have a live address for this contact;
        otherwise fall back to whichever relay THIS contact is assigned to
        (from their contact card, or set via 'Assign relay…'). Safe to call
        repeatedly — connect_to_peer/connect_relay both no-op if already
        connected or already mid-handshake."""
        meta = self.peer_meta.get(fingerprint, {})
        if meta.get("host") and meta.get("tcp_port"):
            threading.Thread(
                target=self._connect_direct_bg,
                args=(fingerprint, meta["host"], meta["tcp_port"]),
                daemon=True,
            ).start()
            return
        relay_key = meta.get("relay_key")
        relay = self.relays.get(relay_key) if relay_key else None
        if meta.get("identity_pub") and relay is not None and relay.connected.is_set():
            try:
                self.net.connect_relay(bytes.fromhex(meta["identity_pub"]), meta.get("username", ""), relay_key=relay_key)
            except ConnectionError as exc:
                self.event_queue.put(("sys", fingerprint, f"Could not reach relay: {exc}"))
            return
        if meta.get("identity_pub") and relay_key and relay is None:
            self.event_queue.put(
                ("sys", fingerprint, f"This contact's relay ({relay_key}) isn't configured on this account.")
            )
            return
        if meta.get("identity_pub") and not relay_key and self.relays:
            self.event_queue.put(
                ("sys", fingerprint, "No relay assigned to this contact yet — use 'Assign relay…' to pick one.")
            )
            return
        self.event_queue.put(
            ("sys", fingerprint, "No route to this contact yet (not on your LAN, and no relay connected).")
        )

    def _connect_direct_bg(self, expected_fp, host, port):
        try:
            fp = self.net.connect_to_peer(host, port)
            if fp != expected_fp:
                self.event_queue.put(("sys", expected_fp, "Warning: peer identity changed — re-verify!"))
        except (ConnectionError, OSError) as exc:
            self.event_queue.put(("sys", expected_fp, f"Could not connect directly: {exc}"))

    def _append_line(self, direction_or_tag: str, text: str, ts: float, who_override: str | None = None):
        tag = {"out": "me", "in": "them", "sys": "sys"}.get(direction_or_tag, "them")
        who = who_override or {
            "out": "you",
            "in": self.peer_meta.get(self.open_fingerprint, {}).get("username", "them"),
        }.get(direction_or_tag, "*")
        stamp = time.strftime("%H:%M", time.localtime(ts))
        self.chat_text.configure(state="normal")
        self.chat_text.insert("end", f"[{stamp}] {who}: ", tag)
        self._insert_with_links(text, tag)
        self.chat_text.insert("end", "\n")
        self.chat_text.see("end")
        self.chat_text.configure(state="disabled")

    def _insert_with_links(self, text: str, base_tag: str):
        """Makes http(s) URLs in a line clickable — opened in the system's
        default browser via webbrowser.open, never fetched by Haven itself.
        No automatic link-preview fetching: this app's whole point is not
        leaking your activity to third parties, and fetching a URL just
        because it appeared in a chat would quietly tell whoever runs that
        site that you (or at least someone on your relay) opened this
        conversation. A future opt-in 'load preview' button is a
        reasonable addition; auto-fetch is not (see ROADMAP.md)."""
        pos = 0
        for m in URL_RE.finditer(text):
            if m.start() > pos:
                self.chat_text.insert("end", text[pos : m.start()], base_tag)
            url = m.group(0)
            link_tag = f"link_{self._link_counter}"
            self._link_counter += 1
            self.chat_text.insert("end", url, (base_tag, "link", link_tag))
            self.chat_text.tag_bind(link_tag, "<Button-1>", lambda e, u=url: webbrowser.open(u))
            self.chat_text.tag_bind(link_tag, "<Enter>", lambda e: self.chat_text.configure(cursor="hand2"))
            self.chat_text.tag_bind(link_tag, "<Leave>", lambda e: self.chat_text.configure(cursor=""))
            pos = m.end()
        if pos < len(text):
            self.chat_text.insert("end", text[pos:], base_tag)

    def _render_history_row(self, direction: str, kind: str, text: str, ts: float, who_override: str | None = None):
        if kind == "text":
            self._append_line(direction, text, ts, who_override=who_override)
        else:
            self._append_attachment(direction, kind, text, ts, who_override=who_override)

    def _append_attachment(self, direction: str, kind: str, payload_json: str, ts: float, who_override: str | None = None):
        tag = "me" if direction == "out" else "them"
        who = who_override or {
            "out": "you",
            "in": self.peer_meta.get(self.open_fingerprint, {}).get("username", "them"),
        }.get(direction, "*")
        stamp = time.strftime("%H:%M", time.localtime(ts))
        label = {"image": "sent an image", "gif": "sent a GIF", "sticker": "sent a sticker"}.get(kind, f"sent a {kind}")

        self.chat_text.configure(state="normal")
        self.chat_text.insert("end", f"[{stamp}] {who} {label}:\n", tag)

        if not HAS_PIL:
            self.chat_text.insert("end", "(install Pillow to preview images/GIFs)\n", "sys")
            self.chat_text.configure(state="disabled")
            return
        try:
            att = attachments.decode_attachment(payload_json)
            max_dim = STICKER_MAX_DIM if kind == "sticker" else ATTACHMENT_MAX_DIM
            if kind == "gif":
                widget = self._make_animated_gif_widget(att["data"], max_dim)
            else:
                widget = self._make_static_image_widget(att["data"], max_dim)
            self.chat_text.window_create("end", window=widget)
            self.chat_text.insert("end", "\n")
        except Exception as exc:
            self.chat_text.insert("end", f"(couldn't display attachment: {exc})\n", "sys")
        self.chat_text.see("end")
        self.chat_text.configure(state="disabled")

    def _scaled_size(self, w: int, h: int, max_dim: int) -> tuple[int, int]:
        if w <= max_dim and h <= max_dim:
            return w, h
        ratio = min(max_dim / w, max_dim / h)
        return max(1, int(w * ratio)), max(1, int(h * ratio))

    def _make_static_image_widget(self, data: bytes, max_dim: int) -> tk.Label:
        img = Image.open(io.BytesIO(data)).convert("RGBA")
        img = img.resize(self._scaled_size(*img.size, max_dim))
        photo = ImageTk.PhotoImage(img)
        label = tk.Label(self.chat_text, image=photo, borderwidth=0)
        label.image = photo  # keep a reference — Tk drops the pixels otherwise
        return label

    def _make_animated_gif_widget(self, data: bytes, max_dim: int) -> tk.Label:
        img = Image.open(io.BytesIO(data))
        frames = []
        durations = []
        for frame in ImageSequence.Iterator(img):
            resized = frame.convert("RGBA").resize(self._scaled_size(*frame.size, max_dim))
            frames.append(ImageTk.PhotoImage(resized))
            durations.append(max(frame.info.get("duration", 100), 20))
        label = tk.Label(self.chat_text, image=frames[0], borderwidth=0)
        label.frames = frames  # keep references alive

        def animate(i=0):
            if not label.winfo_exists():
                return  # chat was cleared/redrawn — stop this animation loop
            label.configure(image=frames[i])
            label.after(durations[i], animate, (i + 1) % len(frames))

        if len(frames) > 1:
            label.after(durations[0], animate, 1)
        return label

    def _send(self):
        text = self.entry_var.get().strip()
        if not text:
            return
        self.entry_var.set("")
        if text.startswith("/ai "):
            self._handle_ai_command(text[len("/ai "):].strip())
            return
        self._send_content(text, "text")

    def _handle_ai_command(self, question: str):
        """A local-only assistant query: the question and answer never
        leave this device or become part of any conversation history —
        they're not sent to whoever you're chatting with, and not stored
        anywhere, unless you copy the answer into a message yourself."""
        if not question:
            return
        if not self.assistant.available():
            self._append_line("sys", "No local AI model configured. Open 'AI settings…' to set one up.", time.time())
            return
        self._append_line("sys", f"(asking local AI — not sent to anyone: {question})", time.time())
        threading.Thread(target=self._run_ai_query, args=(question,), daemon=True).start()

    def _run_ai_query(self, question: str):
        try:
            answer = self.assistant.ask(question)
        except Exception as exc:
            answer = f"(AI error: {exc})"
        self.event_queue.put(("ai_answer", None, answer))

    def _send_content(self, text: str, kind: str):
        """Shared by the typed-text entry box and the image/GIF/sticker
        pickers — everything from here down treats an attachment as just
        another kind of message content on the same encrypted channel."""
        if self.open_group_id:
            self.group_mgr.send_group_message(self.open_group_id, text, kind=kind)
            self._render_sent_content(kind, text, who_override="you")
            return

        fp = self.open_fingerprint
        if not fp:
            return

        if self.net.is_connected(fp):
            self.net.send_text(fp, text, kind=kind)
            self._render_sent_content(kind, text)
            return

        # No session yet: queue it, (re)start a connection attempt, and
        # keep retrying for a few seconds — covers the normal case where a
        # relay handshake takes a moment to complete.
        first_in_queue = not self.pending_sends.get(fp)
        self.pending_sends.setdefault(fp, []).append((text, kind))
        if kind == "text":
            self._append_line("out", text + "  (sending…)", time.time())
        else:
            self._append_line("sys", f"sending {kind}…", time.time())
        if first_in_queue:
            self._attempt_connect(fp)
            self.after(300, lambda: self._flush_pending(fp, attempts_left=20))

    def _render_sent_content(self, kind: str, text: str, who_override: str | None = None):
        if kind == "text":
            self._append_line("out", text, time.time(), who_override=who_override)
        else:
            self._append_attachment("out", kind, text, time.time(), who_override=who_override)

    # -- images, GIFs, stickers (Phase 4) --------------------------------------

    def _send_image_dialog(self):
        if not (self.open_group_id or self.open_fingerprint):
            messagebox.showinfo("No chat open", "Open a contact or group chat first.")
            return
        path = filedialog.askopenfilename(
            title="Choose an image or GIF",
            filetypes=[("Images and GIFs", "*.png *.jpg *.jpeg *.gif *.bmp *.webp")],
        )
        if not path:
            return
        try:
            payload = attachments.encode_attachment(path)
        except attachments.AttachmentTooLarge as exc:
            messagebox.showerror("Too large", str(exc))
            return
        self._send_content(payload, attachments.guess_kind(path))

    def _sticker_dir(self):
        d = self.account.data_dir / "stickers"
        d.mkdir(exist_ok=True)
        return d

    def _open_sticker_picker(self):
        if not (self.open_group_id or self.open_fingerprint):
            messagebox.showinfo("No chat open", "Open a contact or group chat first.")
            return
        sticker_dir = self._sticker_dir()
        files = sorted(
            p for p in sticker_dir.iterdir() if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".webp")
        )

        top = tk.Toplevel(self)
        top.title("Stickers")
        grid = ttk.Frame(top)
        grid.pack(padx=8, pady=8)
        # Tk drops a PhotoImage's pixels once nothing references it, so these
        # thumbnails need a place to live for as long as this picker is open.
        thumb_refs = []

        def send_sticker(path):
            try:
                payload = attachments.encode_attachment(str(path))
            except attachments.AttachmentTooLarge as exc:
                messagebox.showerror("Too large", str(exc))
                return
            self._send_content(payload, "sticker")

        if not files:
            ttk.Label(grid, text="No stickers yet — add one below.").grid(row=0, column=0, padx=8, pady=8)
        elif not HAS_PIL:
            ttk.Label(grid, text="Install Pillow to preview stickers.").grid(row=0, column=0, padx=8, pady=8)
        else:
            cols = 4
            for i, path in enumerate(files):
                try:
                    img = Image.open(path).convert("RGBA")
                    img.thumbnail((72, 72))
                    photo = ImageTk.PhotoImage(img)
                except (OSError, ValueError):
                    continue
                thumb_refs.append(photo)
                btn = tk.Button(grid, image=photo, command=lambda p=path: send_sticker(p), borderwidth=1)
                btn.grid(row=i // cols, column=i % cols, padx=4, pady=4)

        top.thumb_refs = thumb_refs  # anchor references to the window's lifetime

        def add_sticker():
            path = filedialog.askopenfilename(
                title="Add a sticker image", filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.webp")]
            )
            if not path:
                return
            shutil.copyfile(path, sticker_dir / os.path.basename(path))
            top.destroy()
            self._open_sticker_picker()

        ttk.Button(top, text="Add sticker…", command=add_sticker).pack(pady=(0, 8))

    def _flush_pending(self, fp: str, attempts_left: int):
        queued = self.pending_sends.get(fp)
        if not queued:
            return
        if self.net.is_connected(fp):
            for text, kind in queued:
                self.net.send_text(fp, text, kind=kind)
            self.pending_sends[fp] = []
            if fp == self.open_fingerprint:
                self._redraw_current_chat()
            return
        if attempts_left <= 0:
            self.pending_sends[fp] = []
            if fp == self.open_fingerprint:
                self._append_line("sys", "Couldn't deliver — no route to this contact right now.", time.time())
            return
        self.after(300, lambda: self._flush_pending(fp, attempts_left - 1))

    def _redraw_current_chat(self):
        if self.open_group_id:
            self._open_group(self.open_group_id)
            return
        if not self.open_fingerprint:
            return
        self.chat_text.configure(state="normal")
        self.chat_text.delete("1.0", "end")
        self.chat_text.configure(state="disabled")
        for m in self.store.history(self.open_fingerprint):
            if m["kind"] == "group":
                continue
            self._render_history_row(m["direction"], m["kind"], m["text"], m["ts"])

    # -- groups (Phase 3) -----------------------------------------------------

    def _open_group(self, group_id: str):
        self.open_group_id = group_id
        self.open_fingerprint = None
        info = next((g for g in self.group_mgr.list_groups() if g["group_id"] == group_id), None)
        if info is None:
            return
        member_count = len(info["members"])
        removed_note = "  (you were removed)" if info["removed"] else ""
        self.chat_title_var.set(f"# {info['name']}  —  {member_count} members{removed_note}")
        self.verify_btn.configure(state="disabled")
        self.manage_members_btn.configure(state="disabled" if info["removed"] else "normal")
        self.audio_call_btn.configure(state="disabled")
        self.video_call_btn.configure(state="disabled")
        self.assign_relay_btn.configure(state="disabled")

        self.chat_text.configure(state="normal")
        self.chat_text.delete("1.0", "end")
        self.chat_text.configure(state="disabled")
        my_pub_hex = self.account.identity.public_bytes.hex()
        for m in self.group_mgr.group_history(group_id):
            is_me = m["sender_identity_pub"] == my_pub_hex
            username = info["members"].get(m["sender_identity_pub"], m["sender_identity_pub"][:8])
            direction = "out" if is_me else "in"
            who = "you" if is_me else username
            self._render_history_row(direction, m["kind"], m["text"], m["ts"], who_override=who)

    def _create_group(self):
        candidates = [
            (meta["username"], meta["identity_pub"])
            for meta in self.peer_meta.values()
            if meta.get("identity_pub")
        ]
        if not candidates:
            messagebox.showinfo("No contacts yet", "Add or discover at least one contact before creating a group.")
            return

        top = tk.Toplevel(self)
        top.title("Create group")
        ttk.Label(top, text="Group name:").pack(anchor="w", padx=12, pady=(12, 0))
        name_var = tk.StringVar()
        ttk.Entry(top, textvariable=name_var, width=40).pack(padx=12, pady=(0, 8))

        ttk.Label(top, text="Members (ctrl/cmd-click to select multiple):").pack(anchor="w", padx=12)
        listbox = tk.Listbox(top, selectmode="extended", height=min(10, len(candidates)))
        for uname, _pub in candidates:
            listbox.insert("end", uname)
        listbox.pack(padx=12, pady=(0, 8), fill="both", expand=True)

        def do_create():
            name = name_var.get().strip()
            selected = [candidates[i] for i in listbox.curselection()]
            if not name or not selected:
                messagebox.showwarning("Missing info", "Give the group a name and pick at least one member.")
                return
            members = [(uname, bytes.fromhex(pub_hex)) for uname, pub_hex in selected]
            group_id = self.group_mgr.create_group(name, members)
            top.destroy()
            self._redraw_peer_list()
            self._open_group(group_id)

        ttk.Button(top, text="Create", command=do_create).pack(pady=(0, 12))

    def _manage_members(self):
        if not self.open_group_id:
            return
        group_id = self.open_group_id
        info = next((g for g in self.group_mgr.list_groups() if g["group_id"] == group_id), None)
        if info is None:
            return
        my_pub_hex = self.account.identity.public_bytes.hex()

        top = tk.Toplevel(self)
        top.title(f"Members of {info['name']}")
        listbox = tk.Listbox(top, width=50, height=min(10, max(3, len(info["members"]))))
        rows = list(info["members"].items())
        for pub_hex, uname in rows:
            suffix = " (you)" if pub_hex == my_pub_hex else ""
            listbox.insert("end", f"{uname}{suffix}")
        listbox.pack(padx=12, pady=12, fill="both", expand=True)

        def do_remove():
            sel = listbox.curselection()
            if not sel:
                return
            pub_hex, uname = rows[sel[0]]
            if pub_hex == my_pub_hex:
                messagebox.showwarning("Can't remove yourself", "Leave-group isn't implemented yet — remove others instead.")
                return
            self.group_mgr.remove_member(group_id, bytes.fromhex(pub_hex))
            top.destroy()
            self._redraw_current_chat()

        def do_add():
            card = simpledialog.askstring("Add member", "Paste their contact card:", parent=top)
            if not card:
                return
            try:
                uname, pub, relay_host, relay_port = identity.parse_contact_card(card)
            except identity.InvalidContactCard as exc:
                messagebox.showerror("Invalid card", str(exc))
                return
            if relay_host and relay_port:
                relay_key = config.relay_key(relay_host, relay_port)
                if relay_key not in config.list_relays(self.account.data_dir):
                    if messagebox.askyesno(
                        "Add their relay too?",
                        f"This card includes a relay ({relay_host}:{relay_port}) you don't have configured yet. "
                        "Add and connect to it now so you can reach them?",
                    ):
                        config.add_relay(self.account.data_dir, f"{uname}'s relay", relay_host, relay_port)
                        self._start_relay(relay_key, f"{uname}'s relay", relay_host, relay_port)
                    else:
                        relay_key = None
                fp = crypto.fingerprint(self.account.identity.public_bytes, pub)
                self.store.set_contact_relay(fp, relay_host, relay_port)
                self.peer_meta.setdefault(fp, {"username": uname, "identity_pub": pub.hex(), "verified": False})
                self.peer_meta[fp]["relay_key"] = relay_key
            self.group_mgr.add_member(group_id, uname, pub)
            top.destroy()
            self._redraw_current_chat()

        btns = ttk.Frame(top)
        btns.pack(pady=(0, 12))
        ttk.Button(btns, text="Remove selected", command=do_remove).pack(side="left", padx=4)
        ttk.Button(btns, text="Add member…", command=do_add).pack(side="left", padx=4)

    # -- calls (Phase 5) -------------------------------------------------------

    def _start_call(self, video: bool):
        fp = self.open_fingerprint
        if not fp:
            return
        if not self.net.is_connected(fp):
            messagebox.showwarning("Not connected", "Connect to this contact (open their chat) before calling.")
            return
        self.call_mgr.start_call(fp, video=video)
        self._open_call_window(fp, video, ringing=True)

    def _show_incoming_call_dialog(self, fingerprint: str, call_id: str, video: bool):
        name = self.peer_meta.get(fingerprint, {}).get("username", fingerprint[:8])
        kind_label = "video call" if video else "call"
        if messagebox.askyesno("Incoming call", f"Incoming {kind_label} from {name}. Accept?"):
            self.call_mgr.accept_call(fingerprint)
            self._open_call_window(fingerprint, video, ringing=False)
        else:
            self.call_mgr.reject_call(fingerprint)

    def _open_call_window(self, fingerprint: str, video: bool, ringing: bool):
        if fingerprint in self.call_windows:
            return
        name = self.peer_meta.get(fingerprint, {}).get("username", fingerprint[:8])
        top = tk.Toplevel(self)
        top.title(f"Call with {name}")

        top.status_var = tk.StringVar(value="Calling…" if ringing else "Connected")
        ttk.Label(top, textvariable=top.status_var, font=("Helvetica", 12, "bold")).pack(pady=(12, 4))

        top.remote_label = None
        top.local_label = None
        if video:
            video_frame = ttk.Frame(top)
            video_frame.pack(pady=8)
            top.remote_label = tk.Label(video_frame, text="(waiting for their video…)", width=42, height=16, bg="#222", fg="#aaa")
            top.remote_label.grid(row=0, column=0, padx=4)
            top.local_label = tk.Label(video_frame, text="(your camera…)", width=20, height=16, bg="#222", fg="#aaa")
            top.local_label.grid(row=0, column=1, padx=4)

        btns = ttk.Frame(top)
        btns.pack(pady=12)
        muted = {"value": False}

        def toggle_mute():
            muted["value"] = not muted["value"]
            self.call_mgr.set_muted(fingerprint, muted["value"])
            mute_btn.configure(text="Unmute" if muted["value"] else "Mute")

        mute_btn = ttk.Button(btns, text="Mute", command=toggle_mute)
        mute_btn.pack(side="left", padx=4)

        captions_var = tk.BooleanVar(value=False)

        def toggle_captions():
            if captions_var.get():
                if not self.translate_target_lang:
                    messagebox.showinfo(
                        "Set a language first",
                        "Set a translation target language in AI settings before enabling captions.",
                    )
                    captions_var.set(False)
                    return
                self.captions_enabled_for.add(fingerprint)
            else:
                self.captions_enabled_for.discard(fingerprint)
                self.captioner.reset(fingerprint)
                top.caption_var.set("")

        ttk.Checkbutton(btns, text="Live captions", variable=captions_var, command=toggle_captions).pack(
            side="left", padx=4
        )
        ttk.Button(btns, text="Hang up", command=lambda: self.call_mgr.hangup(fingerprint)).pack(side="left", padx=4)
        top.protocol("WM_DELETE_WINDOW", lambda: self.call_mgr.hangup(fingerprint))

        top.caption_var = tk.StringVar(value="")
        ttk.Label(top, textvariable=top.caption_var, wraplength=380, foreground="#333", justify="left").pack(
            padx=12, pady=(0, 12)
        )

        self.call_windows[fingerprint] = top
        self._tick_call_duration(fingerprint)

    def _tick_call_duration(self, fingerprint: str):
        win = self.call_windows.get(fingerprint)
        if win is None or fingerprint not in self.call_mgr.calls:
            return
        if self.call_mgr.calls[fingerprint]["state"] == "active" and fingerprint in self.call_started_at:
            elapsed = int(time.time() - self.call_started_at[fingerprint])
            win.status_var.set(f"Connected — {elapsed // 60:02d}:{elapsed % 60:02d}")
        self.after(1000, lambda: self._tick_call_duration(fingerprint))

    def _handle_call_state(self, fingerprint: str, state: str):
        if state == "active":
            self.call_started_at[fingerprint] = time.time()
            if fingerprint not in self.call_windows:
                call = self.call_mgr.calls.get(fingerprint, {})
                self._open_call_window(fingerprint, call.get("video", False), ringing=False)
            else:
                self.call_windows[fingerprint].status_var.set("Connected")
        elif state in ("ended", "rejected"):
            self._close_call_window(fingerprint)

    def _close_call_window(self, fingerprint: str):
        win = self.call_windows.pop(fingerprint, None)
        self.call_started_at.pop(fingerprint, None)
        self.captions_enabled_for.discard(fingerprint)
        self.captioner.reset(fingerprint)
        if win is not None:
            try:
                win.destroy()
            except tk.TclError:
                pass

    def _handle_call_error(self, fingerprint: str, message: str):
        messagebox.showerror("Call error", message)

    def _update_call_video(self, fingerprint: str, which: str, jpeg_bytes: bytes):
        win = self.call_windows.get(fingerprint)
        if win is None or not HAS_PIL:
            return
        label = win.remote_label if which == "remote" else win.local_label
        if label is None:
            return
        try:
            img = Image.open(io.BytesIO(jpeg_bytes)).convert("RGB")
            photo = ImageTk.PhotoImage(img)
            label.configure(image=photo, text="")
            label.image = photo
        except (OSError, ValueError):
            pass

    # -- thread-safe network callbacks --------------------------------------

    def _on_message_threaded(self, fingerprint, kind, text, sender_identity_pub):
        if kind == "group":
            # Pure state mutation + SQLite, safe to run straight from this
            # network thread — any GUI-facing effect comes back through
            # on_group_message/on_group_update, which do go via the queue.
            self.group_mgr.handle_incoming(sender_identity_pub, text)
            return
        if kind == "call":
            # Same reasoning: handle_incoming only mutates CallManager state
            # and may spin up capture/playback threads; GUI-facing effects
            # (ring, video frame, error) come back through their own
            # threaded callbacks below, which do go via the queue.
            self.call_mgr.handle_incoming(fingerprint, text)
            return
        self.event_queue.put(("msg", fingerprint, (kind, text)))

    def _on_status_threaded(self, fingerprint, status):
        self.event_queue.put(("status", fingerprint, status))

    def _on_connect_threaded(self, conn):
        self.store.upsert_contact(conn.fingerprint, conn.username, conn.identity_pub, "", 0)
        self.event_queue.put(
            ("connect", conn.fingerprint, {"username": conn.username, "identity_pub": conn.identity_pub.hex()})
        )

    def _on_group_message_threaded(self, group_id, sender_username, text, kind):
        self.event_queue.put(("group_msg", group_id, (sender_username, text, kind)))

    def _on_group_update_threaded(self, group_id):
        self.event_queue.put(("group_update", group_id, None))

    def _on_incoming_call_threaded(self, fingerprint, call_id, video):
        self.event_queue.put(("incoming_call", fingerprint, (call_id, video)))

    def _on_call_state_threaded(self, fingerprint, state):
        self.event_queue.put(("call_state", fingerprint, state))

    def _on_call_error_threaded(self, fingerprint, message):
        self.event_queue.put(("call_error", fingerprint, message))

    def _on_remote_video_frame_threaded(self, fingerprint, jpeg_bytes):
        self.event_queue.put(("remote_video", fingerprint, jpeg_bytes))

    def _on_local_video_frame_threaded(self, fingerprint, jpeg_bytes):
        self.event_queue.put(("local_video", fingerprint, jpeg_bytes))

    def _on_remote_audio_chunk_threaded(self, fingerprint, pcm_bytes):
        # Only actually run STT/translation for calls the user opted into
        # captioning for — otherwise this would burn CPU transcribing
        # every call whether or not anyone asked for captions.
        if fingerprint in self.captions_enabled_for:
            self.captioner.feed(fingerprint, pcm_bytes)

    def _on_caption_threaded(self, fingerprint, original, translated, detected_lang):
        self.event_queue.put(("caption", fingerprint, (original, translated, detected_lang)))

    def _poll_events(self):
        try:
            while True:
                kind, fp, payload = self.event_queue.get_nowait()
                if kind == "msg":
                    if fp not in self.peer_meta:
                        self.peer_meta[fp] = {"username": fp[:8], "verified": False}
                    msg_kind, text = payload
                    if fp == self.open_fingerprint:
                        self._render_history_row("in", msg_kind, text, time.time())
                    self._redraw_peer_list()
                elif kind == "connect":
                    existing = self.peer_meta.get(fp, {})
                    existing.setdefault("username", payload["username"])
                    existing.setdefault("identity_pub", payload["identity_pub"])
                    existing["known"] = True
                    self.peer_meta[fp] = existing
                    self._redraw_peer_list()
                    self._flush_pending(fp, attempts_left=0)
                elif kind == "relay_status":
                    relay_key, connected = fp, payload
                    self.relay_connected[relay_key] = connected
                    self._update_relay_status_var()
                    self._redraw_peer_list()
                elif kind in ("status", "sys"):
                    self._redraw_peer_list()
                    if fp == self.open_fingerprint and kind == "sys":
                        self._append_line("sys", payload, time.time())
                elif kind == "group_msg":
                    group_id = fp
                    sender_username, text, msg_kind = payload
                    if group_id == self.open_group_id:
                        self._render_history_row("in", msg_kind, text, time.time(), who_override=sender_username)
                    self._redraw_peer_list()
                elif kind == "group_update":
                    group_id = fp
                    self._redraw_peer_list()
                    if group_id == self.open_group_id:
                        self._open_group(group_id)
                elif kind == "incoming_call":
                    call_id, video = payload
                    self._show_incoming_call_dialog(fp, call_id, video)
                elif kind == "call_state":
                    self._handle_call_state(fp, payload)
                elif kind == "call_error":
                    self._handle_call_error(fp, payload)
                elif kind == "remote_video":
                    self._update_call_video(fp, "remote", payload)
                elif kind == "local_video":
                    self._update_call_video(fp, "local", payload)
                elif kind == "caption":
                    original, translated, detected_lang = payload
                    win = self.call_windows.get(fp)
                    if win is not None:
                        if translated != original:
                            win.caption_var.set(f"{translated}\n(original, {detected_lang}: {original})")
                        else:
                            win.caption_var.set(original)
                elif kind == "ai_answer":
                    self._append_line("sys", f"AI: {payload}", time.time())
        except queue.Empty:
            pass
        self.after(200, self._poll_events)

    # -- safety number verification -----------------------------------------

    def _show_my_fingerprint(self):
        messagebox.showinfo(
            "Your safety number",
            f"Read this out to a friend over a call to prove your identity key "
            f"hasn't been swapped:\n\n{crypto.fingerprint(self.account.identity.public_bytes)}",
        )

    def _verify_current(self):
        if not self.open_fingerprint:
            return
        fp = self.open_fingerprint
        answer = messagebox.askyesno(
            "Verify safety number",
            f"Safety number for this chat:\n\n{fp}\n\n"
            "Read this to your contact over a voice call (or in person) and confirm "
            "it matches exactly what they see for you. Does it match?",
        )
        if answer:
            self.store.set_verified(fp, True)
            self.peer_meta[fp]["verified"] = True
            self._redraw_peer_list()
            messagebox.showinfo("Verified", "Marked as verified.")

    # -- avatar / backup ------------------------------------------------------

    def _set_avatar(self):
        path = filedialog.askopenfilename(
            title="Choose an avatar image", filetypes=[("Images", "*.png *.jpg *.jpeg *.gif")]
        )
        if path:
            self.account.set_avatar(path)
            messagebox.showinfo("Avatar set", "Your avatar has been updated locally.")

    def _export_backup(self):
        out = filedialog.asksaveasfilename(
            title="Export encrypted backup",
            defaultextension=".havenbackup",
            filetypes=[("Haven backup", "*.havenbackup")],
        )
        if not out:
            return
        pw = simpledialog.askstring(
            "Backup password",
            "Choose a password to protect this backup file.\n"
            "Note: a wrong password on restore silently yields garbage, not an error — "
            "write this password down somewhere safe.",
            show="*",
        )
        if not pw:
            return
        backup.export_backup(self.account, pw, out)
        messagebox.showinfo("Backup exported", f"Saved encrypted backup to:\n{out}")

    def shutdown(self):
        for fp in list(self.call_mgr.calls.keys()):
            self.call_mgr.hangup(fp)
        self.disc.stop()
        for client in self.relays.values():
            client.stop()
        self.net.stop()
        self.store.close()


def main():
    root = tk.Tk()
    root.title("Haven")
    root.geometry("900x600")

    # Launching a Tk app from a terminal on macOS often leaves Terminal as
    # the frontmost/focused app even though the Haven window is visible —
    # so keystrokes go nowhere near the login fields until you click into
    # the window yourself. Force focus once at startup so typing works
    # immediately, without permanently pinning the window on top.
    root.lift()
    root.attributes("-topmost", True)
    root.after(200, lambda: root.attributes("-topmost", False))
    root.focus_force()

    state = {"app": None}

    def on_login_success(account: identity.Account):
        for w in root.winfo_children():
            w.destroy()
        app = ChatApp(root, account)
        state["app"] = app

    LoginScreen(root, on_login_success)

    def on_close():
        if state["app"] is not None:
            state["app"].shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
