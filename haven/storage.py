"""Local, encrypted-at-rest chat history and contact/session state.

Two different encryption layers are at play in this app, deliberately:

  1. The ratchet cipher in crypto.py protects messages ON THE WIRE (and
     gives forward secrecy) — but ratchet keys are one-way hash chains by
     design, so once they've advanced you can no longer re-decrypt an old
     wire ciphertext. That's a feature for transit security, not something
     you want for "let me scroll up and re-read what my friend said".

  2. So on receipt (or send), we decrypt to plaintext once and re-encrypt
     it with a LOCAL storage key (AES-256-GCM, derived from your identity
     key via HKDF — never your raw password) before writing it to disk.
     This is the actual persisted "chat history" / backup material: it's
     encrypted at rest, but independent of the wire ratchet's one-way
     advancement.

Session (ratchet) state is persisted the same way so a restart doesn't
lose the ability to keep chatting with a contact.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from . import crypto


class Store:
    def __init__(self, data_dir: Path, identity: crypto.KeyPair):
        self.storage_key = crypto._hkdf(identity.private_bytes, info=b"local-storage-v1")
        self.db_path = data_dir / "haven.db"
        # Accessed from the GUI thread plus one reader thread per peer connection.
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                fingerprint TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                identity_pub BLOB NOT NULL,
                host TEXT,
                port INTEGER,
                verified INTEGER NOT NULL DEFAULT 0,
                added_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                fingerprint TEXT PRIMARY KEY,
                encrypted_state BLOB NOT NULL,
                updated_at REAL NOT NULL,
                FOREIGN KEY(fingerprint) REFERENCES contacts(fingerprint)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('in','out')),
                kind TEXT NOT NULL DEFAULT 'text',
                encrypted_body BLOB NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY(fingerprint) REFERENCES contacts(fingerprint)
            );
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                encrypted_state BLOB NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                sender_identity_pub TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'text',
                encrypted_body BLOB NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY(group_id) REFERENCES groups(group_id)
            );
            """
        )
        self.conn.commit()

    # -- contacts ----------------------------------------------------

    def upsert_contact(
        self, fingerprint: str, username: str, identity_pub: bytes, host: str, port: int
    ) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO contacts (fingerprint, username, identity_pub, host, port, verified, added_at)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    username=excluded.username,
                    host=CASE WHEN excluded.host != '' THEN excluded.host ELSE contacts.host END,
                    port=CASE WHEN excluded.port != 0 THEN excluded.port ELSE contacts.port END
                """,
                (fingerprint, username, identity_pub, host, port, time.time()),
            )
            self.conn.commit()

    def set_verified(self, fingerprint: str, verified: bool = True) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE contacts SET verified=? WHERE fingerprint=?", (int(verified), fingerprint)
            )
            self.conn.commit()

    def get_contact(self, fingerprint: str) -> sqlite3.Row | None:
        with self._lock:
            self.conn.row_factory = sqlite3.Row
            cur = self.conn.execute("SELECT * FROM contacts WHERE fingerprint=?", (fingerprint,))
            return cur.fetchone()

    def list_contacts(self) -> list[sqlite3.Row]:
        with self._lock:
            self.conn.row_factory = sqlite3.Row
            cur = self.conn.execute("SELECT * FROM contacts ORDER BY username")
            return cur.fetchall()

    # -- ratchet session state ----------------------------------------

    def save_session(self, fingerprint: str, session: crypto.RatchetSession) -> None:
        state = json.dumps(
            {
                "send_chain_key": session.send_chain_key.hex(),
                "recv_chain_key": session.recv_chain_key.hex(),
                "send_index": session.send_index,
                "recv_index": session.recv_index,
            }
        ).encode("utf-8")
        blob = crypto.encrypt_authenticated(self.storage_key, state, aad=fingerprint.encode())
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO sessions (fingerprint, encrypted_state, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET encrypted_state=excluded.encrypted_state,
                    updated_at=excluded.updated_at
                """,
                (fingerprint, blob, time.time()),
            )
            self.conn.commit()

    def load_session(self, fingerprint: str) -> crypto.RatchetSession | None:
        with self._lock:
            cur = self.conn.execute(
                "SELECT encrypted_state FROM sessions WHERE fingerprint=?", (fingerprint,)
            )
            row = cur.fetchone()
        if row is None:
            return None
        state = json.loads(
            crypto.decrypt_authenticated(self.storage_key, row[0], aad=fingerprint.encode())
        )
        return crypto.RatchetSession(
            send_chain_key=bytes.fromhex(state["send_chain_key"]),
            recv_chain_key=bytes.fromhex(state["recv_chain_key"]),
            send_index=state["send_index"],
            recv_index=state["recv_index"],
        )

    # -- messages -------------------------------------------------------

    def save_message(
        self, fingerprint: str, direction: str, plaintext: str, kind: str = "text"
    ) -> None:
        body = crypto.encrypt_authenticated(
            self.storage_key, plaintext.encode("utf-8"), aad=fingerprint.encode()
        )
        with self._lock:
            self.conn.execute(
                "INSERT INTO messages (fingerprint, direction, kind, encrypted_body, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (fingerprint, direction, kind, body, time.time()),
            )
            self.conn.commit()

    def history(self, fingerprint: str, limit: int = 500) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT direction, kind, encrypted_body, timestamp FROM messages "
                "WHERE fingerprint=? ORDER BY id ASC LIMIT ?",
                (fingerprint, limit),
            )
            rows = cur.fetchall()
        out = []
        for direction, kind, body, ts in rows:
            plaintext = crypto.decrypt_authenticated(
                self.storage_key, body, aad=fingerprint.encode()
            ).decode("utf-8")
            out.append({"direction": direction, "kind": kind, "text": plaintext, "ts": ts})
        return out

    # -- groups (Phase 3) -------------------------------------------------

    def save_group(self, group_id: str, name: str, state: dict) -> None:
        """`state` holds everything sensitive about the group (member list,
        my outgoing sender-key chain, every other member's incoming chain)
        as one JSON blob, encrypted the same way ratchet session state is —
        with the identity-derived local storage key, never the password."""
        blob = crypto.encrypt_authenticated(
            self.storage_key, json.dumps(state).encode("utf-8"), aad=group_id.encode()
        )
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO groups (group_id, name, encrypted_state, updated_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(group_id) DO UPDATE SET
                    name=excluded.name, encrypted_state=excluded.encrypted_state, updated_at=excluded.updated_at
                """,
                (group_id, name, blob, time.time()),
            )
            self.conn.commit()

    def load_group(self, group_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT encrypted_state FROM groups WHERE group_id=?", (group_id,)
            ).fetchone()
        if row is None:
            return None
        return json.loads(crypto.decrypt_authenticated(self.storage_key, row[0], aad=group_id.encode()))

    def list_groups(self) -> list[tuple[str, str]]:
        with self._lock:
            cur = self.conn.execute("SELECT group_id, name FROM groups ORDER BY name")
            return cur.fetchall()

    def save_group_message(
        self, group_id: str, sender_identity_pub_hex: str, plaintext: str, kind: str = "text"
    ) -> None:
        body = crypto.encrypt_authenticated(
            self.storage_key, plaintext.encode("utf-8"), aad=group_id.encode()
        )
        with self._lock:
            self.conn.execute(
                "INSERT INTO group_messages (group_id, sender_identity_pub, kind, encrypted_body, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (group_id, sender_identity_pub_hex, kind, body, time.time()),
            )
            self.conn.commit()

    def group_history(self, group_id: str, limit: int = 500) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT sender_identity_pub, kind, encrypted_body, timestamp FROM group_messages "
                "WHERE group_id=? ORDER BY id ASC LIMIT ?",
                (group_id, limit),
            )
            rows = cur.fetchall()
        out = []
        for sender_pub_hex, kind, body, ts in rows:
            plaintext = crypto.decrypt_authenticated(
                self.storage_key, body, aad=group_id.encode()
            ).decode("utf-8")
            out.append({"sender_identity_pub": sender_pub_hex, "kind": kind, "text": plaintext, "ts": ts})
        return out

    def close(self) -> None:
        with self._lock:
            self.conn.close()
