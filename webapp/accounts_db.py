"""Storage for the hosted accounts service.

What's stored per account, and why each field is safe to store server-side:

  * username / username_lower — plain text, needed for the global
    uniqueness guarantee and for lookups. This IS new centralized state
    the desktop app never had (no account server knows every username
    that exists there) — that centralization is the direct cost of
    "globally unique usernames" and "log in from any browser."
  * password_salt + password_auth_hash — a bcrypt hash of an auth_key the
    CLIENT derives from the user's password (see crypto.derive_split_keys
    and webapp/README.md). This proves who's logging in without the
    server ever seeing the password itself, and — critically — without
    the server ever holding the key that could decrypt anything, since
    auth_key and enc_key are cryptographically independent outputs of the
    same one-way derivation.
  * encrypted_identity_blob — ciphertext. Only decryptable with enc_key,
    which never leaves the browser. The server stores and returns it
    verbatim; it cannot read it.
  * recovery_salt / recovery_auth_hash / encrypted_identity_blob_recovery
    — the same pattern, keyed by a recovery phrase instead of a password,
    for the "forgot password" flow.
  * identity_pub — the account's public identity key, in the clear. This
    is NOT a secret: it's exactly what a contact card already hands to
    anyone (haven1:username:pubkeyhex), so storing it here to power the
    people-search feature (see search_usernames) doesn't give the server
    any capability it didn't already have — it still never sees a
    private key, a password, or plaintext messages.
  * password_kdf_n / recovery_kdf_n — the scrypt cost parameter the
    CLIENT used to derive that field's auth_key/enc_key. Not a secret
    either (it's a cost factor, not key material) — stored so a
    returning user's password still derives the SAME auth_key it always
    has, even after accounts_server.py raises the cost for new/reset
    credentials (see its SCRYPT_N_CURRENT): the server hands this value
    back at /api/login-salt and /api/recovery-salt so the client knows
    which cost to re-derive with for THIS account, rather than every
    account silently being forced onto a value that would change what
    their existing password derives to.

The contact_edges table is a genuine exception to the "server learns
nothing new" framing above: it's a deliberate, opt-in-by-use record of
WHO IS MUTUAL CONTACTS WITH WHOM (an edge is only ever written once two
accounts have actually gone through the invite/accept flow — see
webapp/static/js/network.js — never on a one-sided request), stored
only to power "people you may know" suggestions (see
suggest_mutual_friends). This is real centralized social-graph
knowledge the server did not have before and a self-hoster should
weigh that the same way as the username directory itself.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from pathlib import Path

DEFAULT_DB_PATH = "haven_accounts.db"


class UsernameTaken(Exception):
    pass


class AccountsDB:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                username_lower TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_auth_hash TEXT NOT NULL,
                encrypted_identity_blob TEXT NOT NULL,
                recovery_salt TEXT NOT NULL,
                recovery_auth_hash TEXT NOT NULL,
                encrypted_identity_blob_recovery TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            """
        )
        self.conn.commit()
        self._migrate_identity_pub_column()
        self._migrate_kdf_n_columns()
        self._migrate_contact_edges_table()

    # identity_pub is NOT a secret — it's exactly what a contact card
    # already hands to anyone (haven1:username:pubkeyhex), so storing it
    # server-side for the people-search feature doesn't weaken the
    # zero-knowledge design described in this file's docstring: it never
    # gives the server anything it couldn't already learn from a user
    # simply sharing their card. Added via migration (rather than in the
    # CREATE TABLE above) since existing deployments already have an
    # `accounts` table without this column; SQLite has no
    # "ADD COLUMN IF NOT EXISTS", so this checks first.
    def _migrate_identity_pub_column(self) -> None:
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(accounts)").fetchall()}
        if "identity_pub" not in cols:
            self.conn.execute("ALTER TABLE accounts ADD COLUMN identity_pub TEXT")
            self.conn.commit()

    # DEFAULT 32768 (2**15, crypto.SCRYPT_N_LEGACY) on both columns is
    # what makes this migration safe for accounts that already exist:
    # SQLite backfills every existing row with that default in the same
    # statement, so a returning user's password keeps deriving with the
    # SAME cost it always has, and only NEW rows (via create_account's
    # own explicit value, or a password reset) ever get the higher one.
    def _migrate_kdf_n_columns(self) -> None:
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(accounts)").fetchall()}
        if "password_kdf_n" not in cols:
            self.conn.execute("ALTER TABLE accounts ADD COLUMN password_kdf_n INTEGER NOT NULL DEFAULT 32768")
        if "recovery_kdf_n" not in cols:
            self.conn.execute("ALTER TABLE accounts ADD COLUMN recovery_kdf_n INTEGER NOT NULL DEFAULT 32768")
        self.conn.commit()

    # One row per mutual-contact PAIR, not per direction — username_a is
    # always the lexicographically smaller of the two (see add_contact_edge)
    # so (alice, bob) and (bob, alice) collapse to the same row instead of
    # needing two and keeping them in sync.
    def _migrate_contact_edges_table(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS contact_edges (
                username_a TEXT NOT NULL,
                username_b TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (username_a, username_b)
            );
            """
        )
        self.conn.commit()

    def is_username_available(self, username: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM accounts WHERE username_lower = ?", (username.lower(),)
            ).fetchone()
        return row is None

    def create_account(
        self,
        username: str,
        password_salt: str,
        password_auth_hash: str,
        encrypted_identity_blob: str,
        recovery_salt: str,
        recovery_auth_hash: str,
        encrypted_identity_blob_recovery: str,
        identity_pub: str = "",
        password_kdf_n: int = 32768,
        recovery_kdf_n: int = 32768,
    ) -> str:
        user_id = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            try:
                self.conn.execute(
                    """
                    INSERT INTO accounts (
                        user_id, username, username_lower, password_salt, password_auth_hash,
                        encrypted_identity_blob, recovery_salt, recovery_auth_hash,
                        encrypted_identity_blob_recovery, identity_pub, password_kdf_n, recovery_kdf_n,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        username,
                        username.lower(),
                        password_salt,
                        password_auth_hash,
                        encrypted_identity_blob,
                        recovery_salt,
                        recovery_auth_hash,
                        encrypted_identity_blob_recovery,
                        identity_pub,
                        password_kdf_n,
                        recovery_kdf_n,
                        now,
                        now,
                    ),
                )
                self.conn.commit()
            except sqlite3.IntegrityError as exc:
                raise UsernameTaken(username) from exc
        return user_id

    def get_by_username(self, username: str) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM accounts WHERE username_lower = ?", (username.lower(),)
            ).fetchone()

    # Called on every login (see accounts_server.py's /api/update-identity-pub,
    # invoked with the same password_auth_key login already verified) — a
    # cheap, idempotent self-healing backfill for accounts created before
    # this column existed, since signup is otherwise the only place this
    # gets set.
    def set_identity_pub(self, username: str, identity_pub: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE accounts SET identity_pub = ? WHERE username_lower = ?",
                (identity_pub, username.lower()),
            )
            self.conn.commit()

    def search_usernames(self, query: str, exclude_username: str = "", limit: int = 15) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                """
                SELECT username, identity_pub FROM accounts
                WHERE username_lower LIKE ?
                  AND username_lower != ?
                  AND identity_pub IS NOT NULL AND identity_pub != ''
                ORDER BY username_lower
                LIMIT ?
                """,
                (f"%{query.lower()}%", exclude_username.lower(), limit),
            ).fetchall()

    def update_password(
        self,
        username: str,
        password_salt: str,
        password_auth_hash: str,
        encrypted_identity_blob: str,
        password_kdf_n: int = 32768,
    ) -> None:
        with self._lock:
            self.conn.execute(
                """
                UPDATE accounts SET password_salt=?, password_auth_hash=?, encrypted_identity_blob=?,
                    password_kdf_n=?, updated_at=?
                WHERE username_lower=?
                """,
                (password_salt, password_auth_hash, encrypted_identity_blob, password_kdf_n, time.time(), username.lower()),
            )
            self.conn.commit()

    # Transparent hash-format upgrades (bcrypt -> Argon2id — see
    # accounts_server.py's _verify_and_maybe_upgrade): called after a
    # successful login/recovery-verify whose stored hash was still in
    # the older format, re-storing the SAME already-proven auth_key
    # under the stronger hash. Never changes password_salt/kdf_n/blob —
    # those are untouched by which hash algorithm protects the hash.
    def upgrade_password_hash(self, username: str, new_hash: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE accounts SET password_auth_hash=?, updated_at=? WHERE username_lower=?",
                (new_hash, time.time(), username.lower()),
            )
            self.conn.commit()

    def upgrade_recovery_hash(self, username: str, new_hash: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE accounts SET recovery_auth_hash=?, updated_at=? WHERE username_lower=?",
                (new_hash, time.time(), username.lower()),
            )
            self.conn.commit()

    # Records that these two usernames are now mutual (accepted) contacts
    # — called once per pair, the first time either side observes the
    # OTHER as an accepted contact (see network.js's status transitions),
    # never on a one-sided request. Stored with the pair sorted so it's
    # idempotent regardless of which side calls it first or again later
    # (e.g. after a "delete chat" and re-add) — INSERT OR IGNORE makes a
    # repeat call a no-op rather than an error.
    def add_contact_edge(self, username_a: str, username_b: str) -> None:
        a, b = sorted([username_a.lower(), username_b.lower()])
        if a == b:
            return
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO contact_edges (username_a, username_b, created_at) VALUES (?, ?, ?)",
                (a, b, time.time()),
            )
            self.conn.commit()

    # "People you may know": accounts that share at least one mutual
    # contact with `username`, excluding username itself and anyone
    # already directly connected to it. Ranked by how many mutual
    # contacts they share (most overlap first) since that's the
    # strongest signal this table can offer.
    def suggest_mutual_friends(self, username: str, limit: int = 15) -> list[sqlite3.Row]:
        u = username.lower()
        with self._lock:
            return self.conn.execute(
                """
                WITH my_contacts AS (
                    SELECT username_b AS peer FROM contact_edges WHERE username_a = ?
                    UNION
                    SELECT username_a AS peer FROM contact_edges WHERE username_b = ?
                ),
                candidates AS (
                    SELECT ce.username_b AS peer FROM contact_edges ce
                        JOIN my_contacts mc ON ce.username_a = mc.peer
                    UNION ALL
                    SELECT ce.username_a AS peer FROM contact_edges ce
                        JOIN my_contacts mc ON ce.username_b = mc.peer
                )
                SELECT a.username AS username, a.identity_pub AS identity_pub, COUNT(*) AS mutual_count
                FROM candidates c
                JOIN accounts a ON a.username_lower = c.peer
                WHERE c.peer != ?
                  AND c.peer NOT IN (SELECT peer FROM my_contacts)
                  AND a.identity_pub IS NOT NULL AND a.identity_pub != ''
                GROUP BY c.peer
                ORDER BY mutual_count DESC, c.peer
                LIMIT ?
                """,
                (u, u, u, limit),
            ).fetchall()

    def close(self) -> None:
        with self._lock:
            self.conn.close()
