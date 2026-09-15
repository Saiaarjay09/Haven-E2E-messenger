"""Self-hosted relay server: store-and-forward for opaque ciphertext.

Run it yourself, on your own hardware (a Raspberry Pi, a home NAS, a
cheap VPS — anything with a stable address your friends' clients can
reach):

    python3 -m haven.relay_server --port 8443

What the relay does and does not see:

  * It sees each client's public identity key (not secret), a per-message
    routing address ("deliver this to identity X"), and opaque ciphertext
    bytes it cannot decrypt (it never has any ratchet or session key).
  * It does NOT see plaintext, private keys, or passwords.
  * It DOES see coarse metadata: which public key is sending to which
    public key, and when. That's the "metadata best-effort" tradeoff
    from ROADMAP.md — the same one Signal's own servers make. Sealed
    sender / padding / cover traffic to reduce this further is listed
    there as future hardening, not done here.

Authentication (proving a connecting client really holds the private key
for the identity_pub it claims) uses a Diffie-Hellman challenge-response
(see crypto.dh_proof) rather than a password or a separate signing key:
the relay proposes a fresh ephemeral X25519 key as the challenge, and
only the true private-key holder can compute the matching proof.

Offline delivery: if the recipient isn't currently connected, the
envelope is queued in a local SQLite file and flushed to them in order
as soon as they connect and register.
"""

from __future__ import annotations

import argparse
import os
import socket
import sqlite3
import threading
import time

from . import crypto
from .network import _recv_frame, _send_frame

DEFAULT_PORT = 8443


class RelayServer:
    def __init__(self, port: int = DEFAULT_PORT, db_path: str = "haven_relay.db"):
        self.port = port
        self.db_path = db_path
        self._db_lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        self.conn.commit()

        self._clients_lock = threading.Lock()
        self.clients: dict[str, socket.socket] = {}  # identity_pub hex -> live socket
        self._stop = threading.Event()
        self.server_sock: socket.socket | None = None

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.port))
        s.listen(64)
        self.server_sock = s
        print(f"[haven-relay] listening on 0.0.0.0:{self.port}, queue db={self.db_path}")
        while not self._stop.is_set():
            try:
                sock, addr = s.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(sock, addr), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass

    # -- per-connection handling -----------------------------------------

    def _handle_client(self, sock: socket.socket, addr) -> None:
        identity_pub_hex: str | None = None
        try:
            init = _recv_frame(sock)
            if init.get("type") != "register_init":
                sock.close()
                return
            claimed_pub_hex = init["identity_pub"]
            claimed_pub = bytes.fromhex(claimed_pub_hex)
            username = init.get("username", claimed_pub_hex[:8])

            ephemeral = crypto.KeyPair.generate()
            nonce = os.urandom(16)
            _send_frame(
                sock,
                {
                    "type": "challenge",
                    "server_ephemeral_pub": ephemeral.public_bytes.hex(),
                    "nonce": nonce.hex(),
                },
            )

            resp = _recv_frame(sock)
            if resp.get("type") != "register":
                sock.close()
                return
            expected_proof = crypto.dh_proof(ephemeral.private_key, claimed_pub, nonce)
            if resp.get("proof") != expected_proof:
                _send_frame(sock, {"type": "error", "reason": "proof-of-possession failed"})
                sock.close()
                return

            identity_pub_hex = claimed_pub_hex
            with self._clients_lock:
                old = self.clients.get(identity_pub_hex)
                if old is not None:
                    try:
                        old.close()
                    except OSError:
                        pass
                self.clients[identity_pub_hex] = sock
            print(f"[haven-relay] {username} ({identity_pub_hex[:12]}...) registered from {addr[0]}")
            _send_frame(sock, {"type": "registered"})

            self._flush_queue(identity_pub_hex)
            self._read_loop(sock, identity_pub_hex)
        except (ConnectionError, OSError, KeyError, ValueError):
            pass
        finally:
            if identity_pub_hex:
                with self._clients_lock:
                    if self.clients.get(identity_pub_hex) is sock:
                        del self.clients[identity_pub_hex]
            try:
                sock.close()
            except OSError:
                pass

    def _read_loop(self, sock: socket.socket, sender_pub_hex: str) -> None:
        while True:
            frame = _recv_frame(sock)
            ftype = frame.get("type")
            if ftype == "relay":
                to = frame["to"]
                payload = frame["payload"]
                msg_id = self._enqueue(to, sender_pub_hex, payload)
                self._try_deliver(to, sender_pub_hex, payload, msg_id)
            elif ftype == "ack":
                self._delete_queued(frame["msg_id"])
            # unknown frame types are ignored, not fatal — forward compatibility

    # -- queue management --------------------------------------------------

    def _enqueue(self, recipient: str, sender: str, payload: dict) -> int:
        import json

        with self._db_lock:
            cur = self.conn.execute(
                "INSERT INTO queue (recipient, sender, payload, created_at) VALUES (?, ?, ?, ?)",
                (recipient, sender, json.dumps(payload), time.time()),
            )
            self.conn.commit()
            return cur.lastrowid

    def _delete_queued(self, msg_id: int) -> None:
        with self._db_lock:
            self.conn.execute("DELETE FROM queue WHERE id=?", (msg_id,))
            self.conn.commit()

    def _try_deliver(self, recipient: str, sender: str, payload: dict, msg_id: int) -> None:
        with self._clients_lock:
            sock = self.clients.get(recipient)
        if sock is None:
            return
        try:
            _send_frame(sock, {"type": "relay", "from": sender, "payload": payload, "msg_id": msg_id})
        except OSError:
            pass  # they'll get it from the queue next time they connect

    def _flush_queue(self, recipient: str) -> None:
        with self._db_lock:
            rows = self.conn.execute(
                "SELECT id, sender, payload FROM queue WHERE recipient=? ORDER BY id ASC",
                (recipient,),
            ).fetchall()
        import json

        for msg_id, sender, payload_json in rows:
            self._try_deliver(recipient, sender, json.loads(payload_json), msg_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Haven self-hosted relay server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--db", default="haven_relay.db")
    args = parser.parse_args()
    RelayServer(port=args.port, db_path=args.db).start()


if __name__ == "__main__":
    main()
