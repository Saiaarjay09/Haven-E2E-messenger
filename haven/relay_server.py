"""Self-hosted relay server: store-and-forward for opaque ciphertext.

Run it yourself, on your own hardware (a Raspberry Pi, a home NAS, a
cheap VPS — anything with a stable address your friends' clients can
reach):

    python3 -m haven.relay_server --port 8443 --ws-port 8444

This relay speaks TWO transports to the SAME routing table and message
queue, so a desktop client (TCP) and a browser client (WebSocket, Phase
7b) registered on the same relay can reach each other transparently —
routing is keyed by identity_pub, never by which transport someone
happens to be connected over.

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
only the true private-key holder can compute the matching proof. Same
handshake, same frame shapes, on both transports — a browser's WebSocket
JSON messages and a desktop client's length-prefixed TCP JSON frames
carry byte-for-byte identical payloads once framing is stripped.

Offline delivery: if the recipient isn't currently connected (on EITHER
transport), the envelope is queued in a local SQLite file and flushed to
them in order as soon as they connect and register on either one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import sqlite3
import threading
import time

from . import crypto
from .network import _recv_frame, _send_frame

DEFAULT_PORT = 8443
DEFAULT_WS_PORT = 8444


class ClientHandle:
    """Uniform interface over a TCP socket or a WebSocket connection, so
    the routing/queue logic below never needs to know which transport a
    given client is using."""

    def send(self, obj: dict) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class TCPClientHandle(ClientHandle):
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send(self, obj: dict) -> None:
        _send_frame(self.sock, obj)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class WSClientHandle(ClientHandle):
    def __init__(self, ws, loop: asyncio.AbstractEventLoop):
        self.ws = ws
        self.loop = loop

    def send(self, obj: dict) -> None:
        # run_coroutine_threadsafe uses call_soon_threadsafe internally,
        # which is safe to call from the loop's own thread or any other —
        # fire-and-forget here (not waiting on .result()) so this can
        # never deadlock regardless of which thread calls it from.
        try:
            asyncio.run_coroutine_threadsafe(self.ws.send(json.dumps(obj)), self.loop)
        except RuntimeError:
            pass  # loop already closed

    def close(self) -> None:
        try:
            asyncio.run_coroutine_threadsafe(self.ws.close(), self.loop)
        except RuntimeError:
            pass


class RelayServer:
    def __init__(self, port: int = DEFAULT_PORT, db_path: str = "haven_relay.db", ws_port: int | None = None):
        self.port = port
        self.ws_port = ws_port
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
        self.clients: dict[str, ClientHandle] = {}  # identity_pub hex -> live handle
        self._stop = threading.Event()
        self.server_sock: socket.socket | None = None
        self._ws_loop: asyncio.AbstractEventLoop | None = None
        self._ws_stop_future: asyncio.Future | None = None

    def start(self) -> None:
        if self.ws_port:
            threading.Thread(target=self._run_ws_server, daemon=True).start()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.port))
        s.listen(64)
        self.server_sock = s
        ws_note = f", websocket on 0.0.0.0:{self.ws_port}" if self.ws_port else ""
        print(f"[haven-relay] listening on 0.0.0.0:{self.port}{ws_note}, queue db={self.db_path}")
        while not self._stop.is_set():
            try:
                sock, addr = s.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_tcp_client, args=(sock, addr), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
        if self._ws_loop is not None and self._ws_stop_future is not None:
            # Resolve the future _ws_main is awaiting so its `async with`
            # block exits cleanly (closing the WS server properly) before
            # the loop stops — stopping the loop directly instead would cut
            # that shutdown off mid-flight and print scary but harmless
            # "Event loop stopped before Future completed" warnings.
            self._ws_loop.call_soon_threadsafe(self._ws_stop_future.set_result, None)

    # -- TCP transport -----------------------------------------------------

    def _handle_tcp_client(self, sock: socket.socket, addr) -> None:
        identity_pub_hex: str | None = None
        handle: TCPClientHandle | None = None
        try:
            def recv():
                return _recv_frame(sock)

            def send(obj):
                _send_frame(sock, obj)

            identity_pub_hex, username = self._do_handshake_sync(recv, send)
            if identity_pub_hex is None:
                sock.close()
                return

            handle = TCPClientHandle(sock)
            self._register_client(identity_pub_hex, username, handle, addr[0])
            send({"type": "registered"})
            self._flush_queue(identity_pub_hex)

            while True:
                frame = _recv_frame(sock)
                self._handle_frame(frame, identity_pub_hex)
        except (ConnectionError, OSError, KeyError, ValueError):
            pass
        finally:
            if identity_pub_hex is not None:
                self._unregister_client(identity_pub_hex, handle)
            try:
                sock.close()
            except OSError:
                pass

    def _do_handshake_sync(self, recv, send) -> tuple[str | None, str | None]:
        init = recv()
        if init.get("type") != "register_init":
            return None, None
        claimed_pub_hex = init["identity_pub"]
        claimed_pub = bytes.fromhex(claimed_pub_hex)
        username = init.get("username", claimed_pub_hex[:8])

        ephemeral = crypto.KeyPair.generate()
        nonce = os.urandom(16)
        send({"type": "challenge", "server_ephemeral_pub": ephemeral.public_bytes.hex(), "nonce": nonce.hex()})

        resp = recv()
        if resp.get("type") != "register":
            return None, None
        expected_proof = crypto.dh_proof(ephemeral.private_key, claimed_pub, nonce)
        if resp.get("proof") != expected_proof:
            send({"type": "error", "reason": "proof-of-possession failed"})
            return None, None
        return claimed_pub_hex, username

    # -- WebSocket transport (Phase 7b) --------------------------------------

    def _run_ws_server(self) -> None:
        asyncio.run(self._ws_main())

    async def _ws_main(self) -> None:
        import websockets.asyncio.server as ws_server

        self._ws_loop = asyncio.get_running_loop()
        self._ws_stop_future = self._ws_loop.create_future()
        async with ws_server.serve(self._handle_ws_client, "0.0.0.0", self.ws_port):
            await self._ws_stop_future

    async def _handle_ws_client(self, ws) -> None:
        identity_pub_hex: str | None = None
        handle: WSClientHandle | None = None
        try:
            async def recv():
                raw = await ws.recv()
                return json.loads(raw)

            async def send(obj):
                await ws.send(json.dumps(obj))

            identity_pub_hex, username = await self._do_handshake_async(recv, send)
            if identity_pub_hex is None:
                await ws.close()
                return

            handle = WSClientHandle(ws, self._ws_loop)
            self._register_client(identity_pub_hex, username, handle, "ws-client")
            await send({"type": "registered"})
            self._flush_queue(identity_pub_hex)

            async for raw in ws:
                frame = json.loads(raw)
                self._handle_frame(frame, identity_pub_hex)
        except (ConnectionError, OSError, KeyError, ValueError):
            pass
        finally:
            if identity_pub_hex is not None:
                self._unregister_client(identity_pub_hex, handle)

    async def _do_handshake_async(self, recv, send) -> tuple[str | None, str | None]:
        init = await recv()
        if init.get("type") != "register_init":
            return None, None
        claimed_pub_hex = init["identity_pub"]
        claimed_pub = bytes.fromhex(claimed_pub_hex)
        username = init.get("username", claimed_pub_hex[:8])

        ephemeral = crypto.KeyPair.generate()
        nonce = os.urandom(16)
        await send({"type": "challenge", "server_ephemeral_pub": ephemeral.public_bytes.hex(), "nonce": nonce.hex()})

        resp = await recv()
        if resp.get("type") != "register":
            return None, None
        expected_proof = crypto.dh_proof(ephemeral.private_key, claimed_pub, nonce)
        if resp.get("proof") != expected_proof:
            await send({"type": "error", "reason": "proof-of-possession failed"})
            return None, None
        return claimed_pub_hex, username

    # -- shared registration + routing (transport-agnostic) ------------------

    def _register_client(self, identity_pub_hex: str, username: str, handle: ClientHandle, source: str) -> None:
        with self._clients_lock:
            old = self.clients.get(identity_pub_hex)
            if old is not None:
                old.close()
            self.clients[identity_pub_hex] = handle
        print(f"[haven-relay] {username} ({identity_pub_hex[:12]}...) registered from {source}")

    def _unregister_client(self, identity_pub_hex: str, handle: ClientHandle | None) -> None:
        with self._clients_lock:
            # Only remove if THIS handle is still the registered one — if the
            # same identity reconnected (new handle) while this connection's
            # cleanup was running, that newer registration must survive.
            if self.clients.get(identity_pub_hex) is handle:
                del self.clients[identity_pub_hex]

    def _handle_frame(self, frame: dict, sender_pub_hex: str) -> None:
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
            handle = self.clients.get(recipient)
        if handle is None:
            return
        try:
            handle.send({"type": "relay", "from": sender, "payload": payload, "msg_id": msg_id})
        except OSError:
            pass  # they'll get it from the queue next time they connect

    def _flush_queue(self, recipient: str) -> None:
        with self._db_lock:
            rows = self.conn.execute(
                "SELECT id, sender, payload FROM queue WHERE recipient=? ORDER BY id ASC",
                (recipient,),
            ).fetchall()
        for msg_id, sender, payload_json in rows:
            self._try_deliver(recipient, sender, json.loads(payload_json), msg_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Haven self-hosted relay server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port for desktop clients")
    parser.add_argument(
        "--ws-port",
        type=int,
        default=DEFAULT_WS_PORT,
        help="WebSocket port for browser clients (0 to disable)",
    )
    parser.add_argument("--db", default="haven_relay.db")
    args = parser.parse_args()
    RelayServer(port=args.port, db_path=args.db, ws_port=args.ws_port or None).start()


if __name__ == "__main__":
    main()
