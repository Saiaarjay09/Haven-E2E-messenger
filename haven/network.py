"""Message transport: handshake + ratchet-encrypted frames, over either a
direct LAN TCP socket or a self-hosted relay (see relay_client.py).

Every session (direct or relayed) starts with a HELLO / HELLO_ACK exchange
carrying each side's identity public key and a fresh ephemeral public key,
from which both sides independently derive the same root key (see
crypto.compute_shared_root_key) and then split it into per-direction
ratchet chains. After that, every frame is opaque ciphertext; the
plaintext never touches the socket, and — for the relay path — the relay
server never sees it either.

Direct-transport framing is a 4-byte big-endian length prefix followed by
that many bytes of UTF-8 JSON, with binary fields hex-encoded inside the
JSON (relay_server.py reuses these same helpers for its own framing).
Relay-transport frames carry the identical JSON payload shape, just
wrapped inside the relay's envelope ({"to"/"from": ..., "payload": {...
this same hello/hello_ack/msg dict ...}}) instead of being written
straight to a dedicated socket — see NetworkManager._on_relay_frame.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from . import crypto


def _send_frame(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return buf


def _recv_frame(sock: socket.socket) -> dict:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    payload = _recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))


@dataclass
class PeerConnection:
    transport: str  # 'direct' or 'relay'
    fingerprint: str
    username: str
    identity_pub: bytes
    session: crypto.RatchetSession
    sock: socket.socket | None = None  # set when transport == 'direct'
    relay: object | None = None  # RelayClient, set when transport == 'relay'
    lock: threading.Lock = field(default_factory=threading.Lock)

    def send_raw(self, obj: dict) -> None:
        if self.transport == "direct":
            _send_frame(self.sock, obj)
        else:
            if not self.relay.send_to(self.identity_pub, obj):
                raise ConnectionError("relay is not currently connected")

    def close(self) -> None:
        if self.transport == "direct" and self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass


class NetworkManager:
    def __init__(self, identity: crypto.KeyPair, username: str, store):
        self.identity = identity
        self.username = username
        self.store = store
        self.server_sock: socket.socket | None = None
        self.port: int = 0
        self.connections: dict[str, PeerConnection] = {}
        self._conn_lock = threading.Lock()
        self.on_message = None  # callback(fingerprint, kind, text, sender_identity_pub)
        self.on_status = None  # callback(fingerprint, status_str)
        self.on_connect = None  # callback(PeerConnection) fired once per new/replaced connection
        self._stop = threading.Event()

        self.relay = None  # RelayClient, set via attach_relay()
        self._pending_relay_ephemeral: dict[str, crypto.KeyPair] = {}

    # -- relay wiring --------------------------------------------------------

    def attach_relay(self, relay_client) -> None:
        self.relay = relay_client
        self.relay.on_deliver = self._on_relay_frame

    def connect_relay(self, identity_pub: bytes, username_hint: str = "") -> str:
        """Kick off a relay-based handshake with a peer identified only by
        their public identity key (no host/port needed — the relay routes
        by identity_pub). Returns the fingerprint immediately; the session
        itself completes asynchronously once their hello_ack arrives,
        possibly after they come back online."""
        if self.relay is None:
            raise ConnectionError("no relay configured")
        fp = crypto.fingerprint(self.identity.public_bytes, identity_pub)
        with self._conn_lock:
            if fp in self.connections:
                return fp
        if identity_pub.hex() in self._pending_relay_ephemeral:
            return fp  # handshake already in flight

        my_ephemeral = crypto.KeyPair.generate()
        self._pending_relay_ephemeral[identity_pub.hex()] = my_ephemeral
        sent = self.relay.send_to(
            identity_pub,
            {
                "type": "hello",
                "username": self.username,
                "identity_pub": self.identity.public_bytes.hex(),
                "ephemeral_pub": my_ephemeral.public_bytes.hex(),
            },
        )
        if not sent:
            del self._pending_relay_ephemeral[identity_pub.hex()]
            raise ConnectionError("relay is not currently connected")
        return fp

    def _on_relay_frame(self, sender_pub_hex: str, payload: dict) -> None:
        sender_pub = bytes.fromhex(sender_pub_hex)
        ftype = payload.get("type")
        try:
            if ftype == "hello":
                self._handle_relay_hello(sender_pub, payload)
            elif ftype == "hello_ack":
                self._handle_relay_hello_ack(sender_pub, payload)
            elif ftype == "msg":
                self._handle_incoming_msg("relay", sender_pub, payload)
        except (KeyError, ValueError):
            pass  # malformed frame from a buggy/hostile peer — drop it

    def _handle_relay_hello(self, their_identity_pub: bytes, hello: dict) -> None:
        their_ephemeral_pub = bytes.fromhex(hello["ephemeral_pub"])
        their_username = hello["username"]
        my_ephemeral = crypto.KeyPair.generate()

        session = self._derive_session(
            is_initiator=False,
            my_ephemeral=my_ephemeral,
            their_identity_pub=their_identity_pub,
            their_ephemeral_pub=their_ephemeral_pub,
        )
        fp = crypto.fingerprint(self.identity.public_bytes, their_identity_pub)
        conn = PeerConnection(
            transport="relay",
            fingerprint=fp,
            username=their_username,
            identity_pub=their_identity_pub,
            session=session,
            relay=self.relay,
        )
        self._register_connection(conn)
        self.relay.send_to(
            their_identity_pub,
            {
                "type": "hello_ack",
                "username": self.username,
                "identity_pub": self.identity.public_bytes.hex(),
                "ephemeral_pub": my_ephemeral.public_bytes.hex(),
            },
        )

    def _handle_relay_hello_ack(self, their_identity_pub: bytes, ack: dict) -> None:
        my_ephemeral = self._pending_relay_ephemeral.pop(their_identity_pub.hex(), None)
        if my_ephemeral is None:
            return  # unexpected/duplicate ack — ignore
        their_ephemeral_pub = bytes.fromhex(ack["ephemeral_pub"])
        their_username = ack["username"]

        session = self._derive_session(
            is_initiator=True,
            my_ephemeral=my_ephemeral,
            their_identity_pub=their_identity_pub,
            their_ephemeral_pub=their_ephemeral_pub,
        )
        fp = crypto.fingerprint(self.identity.public_bytes, their_identity_pub)
        conn = PeerConnection(
            transport="relay",
            fingerprint=fp,
            username=their_username,
            identity_pub=their_identity_pub,
            session=session,
            relay=self.relay,
        )
        self._register_connection(conn)

    def _derive_session(
        self, *, is_initiator: bool, my_ephemeral, their_identity_pub: bytes, their_ephemeral_pub: bytes
    ) -> crypto.RatchetSession:
        root_key = crypto.compute_shared_root_key(
            is_initiator=is_initiator,
            my_identity=self.identity,
            my_ephemeral=my_ephemeral,
            their_identity_pub=their_identity_pub,
            their_ephemeral_pub=their_ephemeral_pub,
        )
        send_key, recv_key = crypto.derive_chain_keys(root_key, is_initiator=is_initiator)
        return crypto.RatchetSession(send_chain_key=send_key, recv_chain_key=recv_key)

    # -- direct LAN server side ------------------------------------------

    def start_server(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 0))
        s.listen(8)
        self.server_sock = s
        self.port = s.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
        with self._conn_lock:
            for c in self.connections.values():
                c.close()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                sock, addr = self.server_sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle_inbound, args=(sock,), daemon=True
            ).start()

    def _handle_inbound(self, sock: socket.socket) -> None:
        try:
            hello = _recv_frame(sock)
            if hello.get("type") != "hello":
                sock.close()
                return
            their_identity_pub = bytes.fromhex(hello["identity_pub"])
            their_ephemeral_pub = bytes.fromhex(hello["ephemeral_pub"])
            their_username = hello["username"]

            my_ephemeral = crypto.KeyPair.generate()
            _send_frame(
                sock,
                {
                    "type": "hello_ack",
                    "username": self.username,
                    "identity_pub": self.identity.public_bytes.hex(),
                    "ephemeral_pub": my_ephemeral.public_bytes.hex(),
                },
            )

            session = self._derive_session(
                is_initiator=False,
                my_ephemeral=my_ephemeral,
                their_identity_pub=their_identity_pub,
                their_ephemeral_pub=their_ephemeral_pub,
            )
            fp = crypto.fingerprint(self.identity.public_bytes, their_identity_pub)

            conn = PeerConnection(
                transport="direct",
                sock=sock,
                fingerprint=fp,
                username=their_username,
                identity_pub=their_identity_pub,
                session=session,
            )
            self._register_connection(conn)
            self._read_loop(conn)
        except (ConnectionError, OSError, KeyError, ValueError):
            try:
                sock.close()
            except OSError:
                pass

    # -- direct LAN client side -------------------------------------------

    def connect_to_peer(self, host: str, port: int, timeout: float = 5.0) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        my_ephemeral = crypto.KeyPair.generate()
        _send_frame(
            sock,
            {
                "type": "hello",
                "username": self.username,
                "identity_pub": self.identity.public_bytes.hex(),
                "ephemeral_pub": my_ephemeral.public_bytes.hex(),
            },
        )
        ack = _recv_frame(sock)
        if ack.get("type") != "hello_ack":
            sock.close()
            raise ConnectionError("handshake failed: no hello_ack")

        their_identity_pub = bytes.fromhex(ack["identity_pub"])
        their_ephemeral_pub = bytes.fromhex(ack["ephemeral_pub"])
        their_username = ack["username"]

        session = self._derive_session(
            is_initiator=True,
            my_ephemeral=my_ephemeral,
            their_identity_pub=their_identity_pub,
            their_ephemeral_pub=their_ephemeral_pub,
        )
        fp = crypto.fingerprint(self.identity.public_bytes, their_identity_pub)

        sock.settimeout(None)
        conn = PeerConnection(
            transport="direct",
            sock=sock,
            fingerprint=fp,
            username=their_username,
            identity_pub=their_identity_pub,
            session=session,
        )
        self._register_connection(conn)
        threading.Thread(target=self._read_loop, args=(conn,), daemon=True).start()
        return fp

    # -- shared ------------------------------------------------------------

    def _register_connection(self, conn: PeerConnection) -> None:
        with self._conn_lock:
            old = self.connections.get(conn.fingerprint)
            if old is not None:
                old.close()
            self.connections[conn.fingerprint] = conn
        if self.on_connect:
            self.on_connect(conn)
        if self.on_status:
            self.on_status(conn.fingerprint, "connected")

    def _read_loop(self, conn: PeerConnection) -> None:
        """Direct-transport only: relay-transport inbound frames arrive via
        _on_relay_frame instead, since one relay socket multiplexes many
        peers."""
        try:
            while True:
                frame = _recv_frame(conn.sock)
                if frame.get("type") != "msg":
                    continue
                self._handle_incoming_msg("direct", conn.identity_pub, frame, conn=conn)
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            with self._conn_lock:
                if self.connections.get(conn.fingerprint) is conn:
                    del self.connections[conn.fingerprint]
            if self.on_status:
                self.on_status(conn.fingerprint, "disconnected")

    def _handle_incoming_msg(
        self, transport: str, sender_identity_pub: bytes, frame: dict, conn: PeerConnection | None = None
    ) -> None:
        fp = crypto.fingerprint(self.identity.public_bytes, sender_identity_pub)
        if conn is None:
            with self._conn_lock:
                conn = self.connections.get(fp)
            if conn is None:
                return  # message for a session we don't have (e.g. dropped state) — drop it
        envelope = {
            "index": frame["index"],
            "nonce": bytes.fromhex(frame["nonce"]),
            "ciphertext": bytes.fromhex(frame["ciphertext"]),
        }
        with conn.lock:
            plaintext = conn.session.decrypt(envelope, aad=conn.identity_pub).decode("utf-8")
            self.store.save_session(conn.fingerprint, conn.session)
        kind = frame.get("kind", "text")
        self.store.save_message(conn.fingerprint, "in", plaintext, kind=kind)
        if self.on_message:
            self.on_message(conn.fingerprint, kind, plaintext, conn.identity_pub)

    def send_text(self, fingerprint: str, text: str, kind: str = "text") -> None:
        with self._conn_lock:
            conn = self.connections.get(fingerprint)
        if conn is None:
            raise ConnectionError("not connected to this peer")
        # The encrypt (which assigns the next ratchet index) and the actual
        # wire write must be one atomic step under conn.lock — group control
        # messages in particular fire several sends to the same peer back to
        # back from different threads (see groups.py), and the ratchet's
        # strict in-order delivery requirement means whichever index hits
        # the socket first must also be the lowest one, not just whichever
        # thread happened to finish encrypting first.
        with conn.lock:
            envelope = conn.session.encrypt(text.encode("utf-8"), aad=self.identity.public_bytes)
            self.store.save_session(fingerprint, conn.session)
            conn.send_raw(
                {
                    "type": "msg",
                    "index": envelope["index"],
                    "nonce": envelope["nonce"].hex(),
                    "ciphertext": envelope["ciphertext"].hex(),
                    "kind": kind,
                }
            )
        self.store.save_message(fingerprint, "out", text, kind=kind)

    def is_connected(self, fingerprint: str) -> bool:
        with self._conn_lock:
            return fingerprint in self.connections

    def send_when_ready(
        self,
        fingerprint: str,
        text: str,
        kind: str = "text",
        timeout: float = 6.0,
        poll_interval: float = 0.25,
        on_result=None,
    ) -> None:
        """Fire-and-forget send used by GroupManager to fan a message out to
        several members at once without each caller hand-rolling its own
        retry loop: the CALLER is responsible for having already kicked off
        a connection attempt (connect_to_peer / connect_relay) — this just
        waits for that to land, then sends. on_result(True, None) or
        on_result(False, reason) is invoked from a background thread."""

        def worker():
            deadline = time.time() + timeout
            while time.time() < deadline:
                if self.is_connected(fingerprint):
                    try:
                        self.send_text(fingerprint, text, kind=kind)
                    except ConnectionError as exc:
                        if on_result:
                            on_result(False, str(exc))
                        return
                    if on_result:
                        on_result(True, None)
                    return
                time.sleep(poll_interval)
            if on_result:
                on_result(False, "timed out waiting for a session")

        threading.Thread(target=worker, daemon=True).start()
