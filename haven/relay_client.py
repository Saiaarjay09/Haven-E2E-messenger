"""Client side of the relay protocol: register via DH proof-of-possession,
then send/receive opaque payload dicts addressed by identity_pub, with
automatic reconnect. See relay_server.py for the protocol and the privacy
tradeoff (the relay sees who's sending to whom, never plaintext).
"""

from __future__ import annotations

import socket
import threading
import time

from . import crypto
from .network import _recv_frame, _send_frame


class RelayClient:
    def __init__(self, identity: crypto.KeyPair, username: str, host: str, port: int):
        self.identity = identity
        self.username = username
        self.host = host
        self.port = port

        self.sock: socket.socket | None = None
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self.connected = threading.Event()

        self.on_deliver = None  # callback(sender_pub_hex: str, payload: dict)
        self.on_connection_change = None  # callback(bool connected)

    def start(self) -> None:
        threading.Thread(target=self._run_forever, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _run_forever(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            try:
                self._connect_and_serve()
                backoff = 1.0
            except (ConnectionError, OSError, KeyError, ValueError):
                pass
            self.connected.clear()
            if self.on_connection_change:
                self.on_connection_change(False)
            if self._stop.is_set():
                return
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

    def _connect_and_serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(6.0)
        sock.connect((self.host, self.port))

        _send_frame(
            sock,
            {
                "type": "register_init",
                "identity_pub": self.identity.public_bytes.hex(),
                "username": self.username,
            },
        )
        challenge = _recv_frame(sock)
        if challenge.get("type") != "challenge":
            sock.close()
            return
        server_ephemeral_pub = bytes.fromhex(challenge["server_ephemeral_pub"])
        nonce = bytes.fromhex(challenge["nonce"])
        proof = crypto.dh_proof(self.identity.private_key, server_ephemeral_pub, nonce)
        _send_frame(sock, {"type": "register", "proof": proof})

        ack = _recv_frame(sock)
        if ack.get("type") != "registered":
            sock.close()
            return

        sock.settimeout(None)
        self.sock = sock
        self.connected.set()
        if self.on_connection_change:
            self.on_connection_change(True)

        while True:
            frame = _recv_frame(sock)
            if frame.get("type") == "relay":
                sender = frame["from"]
                payload = frame["payload"]
                msg_id = frame["msg_id"]
                if self.on_deliver:
                    self.on_deliver(sender, payload)
                self._send(sock, {"type": "ack", "msg_id": msg_id})

    def send_to(self, identity_pub: bytes, payload: dict) -> bool:
        sock = self.sock
        if sock is None or not self.connected.is_set():
            return False
        try:
            self._send(sock, {"type": "relay", "to": identity_pub.hex(), "payload": payload})
            return True
        except OSError:
            return False

    def _send(self, sock: socket.socket, obj: dict) -> None:
        with self._send_lock:
            _send_frame(sock, obj)
