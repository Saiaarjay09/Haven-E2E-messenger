"""LAN peer discovery via periodic UDP broadcast — no internet, no server.

Every running instance broadcasts a small beacon announcing its username,
identity public key, and the TCP port it is listening on. Anyone else on
the same local network/subnet sees it and can offer to start a chat. This
is intentionally the entire "directory service": there is nothing to
trust here except what the user verifies themselves via the safety-number
fingerprint before marking a contact verified.
"""

from __future__ import annotations

import json
import socket
import threading
import time

BEACON_PORT = 51820
BEACON_INTERVAL = 3.0
PEER_TIMEOUT = 15.0


class Discovery:
    def __init__(self, username: str, identity_pub: bytes, tcp_port: int):
        self.username = username
        self.identity_pub_hex = identity_pub.hex()
        self.tcp_port = tcp_port
        self.peers: dict[str, dict] = {}  # fingerprint-ish key -> info
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) if hasattr(
            socket, "SO_REUSEPORT"
        ) else None
        self._recv_sock.bind(("", BEACON_PORT))
        self._recv_sock.settimeout(1.0)

    def start(self) -> None:
        threading.Thread(target=self._broadcast_loop, daemon=True).start()
        threading.Thread(target=self._listen_loop, daemon=True).start()
        threading.Thread(target=self._reap_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _broadcast_loop(self) -> None:
        while not self._stop.is_set():
            payload = json.dumps(
                {
                    "type": "haven-beacon",
                    "username": self.username,
                    "identity_pub": self.identity_pub_hex,
                    "tcp_port": self.tcp_port,
                }
            ).encode("utf-8")
            try:
                self._send_sock.sendto(payload, ("255.255.255.255", BEACON_PORT))
            except OSError:
                pass
            time.sleep(BEACON_INTERVAL)

    def _listen_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._recv_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except ValueError:
                continue
            if msg.get("type") != "haven-beacon":
                continue
            if msg.get("identity_pub") == self.identity_pub_hex:
                continue  # ourselves
            key = msg["identity_pub"]
            with self._lock:
                self.peers[key] = {
                    "username": msg["username"],
                    "identity_pub": msg["identity_pub"],
                    "host": addr[0],
                    "tcp_port": msg["tcp_port"],
                    "last_seen": time.time(),
                }

    def _reap_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(2.0)
            cutoff = time.time() - PEER_TIMEOUT
            with self._lock:
                stale = [k for k, v in self.peers.items() if v["last_seen"] < cutoff]
                for k in stale:
                    del self.peers[k]

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self.peers.values())
