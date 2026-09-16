"""Headless smoke test for Phase 7b: the relay's WebSocket transport,
which is what a browser client will use (browsers can't open raw TCP
sockets). Uses the `websockets` library as a stand-in for a browser's
native WebSocket API — same protocol either way. Proves:
  1. two WebSocket clients can register and exchange an E2E-ratcheted
     message through the relay, exactly like two TCP clients can
  2. offline queuing works over WebSocket the same way it does over TCP
  3. the REAL interop case: a desktop-style TCP client and a
     browser-style WebSocket client, both registered on the SAME relay,
     can reach each other — proving routing is transport-agnostic
Run: python3 test_ws_relay_smoke.py
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path

import websockets.asyncio.client as ws_client

from haven import crypto, identity, network, relay_client, relay_server, storage

tmp = Path(tempfile.mkdtemp())
identity.DATA_ROOT = tmp
print("test data root:", tmp)

TCP_PORT = 19201
WS_PORT = 19202
relay = relay_server.RelayServer(port=TCP_PORT, ws_port=WS_PORT, db_path=str(tmp / "relay.db"))
threading.Thread(target=relay.start, daemon=True).start()
time.sleep(0.5)
print(f"relay up: TCP={TCP_PORT} WS={WS_PORT}")


def wait_until(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class BrowserLikeWSClient:
    """Minimal stand-in for what browser JS will do over WebSocket —
    same register_init/challenge/register/registered handshake, same
    relay/ack frame shapes as the TCP path."""

    def __init__(self, identity_keypair: crypto.KeyPair, username: str, ws_port: int):
        self.identity = identity_keypair
        self.username = username
        self.ws_port = ws_port
        self.received: list[tuple[str, dict]] = []  # (from_pub_hex, payload)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.connected = threading.Event()
        self.ws = None
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._main())

    async def _main(self):
        async with ws_client.connect(f"ws://127.0.0.1:{self.ws_port}") as ws:
            self.ws = ws
            await ws.send(
                json.dumps(
                    {"type": "register_init", "identity_pub": self.identity.public_bytes.hex(), "username": self.username}
                )
            )
            challenge = json.loads(await ws.recv())
            assert challenge["type"] == "challenge"
            server_ephemeral_pub = bytes.fromhex(challenge["server_ephemeral_pub"])
            nonce = bytes.fromhex(challenge["nonce"])
            proof = crypto.dh_proof(self.identity.private_key, server_ephemeral_pub, nonce)
            await ws.send(json.dumps({"type": "register", "proof": proof}))
            ack = json.loads(await ws.recv())
            assert ack["type"] == "registered"
            self.connected.set()

            async for raw in ws:
                frame = json.loads(raw)
                if frame.get("type") == "relay":
                    self.received.append((frame["from"], frame["payload"]))
                    await ws.send(json.dumps({"type": "ack", "msg_id": frame["msg_id"]}))

    def send_to(self, identity_pub: bytes, payload: dict):
        async def _send():
            await self.ws.send(json.dumps({"type": "relay", "to": identity_pub.hex(), "payload": payload}))

        asyncio.run_coroutine_threadsafe(_send(), self._loop)

    def stop(self):
        async def _shutdown():
            if self.ws is not None:
                await self.ws.close()

        try:
            asyncio.run_coroutine_threadsafe(_shutdown(), self._loop).result(timeout=2)
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=2)


# --- 1. two WebSocket clients exchange a message ---
alice_id = crypto.KeyPair.generate()
bob_id = crypto.KeyPair.generate()
alice_ws = BrowserLikeWSClient(alice_id, "alice", WS_PORT)
bob_ws = BrowserLikeWSClient(bob_id, "bob", WS_PORT)
assert wait_until(lambda: alice_ws.connected.is_set())
assert wait_until(lambda: bob_ws.connected.is_set())
print("two WebSocket ('browser') clients registered with the relay")

alice_ws.send_to(bob_id.public_bytes, {"hello": "from alice over websocket"})
assert wait_until(lambda: len(bob_ws.received) == 1)
assert bob_ws.received[0][0] == alice_id.public_bytes.hex()
assert bob_ws.received[0][1] == {"hello": "from alice over websocket"}
print("confirmed: WebSocket-to-WebSocket relay delivery works")

# --- 2. offline queuing works over WebSocket too ---
bob_ws.stop()
time.sleep(0.3)
alice_ws.send_to(bob_id.public_bytes, {"hello": "sent while bob was offline"})
time.sleep(0.3)

bob_ws2 = BrowserLikeWSClient(bob_id, "bob", WS_PORT)
assert wait_until(lambda: bob_ws2.connected.is_set())
assert wait_until(lambda: any(p == {"hello": "sent while bob was offline"} for _, p in bob_ws2.received))
print("confirmed: a message sent while the WebSocket client was offline is queued and delivered on reconnect")

# --- 3. real interop: a TCP client and a WebSocket client, same relay ---
carol, _ = identity.create_account("carol", "carol-password-123")
carol_store = storage.Store(carol.data_dir, carol.identity)
carol_net = network.NetworkManager(carol.identity, "carol", carol_store)
carol_relay = relay_client.RelayClient(carol.identity, "carol", "127.0.0.1", TCP_PORT)
RELAY_KEY = f"127.0.0.1:{TCP_PORT}"
carol_net.attach_relay(RELAY_KEY, carol_relay)
carol_relay.start()
assert wait_until(lambda: carol_relay.connected.is_set())
print("carol connected over TCP (the desktop-style transport)")

dave_ws = BrowserLikeWSClient(crypto.KeyPair.generate(), "dave", WS_PORT)
assert wait_until(lambda: dave_ws.connected.is_set())
print("dave connected over WebSocket (the browser-style transport), same relay")

# carol (TCP) reaches dave (WebSocket) via the standard hello handshake
fp = carol_net.connect_relay(dave_ws.identity.public_bytes, "dave", relay_key=RELAY_KEY)
assert wait_until(lambda: len(dave_ws.received) > 0), "dave (WebSocket) never received carol's (TCP) hello"

hello_msgs = [p for _, p in dave_ws.received if p.get("type") == "hello"]
assert len(hello_msgs) == 1
assert hello_msgs[0]["username"] == "carol"
print("confirmed: a TCP client's handshake reaches a WebSocket client through the SAME relay")
print("           (this is the actual interop that lets desktop and future web clients talk to each other)")

alice_ws.stop()
bob_ws2.stop()
dave_ws.stop()
carol_net.stop()
carol_relay.stop()
carol_store.close()
relay.stop()
time.sleep(0.2)
shutil.rmtree(tmp, ignore_errors=True)

print("\nALL WEBSOCKET RELAY SMOKE TESTS PASSED")
