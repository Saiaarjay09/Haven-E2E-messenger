"""Sender-keys style group messaging, layered entirely on top of the
existing 1:1 pairwise E2E channel (network.NetworkManager). Group control
messages (invite, sender-key distribution, membership changes) and group
chat messages both ride as ordinary end-to-end encrypted 1:1 messages
between members (kind="group", a JSON payload as the "text") — there is
no separate group transport, and no server ever sees a decrypted group
message any more than it sees a decrypted 1:1 one.

Sender keys: each member maintains one outgoing symmetric chain
(crypto.SenderKeyChain) used for every message THEY send to a group, and
one copy of every OTHER member's chain (received from them) to decrypt
what that member sends. This is the same design Signal and WhatsApp use
for groups: O(members) fan-out per message instead of a fresh pairwise
Diffie-Hellman negotiation for every send, while each member still gets
their own independent forward-secret chain.

Adding a member: whoever adds them sends a group_invite carrying the
current membership list and the adder's OWN current sender key; every
OTHER existing member, on hearing about the new member via
group_member_add, separately sends the newcomer their own current sender
key too. The new member therefore starts receiving from everyone going
forward but cannot decrypt anything sent before they joined — there is no
shared history for them to catch up on, by design.

Removing a member: every remaining member discards the removed member's
stored sender key (so they can no longer receive from them) AND rotates
their OWN sender key to a brand new one, redistributed only to the
remaining members. Without that rotation, a removed member could keep
advancing their last-known copy of everyone's chain key indefinitely (the
hash-chain ratchet only gives forward secrecy for the past, not the
future) and silently keep reading the group after being "removed".
"""

from __future__ import annotations

import json
import os
import threading

from . import crypto


class GroupManager:
    def __init__(self, net, store, identity: crypto.KeyPair, username: str, resolve_route=None):
        self.net = net
        self.store = store
        self.identity = identity
        self.username = username
        self.my_pub_hex = identity.public_bytes.hex()
        # resolve_route(identity_pub_hex) -> {"host":..., "tcp_port":...} | None,
        # supplied by the GUI (looks up its own peer/discovery cache).
        self.resolve_route = resolve_route

        self.on_group_message = None  # callback(group_id, sender_username, text, kind)
        self.on_group_update = None  # callback(group_id)

        self.groups: dict[str, dict] = {}
        for group_id, name in store.list_groups():
            state = store.load_group(group_id)
            self.groups[group_id] = {
                "name": name,
                "members": dict(state["members"]),
                "my_chain": crypto.SenderKeyChain(
                    chain_key=bytes.fromhex(state["my_chain"]["chain_key"]),
                    index=state["my_chain"]["index"],
                ),
                "peer_chains": {
                    pub_hex: crypto.SenderKeyChain(chain_key=bytes.fromhex(c["chain_key"]), index=c["index"])
                    for pub_hex, c in state["peer_chains"].items()
                },
                "removed": state.get("removed", False),
            }

    # -- public API ----------------------------------------------------------

    def create_group(self, name: str, members: list[tuple[str, bytes]]) -> str:
        group_id = os.urandom(8).hex()
        full_members = {self.my_pub_hex: self.username}
        for uname, pub in members:
            full_members[pub.hex()] = uname
        my_chain = crypto.SenderKeyChain(chain_key=os.urandom(32))
        self.groups[group_id] = {
            "name": name,
            "members": full_members,
            "my_chain": my_chain,
            "peer_chains": {},
            "removed": False,
        }
        self._persist(group_id)
        self._notify_update(group_id)

        members_payload = [{"username": u, "identity_pub": p} for p, u in full_members.items()]
        for uname, pub in members:
            self._send_control(
                pub,
                uname,
                {
                    "type": "group_invite",
                    "group_id": group_id,
                    "name": name,
                    "members": members_payload,
                    "sender_key": {"chain_key": my_chain.chain_key.hex(), "index": my_chain.index},
                },
            )
        return group_id

    def add_member(self, group_id: str, username: str, identity_pub: bytes) -> None:
        g = self._require_group(group_id)
        pub_hex = identity_pub.hex()
        g["members"][pub_hex] = username
        self._persist(group_id)
        self._notify_update(group_id)

        members_payload = [{"username": u, "identity_pub": p} for p, u in g["members"].items()]
        self._send_control(
            identity_pub,
            username,
            {
                "type": "group_invite",
                "group_id": group_id,
                "name": g["name"],
                "members": members_payload,
                "sender_key": {"chain_key": g["my_chain"].chain_key.hex(), "index": g["my_chain"].index},
            },
        )
        for other_pub_hex, other_uname in list(g["members"].items()):
            if other_pub_hex in (self.my_pub_hex, pub_hex):
                continue
            self._send_control(
                bytes.fromhex(other_pub_hex),
                other_uname,
                {
                    "type": "group_member_add",
                    "group_id": group_id,
                    "member": {"username": username, "identity_pub": pub_hex},
                },
            )

    def remove_member(self, group_id: str, identity_pub: bytes) -> None:
        g = self._require_group(group_id)
        pub_hex = identity_pub.hex()
        removed_username = g["members"].pop(pub_hex, None)
        g["peer_chains"].pop(pub_hex, None)
        g["my_chain"] = crypto.SenderKeyChain(chain_key=os.urandom(32))  # rotate: see module docstring
        self._persist(group_id)
        self._notify_update(group_id)

        # Tell the removed member explicitly (so their own client can show
        # "you were removed" instead of just going quiet) — send this
        # BEFORE popping them out of the loop targets below, since they're
        # no longer in g["members"] once removed_username is captured above.
        if removed_username is not None:
            self._send_control(
                identity_pub,
                removed_username,
                {"type": "group_member_remove", "group_id": group_id, "member_identity_pub": pub_hex},
            )

        for other_pub_hex, other_uname in list(g["members"].items()):
            if other_pub_hex == self.my_pub_hex:
                continue
            self._send_control(
                bytes.fromhex(other_pub_hex),
                other_uname,
                {"type": "group_member_remove", "group_id": group_id, "member_identity_pub": pub_hex},
            )
            self._send_control(
                bytes.fromhex(other_pub_hex),
                other_uname,
                {
                    "type": "group_sender_key",
                    "group_id": group_id,
                    "chain_key": g["my_chain"].chain_key.hex(),
                    "index": g["my_chain"].index,
                },
            )

    def send_group_message(self, group_id: str, text: str, kind: str = "text") -> None:
        g = self._require_group(group_id)
        envelope = g["my_chain"].encrypt(text.encode("utf-8"), aad=group_id.encode())
        self._persist(group_id)
        self.store.save_group_message(group_id, self.my_pub_hex, text, kind=kind)

        payload_json = json.dumps(
            {
                "type": "group_msg",
                "group_id": group_id,
                "kind": kind,
                "envelope": {
                    "index": envelope["index"],
                    "nonce": envelope["nonce"].hex(),
                    "ciphertext": envelope["ciphertext"].hex(),
                },
            }
        )
        for pub_hex, uname in list(g["members"].items()):
            if pub_hex == self.my_pub_hex:
                continue
            self._ensure_route_and_send(bytes.fromhex(pub_hex), uname, payload_json)

    def list_groups(self) -> list[dict]:
        return [
            {"group_id": gid, "name": g["name"], "members": dict(g["members"]), "removed": g.get("removed", False)}
            for gid, g in self.groups.items()
        ]

    def group_history(self, group_id: str) -> list[dict]:
        return self.store.group_history(group_id)

    # -- inbound control-message handling ------------------------------------

    def handle_incoming(self, sender_identity_pub: bytes, text: str) -> None:
        try:
            payload = json.loads(text)
            ftype = payload.get("type")
            if ftype == "group_invite":
                self._on_invite(sender_identity_pub, payload)
            elif ftype == "group_sender_key":
                self._on_sender_key(sender_identity_pub, payload)
            elif ftype == "group_msg":
                self._on_group_msg(sender_identity_pub, payload)
            elif ftype == "group_member_add":
                self._on_member_add(payload)
            elif ftype == "group_member_remove":
                self._on_member_remove(payload)
        except (KeyError, ValueError, json.JSONDecodeError):
            pass  # malformed control frame — drop it rather than crash

    def _on_invite(self, sender_identity_pub: bytes, payload: dict) -> None:
        group_id = payload["group_id"]
        members = {m["identity_pub"]: m["username"] for m in payload["members"]}
        if self.my_pub_hex not in members:
            return
        sender_hex = sender_identity_pub.hex()
        sk = payload["sender_key"]
        sender_chain = crypto.SenderKeyChain(chain_key=bytes.fromhex(sk["chain_key"]), index=sk.get("index", 0))

        g = self.groups.get(group_id)
        if g is None:
            my_chain = crypto.SenderKeyChain(chain_key=os.urandom(32))
            g = {
                "name": payload["name"],
                "members": members,
                "my_chain": my_chain,
                "peer_chains": {sender_hex: sender_chain},
                "removed": False,
            }
            self.groups[group_id] = g
            self._persist(group_id)
            self._notify_update(group_id)
            # newly joining: hand our sender key to everyone else so they can receive from us too
            for pub_hex, uname in members.items():
                if pub_hex == self.my_pub_hex:
                    continue
                self._send_control(
                    bytes.fromhex(pub_hex),
                    uname,
                    {
                        "type": "group_sender_key",
                        "group_id": group_id,
                        "chain_key": my_chain.chain_key.hex(),
                        "index": my_chain.index,
                    },
                )
        else:
            g["members"].update(members)
            g["peer_chains"][sender_hex] = sender_chain
            g["removed"] = False
            self._persist(group_id)
            self._notify_update(group_id)

    def _on_sender_key(self, sender_identity_pub: bytes, payload: dict) -> None:
        g = self.groups.get(payload["group_id"])
        if g is None:
            return
        g["peer_chains"][sender_identity_pub.hex()] = crypto.SenderKeyChain(
            chain_key=bytes.fromhex(payload["chain_key"]), index=payload.get("index", 0)
        )
        self._persist(payload["group_id"])
        self._notify_update(payload["group_id"])

    def _on_group_msg(self, sender_identity_pub: bytes, payload: dict) -> None:
        group_id = payload["group_id"]
        g = self.groups.get(group_id)
        if g is None:
            return
        sender_hex = sender_identity_pub.hex()
        chain = g["peer_chains"].get(sender_hex)
        if chain is None:
            return  # haven't received their sender key yet — drop (known limitation)
        env = payload["envelope"]
        envelope = {"index": env["index"], "nonce": bytes.fromhex(env["nonce"]), "ciphertext": bytes.fromhex(env["ciphertext"])}
        try:
            plaintext = chain.decrypt(envelope, aad=group_id.encode()).decode("utf-8")
        except ValueError:
            return
        kind = payload.get("kind", "text")
        self._persist(group_id)
        self.store.save_group_message(group_id, sender_hex, plaintext, kind=kind)
        if self.on_group_message:
            username = g["members"].get(sender_hex, sender_hex[:8])
            self.on_group_message(group_id, username, plaintext, kind)

    def _on_member_add(self, payload: dict) -> None:
        group_id = payload["group_id"]
        g = self.groups.get(group_id)
        if g is None:
            return
        member = payload["member"]
        g["members"][member["identity_pub"]] = member["username"]
        self._persist(group_id)
        self._notify_update(group_id)
        self._send_control(
            bytes.fromhex(member["identity_pub"]),
            member["username"],
            {
                "type": "group_sender_key",
                "group_id": group_id,
                "chain_key": g["my_chain"].chain_key.hex(),
                "index": g["my_chain"].index,
            },
        )

    def _on_member_remove(self, payload: dict) -> None:
        group_id = payload["group_id"]
        g = self.groups.get(group_id)
        if g is None:
            return
        removed_pub_hex = payload["member_identity_pub"]
        if removed_pub_hex == self.my_pub_hex:
            g["removed"] = True
            self._persist(group_id)
            self._notify_update(group_id)
            return
        g["members"].pop(removed_pub_hex, None)
        g["peer_chains"].pop(removed_pub_hex, None)
        self._persist(group_id)
        self._notify_update(group_id)

    # -- helpers -------------------------------------------------------------

    def _require_group(self, group_id: str) -> dict:
        g = self.groups.get(group_id)
        if g is None:
            raise ValueError(f"unknown group {group_id}")
        return g

    def _persist(self, group_id: str) -> None:
        g = self.groups[group_id]
        state = {
            "members": g["members"],
            "my_chain": {"chain_key": g["my_chain"].chain_key.hex(), "index": g["my_chain"].index},
            "peer_chains": {
                pub_hex: {"chain_key": c.chain_key.hex(), "index": c.index}
                for pub_hex, c in g["peer_chains"].items()
            },
            "removed": g.get("removed", False),
        }
        self.store.save_group(group_id, g["name"], state)

    def _notify_update(self, group_id: str) -> None:
        if self.on_group_update:
            self.on_group_update(group_id)

    def _send_control(self, identity_pub: bytes, username_hint: str, payload: dict) -> None:
        self._ensure_route_and_send(identity_pub, username_hint, json.dumps(payload))

    def _ensure_route_and_send(self, identity_pub: bytes, username_hint: str, text_json: str) -> None:
        fp = crypto.fingerprint(self.identity.public_bytes, identity_pub)
        if not self.net.is_connected(fp):
            route = self.resolve_route(identity_pub.hex()) if self.resolve_route else None
            if route and route.get("host") and route.get("tcp_port"):
                threading.Thread(
                    target=self._bg_connect_direct, args=(route["host"], route["tcp_port"]), daemon=True
                ).start()
            elif self.net.relay is not None:
                try:
                    self.net.connect_relay(identity_pub, username_hint)
                except ConnectionError:
                    pass
        self.net.send_when_ready(fp, text_json, kind="group")

    def _bg_connect_direct(self, host: str, port: int) -> None:
        try:
            self.net.connect_to_peer(host, port)
        except (ConnectionError, OSError):
            pass  # send_when_ready's own poll loop will time out and report failure
