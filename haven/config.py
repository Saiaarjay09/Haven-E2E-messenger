"""Small per-account settings file (currently just relay server address)."""

from __future__ import annotations

import json
from pathlib import Path


def _path(data_dir: Path) -> Path:
    return data_dir / "config.json"


def load(data_dir: Path) -> dict:
    p = _path(data_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save(data_dir: Path, updates: dict) -> None:
    """Merges `updates` into the existing config rather than replacing it —
    relay settings and AI settings are saved independently of each other,
    and a naive overwrite here would silently wipe out whichever one
    wasn't part of the current save() call."""
    cfg = load(data_dir)
    cfg.update(updates)
    _path(data_dir).write_text(json.dumps(cfg, indent=2))


# -- relays (plural): different contacts can be reachable through different
# self-hosted relays, so an account can remember several, each keyed by
# "host:port". A single legacy relay_host/relay_port (from before multi-relay
# support existed) is migrated into this list the first time it's read.


def relay_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def list_relays(data_dir: Path) -> dict:
    """Returns {"host:port": {"name":..., "host":..., "port":...}, ...}."""
    cfg = load(data_dir)
    relays = dict(cfg.get("relays", {}))
    legacy_host, legacy_port = cfg.get("relay_host"), cfg.get("relay_port")
    if legacy_host and legacy_port:
        key = relay_key(legacy_host, legacy_port)
        if key not in relays:
            relays[key] = {"name": "Default relay", "host": legacy_host, "port": legacy_port}
            save(data_dir, {"relays": relays, "relay_host": None, "relay_port": None})
    return relays


def add_relay(data_dir: Path, name: str, host: str, port: int) -> str:
    relays = list_relays(data_dir)
    key = relay_key(host, port)
    relays[key] = {"name": name or key, "host": host, "port": port}
    save(data_dir, {"relays": relays})
    return key


def remove_relay(data_dir: Path, key: str) -> None:
    relays = list_relays(data_dir)
    relays.pop(key, None)
    save(data_dir, {"relays": relays})
