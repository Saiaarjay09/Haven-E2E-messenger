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
