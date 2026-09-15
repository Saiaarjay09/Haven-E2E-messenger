"""Images, GIFs, and stickers ride the exact same end-to-end encrypted
channel as text — a message's "kind" (already threaded through
network.py and groups.py since Phase 1/3) is "image", "gif", or
"sticker" instead of "text", and its content is this module's small JSON
envelope (filename + mime type + base64 bytes) instead of a plain string.
No changes to crypto.py, network.py, or storage.py were needed: they
already treat message content as an opaque string and encrypt/store it
identically regardless of kind.
"""

from __future__ import annotations

import base64
import json
import mimetypes
import os

MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024  # 8 MB — generous for a chat image/GIF, bounded to keep sends snappy


class AttachmentTooLarge(Exception):
    pass


def encode_attachment(file_path: str) -> str:
    size = os.path.getsize(file_path)
    if size > MAX_ATTACHMENT_BYTES:
        raise AttachmentTooLarge(
            f"{os.path.basename(file_path)} is {size // 1024} KB; the limit is {MAX_ATTACHMENT_BYTES // 1024} KB"
        )
    with open(file_path, "rb") as f:
        data = f.read()
    mime = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
    return json.dumps(
        {
            "filename": os.path.basename(file_path),
            "mime": mime,
            "data_b64": base64.b64encode(data).decode("ascii"),
        }
    )


def decode_attachment(text: str) -> dict:
    """Returns {"filename":..., "mime":..., "data": bytes}."""
    payload = json.loads(text)
    return {
        "filename": payload["filename"],
        "mime": payload["mime"],
        "data": base64.b64decode(payload["data_b64"]),
    }


def guess_kind(file_path: str) -> str:
    mime = mimetypes.guess_type(file_path)[0] or ""
    return "gif" if mime == "image/gif" else "image"
