"""Recovery phrases: a human-writable secondary unlock mechanism.

Used by identity.py's desktop "forgot password" flow (a second, independent
local copy of your identity key encrypted with a phrase instead of your
password) and by webapp/'s hosted equivalent (same idea, server-mediated).

This borrows the standard 2048-word BIP39 English wordlist (haven/data/
wordlist.txt) — not the BIP39 mnemonic algorithm itself (there's no
checksum here and the phrase doesn't deterministically derive your keys,
it's just used as high-entropy password material for the same scrypt+
AES-GCM scheme as your regular password). The wordlist is reused because
it was carefully hand-curated for exactly this purpose: no two words
share a long prefix, and nothing looks similar enough to another word to
cause a transcription error when someone copies it down by hand.
"""

from __future__ import annotations

import os
from pathlib import Path

_WORDLIST_PATH = Path(__file__).parent / "data" / "wordlist.txt"
_WORDLIST = _WORDLIST_PATH.read_text().split()
assert len(_WORDLIST) == 2048, f"expected 2048 words, found {len(_WORDLIST)}"


def generate_recovery_phrase(num_words: int = 12) -> str:
    """~11 bits of entropy per word, drawn from os.urandom (not the
    non-cryptographic `random` module) — 12 words is 132 bits, far beyond
    anything a scrypt-hardened offline attack could reach."""
    indices = [int.from_bytes(os.urandom(2), "big") % len(_WORDLIST) for _ in range(num_words)]
    return " ".join(_WORDLIST[i] for i in indices)


def normalize_phrase(phrase: str) -> str:
    """Collapses whitespace and case differences so a recovery phrase
    typed back in still matches regardless of extra spaces or capitalization."""
    return " ".join(phrase.strip().lower().split())
