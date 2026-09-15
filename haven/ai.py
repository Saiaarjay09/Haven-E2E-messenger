"""On-device AI: a local assistant, speech-to-text, and text translation.

Nothing here ever calls a cloud API. Every model runs locally via
`llama-cpp-python` (assistant), `faster-whisper` (speech-to-text), and
`argos-translate` (translation) — inference happens entirely on this
machine, and a result never reaches your contacts unless you explicitly
send it as a chat message yourself. The one unavoidable exception to
"fully offline" is a ONE-TIME download of model weights (the same
tradeoff any offline AI feature has — the app needs the model file
before it can run without a network). After that download, everything
above works with no network access at all.

Because this environment's Python install doesn't always trust the
system CA store, we point requests at certifi's bundle up front so that
one-time model download doesn't fail with a confusing SSL error.
"""

from __future__ import annotations

import os
import threading

try:
    import certifi

    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
    os.environ.setdefault("REQUESTS_CA_BUNDLE", certifi.where())
except ImportError:
    pass

DEFAULT_MODEL_URL = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"
DEFAULT_MODEL_SIZE_MB = 490


def download_default_model(dest_path: str, on_progress=None) -> None:
    """One-time fetch of a small (~490MB) local instruct model. Needs a
    network connection for this call only — everything downstream runs
    fully offline once the file exists at dest_path."""
    import urllib.request

    def _hook(block_num, block_size, total_size):
        if on_progress and total_size > 0:
            on_progress(min(1.0, block_num * block_size / total_size))

    urllib.request.urlretrieve(DEFAULT_MODEL_URL, dest_path, _hook)


class LocalAssistant:
    """A local LLM you can ask questions in chat with "/ai <question>".
    The question and answer never leave this device or touch any
    contact's session unless you copy the answer into a message yourself."""

    def __init__(self, model_path: str | None):
        self.model_path = model_path
        self._llm = None
        self._lock = threading.Lock()

    def available(self) -> bool:
        return bool(self.model_path) and os.path.exists(self.model_path)

    def _ensure_loaded(self):
        if self._llm is not None:
            return
        from llama_cpp import Llama

        self._llm = Llama(model_path=self.model_path, n_ctx=2048, verbose=False)

    def ask(self, prompt: str) -> str:
        if not self.available():
            raise RuntimeError("No local AI model configured yet — set one up in AI settings.")
        with self._lock:
            self._ensure_loaded()
            out = self._llm.create_chat_completion(
                messages=[{"role": "user", "content": prompt}], max_tokens=300
            )
            return out["choices"][0]["message"]["content"].strip()


class Transcriber:
    """Local speech-to-text via faster-whisper. The `tiny` model downloads
    once (~75MB) the first time it's used, then runs fully offline."""

    def __init__(self, model_size: str = "tiny"):
        self.model_size = model_size
        self._model = None
        self._lock = threading.Lock()

    def _ensure_loaded(self):
        if self._model is not None:
            return
        from faster_whisper import WhisperModel

        self._model = WhisperModel(self.model_size, device="cpu", compute_type="int8")

    def transcribe_pcm16(self, pcm_bytes: bytes, sample_rate: int = 16000) -> tuple[str, str | None]:
        """Returns (text, detected_language_code)."""
        import numpy as np

        with self._lock:
            self._ensure_loaded()
            audio = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32) / 32768.0
            segments, info = self._model.transcribe(audio, language=None)
            text = " ".join(seg.text for seg in segments).strip()
            return text, getattr(info, "language", None)


class Translator:
    """Local text translation via argos-translate. Each language PAIR
    downloads its own small package (~50-100MB) once, on first use."""

    _installed_pairs: set[tuple[str, str]] = set()
    _lock = threading.Lock()

    @classmethod
    def ensure_pair_installed(cls, from_code: str, to_code: str) -> None:
        key = (from_code, to_code)
        with cls._lock:
            if key in cls._installed_pairs:
                return
            import argostranslate.package

            installed = argostranslate.package.get_installed_packages()
            if any(p.from_code == from_code and p.to_code == to_code for p in installed):
                cls._installed_pairs.add(key)
                return
            argostranslate.package.update_package_index()
            available = argostranslate.package.get_available_packages()
            pkg = next((p for p in available if p.from_code == from_code and p.to_code == to_code), None)
            if pkg is None:
                raise RuntimeError(f"No offline translation package available for {from_code} -> {to_code}")
            path = pkg.download()
            argostranslate.package.install_from_path(path)
            cls._installed_pairs.add(key)

    @classmethod
    def translate(cls, text: str, from_code: str, to_code: str) -> str:
        if not text or from_code == to_code:
            return text
        cls.ensure_pair_installed(from_code, to_code)
        import argostranslate.translate

        return argostranslate.translate.translate(text, from_code, to_code)


class LiveCallCaptioner:
    """Buffers a few seconds of incoming call audio per contact and runs
    STT + translation on each buffered chunk, surfacing captions via a
    callback. Purely additive — it observes CallManager's incoming audio
    (see CallManager.on_remote_audio_chunk) without touching playback, so
    a captioning failure can never break the call itself."""

    BUFFER_SECONDS = 3.0
    SAMPLE_RATE = 16000

    def __init__(self, transcriber: Transcriber, target_lang: str | None):
        self.transcriber = transcriber
        self.target_lang = target_lang
        self.on_caption = None  # callback(fingerprint, original_text, translated_text, detected_lang)
        self._buffers: dict[str, bytearray] = {}
        self._lock = threading.Lock()

    def feed(self, fingerprint: str, pcm_bytes: bytes) -> None:
        chunk = None
        with self._lock:
            buf = self._buffers.setdefault(fingerprint, bytearray())
            buf.extend(pcm_bytes)
            needed = int(self.BUFFER_SECONDS * self.SAMPLE_RATE * 2)
            if len(buf) >= needed:
                chunk = bytes(buf[:needed])
                del buf[:needed]
        if chunk is not None:
            threading.Thread(target=self._process, args=(fingerprint, chunk), daemon=True).start()

    def reset(self, fingerprint: str) -> None:
        with self._lock:
            self._buffers.pop(fingerprint, None)

    def _process(self, fingerprint: str, chunk: bytes) -> None:
        try:
            text, detected_lang = self.transcriber.transcribe_pcm16(chunk)
            if not text:
                return
            translated = text
            if self.target_lang and detected_lang and detected_lang != self.target_lang:
                translated = Translator.translate(text, detected_lang, self.target_lang)
            if self.on_caption:
                self.on_caption(fingerprint, text, translated, detected_lang)
        except Exception:
            pass  # captioning is best-effort — never let it break the call
