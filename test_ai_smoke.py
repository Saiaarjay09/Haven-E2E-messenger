"""Headless smoke test for Phase 6: on-device AI (speech-to-text,
translation, and a local LLM assistant), plus live call captioning.
Everything here runs a REAL local model — no mocking of the AI itself —
but two things are handled as optional/skippable since they need a
one-time download this test won't force on every run:
  * the local LLM assistant needs a GGUF model file already present
    (set HAVEN_TEST_MODEL_PATH, or it looks for the file this session
    already downloaded to ~/.haven_models/ while building this feature)
  * speech synthesis for the STT/captioning fixtures uses macOS's `say`
    command, so those parts are skipped on non-macOS
Run: python3 test_ai_smoke.py
"""
import os
import shutil
import subprocess
import sys
import time
import wave
from pathlib import Path

from haven import ai

print("=== Translator (argos-translate, on-device) ===")
translated = ai.Translator.translate("Hello, how are you?", "en", "es")
print("en->es:", translated)
assert translated and translated.lower() != "hello, how are you?"
print("confirmed: on-device translation produced real Spanish output")

have_speech_fixture = shutil.which("say") is not None and shutil.which("afconvert") is not None
if not have_speech_fixture:
    print("\n(skipping STT/captioning tests — macOS `say`/`afconvert` not found on this machine)")
else:
    print("\n=== Transcriber (faster-whisper, on-device) ===")
    tmp_wav = "/tmp/haven_ai_test_speech.wav"
    tmp_aiff = "/tmp/haven_ai_test_speech.aiff"
    subprocess.run(["say", "-o", tmp_aiff, "Hello, this is a test of the translation feature."], check=True)
    subprocess.run(
        ["afconvert", tmp_aiff, tmp_wav, "-f", "WAVE", "-d", "LEI16@16000", "-c", "1"], check=True
    )
    with wave.open(tmp_wav, "rb") as w:
        assert w.getframerate() == 16000 and w.getnchannels() == 1
        pcm = w.readframes(w.getnframes())

    transcriber = ai.Transcriber(model_size="tiny")
    text, lang = transcriber.transcribe_pcm16(pcm)
    print("transcribed:", repr(text), "detected language:", lang)
    assert "test" in text.lower() and "translation" in text.lower()
    assert lang == "en"
    print("confirmed: on-device speech-to-text correctly transcribed synthesized speech")

    print("\n=== LiveCallCaptioner (STT + translation on buffered call audio) ===")
    captioner = ai.LiveCallCaptioner(transcriber, target_lang="es")
    captioner.BUFFER_SECONDS = 2.0  # our ~2.8s test clip is shorter than the module's real-use 3.0s default
    captions = []
    captioner.on_caption = lambda fp, orig, translated, lang: captions.append((fp, orig, translated, lang))
    # Feed the same real speech audio in small chunks, like live call audio would arrive.
    chunk_size = 3200  # 100ms @ 16kHz/16-bit, matching calls.py's AUDIO_BLOCK_SAMPLES chunking
    for i in range(0, len(pcm), chunk_size):
        captioner.feed("test-fingerprint", pcm[i : i + chunk_size])
    deadline = time.time() + 15
    while not captions and time.time() < deadline:
        time.sleep(0.2)
    assert captions, "live captioner never produced a caption from real speech audio"
    fp, original, translated_caption, detected = captions[0]
    print("caption:", repr(original), "->", repr(translated_caption), f"(detected: {detected})")
    assert "test" in original.lower()
    assert translated_caption != original  # should actually be translated to Spanish
    print("confirmed: live call captioning transcribes AND translates buffered audio")

    os.remove(tmp_aiff)
    os.remove(tmp_wav)

print("\n=== LocalAssistant (llama-cpp-python, on-device LLM) ===")
model_path = os.environ.get("HAVEN_TEST_MODEL_PATH") or str(
    Path.home() / ".haven_models" / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
)
if not os.path.exists(model_path):
    print(f"(skipping — no local model at {model_path}; set HAVEN_TEST_MODEL_PATH or download one first)")
else:
    assistant = ai.LocalAssistant(model_path)
    assert assistant.available()
    answer = assistant.ask("In one short sentence, what is end-to-end encryption?")
    print("model answered:", answer)
    assert len(answer) > 0
    print("confirmed: local LLM assistant answered a real prompt, fully on-device")

print("\nALL AI SMOKE TESTS COMPLETED (see above for anything skipped and why)")
