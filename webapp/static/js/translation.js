/**
 * Live call translation. Explicitly NOT private the way the rest of
 * this app is — this is the one deliberate exception (see the user's
 * own choice when this was built): a few seconds of the other person's
 * call audio at a time is sent to OpenAI's Whisper API for translation
 * to English, via this app's own accounts server acting as a proxy.
 * It leaves the conversation (which nothing else in this app does),
 * but the OpenAI API key never leaves the server — deliberately NOT
 * embedded here, unlike the Giphy key. Giphy keys are meant to be
 * public/client-side (they only identify the app for rate limiting);
 * an OpenAI key is tied to real billing, so shipping it in this
 * public repo's client-side JS would let anyone who finds it run up
 * charges on the account that owns it. See webapp/accounts_server.py's
 * /api/translate for the server side of this — it reads
 * HAVEN_OPENAI_API_KEY from the environment, never from a request.
 * Only used for audio a call participant is already hearing anyway
 * (this device's own decrypted playback), never at rest and never for
 * text messages.
 */

const HavenTranslation = (() => {
  "use strict";

  // Matches app.js's defaultAccountsUrl() — this deployment's fixed
  // accounts server, which now also proxies translation requests.
  const TRANSLATE_URL = "https://haven.taila6d3cb.ts.net:8443/api/translate";

  const SAMPLE_RATE = 16000;
  const MAX_BUFFER_SECONDS = 4; // flush at this many seconds regardless, so captions stay roughly real-time
  const MIN_UTTERANCE_SECONDS = 0.6; // shorter than this is almost certainly noise/silence, not speech
  const SILENCE_RMS_THRESHOLD = 250;
  const SILENCE_CHUNKS_TO_FLUSH = 6; // ~600ms of quiet (100ms chunks) after speech ends an utterance

  function rms(int16) {
    let sum = 0;
    for (let i = 0; i < int16.length; i++) sum += int16[i] * int16[i];
    return Math.sqrt(sum / int16.length);
  }

  // Wraps raw 16kHz mono PCM in a minimal WAV header — Whisper's API
  // needs an actual audio file, not headerless samples.
  function pcm16ToWavBlob(int16Samples, sampleRate) {
    const numSamples = int16Samples.length;
    const buffer = new ArrayBuffer(44 + numSamples * 2);
    const view = new DataView(buffer);
    const writeString = (offset, str) => {
      for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
    };
    writeString(0, "RIFF");
    view.setUint32(4, 36 + numSamples * 2, true);
    writeString(8, "WAVE");
    writeString(12, "fmt ");
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true); // PCM
    view.setUint16(22, 1, true); // mono
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeString(36, "data");
    view.setUint32(40, numSamples * 2, true);
    for (let i = 0; i < numSamples; i++) view.setInt16(44 + i * 2, int16Samples[i], true);
    return new Blob([buffer], { type: "audio/wav" });
  }

  async function translateUtterance(int16Samples) {
    const wavBlob = pcm16ToWavBlob(int16Samples, SAMPLE_RATE);
    const formData = new FormData();
    formData.append("file", wavBlob, "audio.wav");
    const resp = await fetch(TRANSLATE_URL, { method: "POST", body: formData });
    if (resp.status === 503) throw new Error("Translation isn't configured on the server yet.");
    if (!resp.ok) throw new Error(`Translation request failed (${resp.status})`);
    const data = await resp.json();
    return { text: (data.text || "").trim(), language: (data.language || "").toLowerCase() };
  }

  // Accumulates one participant's incoming audio chunks and calls back
  // with each complete utterance's translation — only when it detects
  // the source wasn't already English, matching "if another language is
  // spoken, translate it" rather than captioning every single word.
  class SpeakerBuffer {
    constructor(onCaption, onError) {
      this.chunks = [];
      this.silenceStreak = 0;
      this.onCaption = onCaption;
      this.onError = onError;
      this.busy = false;
    }

    push(int16) {
      this.chunks.push(int16);
      const totalSamples = this.chunks.reduce((n, c) => n + c.length, 0);
      if (rms(int16) < SILENCE_RMS_THRESHOLD) this.silenceStreak++;
      else this.silenceStreak = 0;

      const hasEnoughForPause = this.silenceStreak >= SILENCE_CHUNKS_TO_FLUSH && totalSamples > SAMPLE_RATE * MIN_UTTERANCE_SECONDS;
      const hitMaxBuffer = totalSamples >= SAMPLE_RATE * MAX_BUFFER_SECONDS;
      if (hasEnoughForPause || hitMaxBuffer) this._flush();
    }

    _flush() {
      const totalSamples = this.chunks.reduce((n, c) => n + c.length, 0);
      const chunks = this.chunks;
      this.chunks = [];
      this.silenceStreak = 0;
      if (totalSamples < SAMPLE_RATE * MIN_UTTERANCE_SECONDS || this.busy) return; // too short to be real speech, or already translating
      const merged = new Int16Array(totalSamples);
      let offset = 0;
      for (const c of chunks) {
        merged.set(c, offset);
        offset += c.length;
      }
      this.busy = true;
      translateUtterance(merged)
        .then(({ text, language }) => {
          this.busy = false;
          if (!text) return;
          if (language && (language === "english" || language === "en")) return; // already English — nothing to show
          this.onCaption(text, language);
        })
        .catch((e) => {
          this.busy = false;
          if (this.onError) this.onError(e);
        });
    }
  }

  return {
    // Whether the server has a key configured isn't knowable from here
    // without an extra round-trip, so this is always true — an
    // unconfigured server just surfaces as an occasional console error
    // via SpeakerBuffer's onError callback (calls/captions otherwise
    // keep working fine).
    SpeakerBuffer,
    configured: true,
  };
})();
