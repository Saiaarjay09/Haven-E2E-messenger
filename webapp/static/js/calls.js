/**
 * Voice and video calls — the browser port of haven/calls.py. Same
 * deliberate design choice as desktop: no WebRTC, no ICE/STUN/TURN, no
 * separate media key exchange. Call signaling (offer/answer/reject/end)
 * and every audio/video chunk are just messages with kind="call" riding
 * the exact same end-to-end encrypted 1:1 ratchet session as text — so a
 * call is exactly as private as a text message, and a web client can
 * call a desktop client (or vice versa) since the wire format matches
 * exactly: 16kHz mono 16-bit PCM audio chunks, JPEG video frames.
 *
 * The honest tradeoff (see calls.py's own docstring) is real: every
 * audio/video chunk pays for a full encrypted message rather than a
 * lightweight unencrypted-transport RTP packet, and delivery is
 * in-order/reliable rather than "drop late packets" the way real-time
 * media transports prefer. Walkie-talkie/early-Skype quality, not
 * enterprise telephony — that's an accepted, documented tradeoff, not
 * an oversight.
 */

const HavenCalls = (() => {
  "use strict";
  const H = Haven;

  const AUDIO_SAMPLE_RATE = 16000;
  const AUDIO_BLOCK_SAMPLES = 1600; // 100ms @ 16kHz, matches calls.py exactly
  const VIDEO_FPS = 7;
  const VIDEO_SIZE = { width: 320, height: 240 };
  const VIDEO_JPEG_QUALITY = 0.5;

  function bytesToBase64(bytes) {
    let bin = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    return btoa(bin);
  }
  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  class CallManager {
    constructor(net, identity, username) {
      this.net = net;
      this.identity = identity;
      this.username = username;

      this.onIncomingCall = null; // (fingerprint, callId, hasVideo) => void
      this.onCallState = null; // (fingerprint, state) state in ringing_out/active/ended/rejected/error
      this.onCallError = null; // (fingerprint, message) => void
      this.onRemoteVideoFrame = null; // (fingerprint, blobUrl) => void
      this.onLocalVideoFrame = null; // (fingerprint, blobUrl) => void — self-view preview
      this.onAudioChunk = null; // (fingerprint, int16Samples) => void — raw incoming PCM, for live translation (see translation.js)

      this.calls = new Map(); // fingerprint -> call state
    }

    // -- signaling ------------------------------------------------------------

    async startCall(fingerprint, video = false) {
      const callId = H.bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
      this.calls.set(fingerprint, { callId, video, state: "ringing_out" });
      await this.net.sendText(fingerprint, JSON.stringify({ type: "call_offer", call_id: callId, video }), "call");
      this._notifyState(fingerprint, "ringing_out");
      return callId;
    }

    async acceptCall(fingerprint) {
      const call = this.calls.get(fingerprint);
      if (!call) return;
      await this.net.sendText(fingerprint, JSON.stringify({ type: "call_answer", call_id: call.callId, accepted: true }), "call");
      call.state = "active";
      // The call UI (hang up/mute) must not wait on getUserMedia's
      // permission prompt — that can take seconds, be ignored, or never
      // resolve at all, and the call is already connected from a
      // signaling standpoint regardless of mic/camera permission state.
      this._notifyState(fingerprint, "active");
      this._startMedia(fingerprint, call.video).catch((e) => this._reportError(fingerprint, "Media error: " + e.message));
    }

    async rejectCall(fingerprint) {
      const call = this.calls.get(fingerprint);
      this.calls.delete(fingerprint);
      if (call) {
        try {
          await this.net.sendText(fingerprint, JSON.stringify({ type: "call_reject", call_id: call.callId }), "call");
        } catch (e) {
          /* best-effort */
        }
      }
      this._notifyState(fingerprint, "rejected");
    }

    async hangup(fingerprint) {
      const call = this.calls.get(fingerprint);
      this.calls.delete(fingerprint);
      if (call) {
        this._stopMedia(call);
        try {
          await this.net.sendText(fingerprint, JSON.stringify({ type: "call_end", call_id: call.callId }), "call");
        } catch (e) {
          /* best-effort */
        }
      }
      this._notifyState(fingerprint, "ended");
    }

    setMuted(fingerprint, muted) {
      const call = this.calls.get(fingerprint);
      if (call) call.muted = muted;
    }

    async handleIncoming(fingerprint, text) {
      let payload;
      try {
        payload = JSON.parse(text);
      } catch (e) {
        return;
      }
      try {
        const t = payload.type;
        if (t === "call_offer") await this._onOffer(fingerprint, payload);
        else if (t === "call_answer") await this._onAnswer(fingerprint, payload);
        else if (t === "call_reject") {
          this.calls.delete(fingerprint);
          this._notifyState(fingerprint, "rejected");
        } else if (t === "call_end") {
          const call = this.calls.get(fingerprint);
          this.calls.delete(fingerprint);
          if (call) this._stopMedia(call);
          this._notifyState(fingerprint, "ended");
        } else if (t === "call_audio") this._onAudio(fingerprint, payload);
        else if (t === "call_video") this._onVideo(fingerprint, payload);
      } catch (e) {
        console.error("malformed call control frame, dropped:", e);
      }
    }

    async _onOffer(fingerprint, payload) {
      const video = !!payload.video;
      this.calls.set(fingerprint, { callId: payload.call_id, video, state: "ringing_in" });
      if (this.onIncomingCall) this.onIncomingCall(fingerprint, payload.call_id, video);
    }

    async _onAnswer(fingerprint, payload) {
      const call = this.calls.get(fingerprint);
      if (!call || call.callId !== payload.call_id) return;
      if (payload.accepted) {
        call.state = "active";
        this._notifyState(fingerprint, "active");
        this._startMedia(fingerprint, call.video).catch((e) => this._reportError(fingerprint, "Media error: " + e.message));
      } else {
        this.calls.delete(fingerprint);
        this._notifyState(fingerprint, "rejected");
      }
    }

    _notifyState(fingerprint, state) {
      if (this.onCallState) this.onCallState(fingerprint, state);
    }

    // -- media: pure send/receive (hardware-independent, directly testable) ---

    async sendAudioChunk(fingerprint, pcmBytes) {
      const call = this.calls.get(fingerprint);
      if (!call) return;
      const seq = call.audioSeq || 0;
      call.audioSeq = seq + 1;
      const payload = JSON.stringify({ type: "call_audio", call_id: call.callId, seq, pcm_b64: bytesToBase64(pcmBytes) });
      await this.net.sendText(fingerprint, payload, "call");
    }

    _onAudio(fingerprint, payload) {
      const call = this.calls.get(fingerprint);
      if (!call || call.callId !== payload.call_id) return;
      const pcm = base64ToBytes(payload.pcm_b64);
      const int16 = new Int16Array(pcm.buffer, pcm.byteOffset, pcm.length / 2);
      if (call.playChunk) call.playChunk(int16);
      if (this.onAudioChunk) this.onAudioChunk(fingerprint, int16);
    }

    async sendVideoFrame(fingerprint, jpegBytes) {
      const call = this.calls.get(fingerprint);
      if (!call) return;
      const seq = call.videoSeq || 0;
      call.videoSeq = seq + 1;
      const payload = JSON.stringify({ type: "call_video", call_id: call.callId, seq, jpg_b64: bytesToBase64(jpegBytes) });
      await this.net.sendText(fingerprint, payload, "call");
    }

    _onVideo(fingerprint, payload) {
      const call = this.calls.get(fingerprint);
      if (!call || call.callId !== payload.call_id) return;
      const jpegBytes = base64ToBytes(payload.jpg_b64);
      const url = URL.createObjectURL(new Blob([jpegBytes], { type: "image/jpeg" }));
      if (this.onRemoteVideoFrame) this.onRemoteVideoFrame(fingerprint, url);
    }

    // -- media: real hardware capture/playback (getUserMedia + Web Audio) -----

    async _startMedia(fingerprint, video) {
      const call = this.calls.get(fingerprint);
      if (!call) return; // hung up already, before this (unawaited) setup got a chance to run
      call.muted = false;
      call.stopped = false;

      // Playback: a small scheduled-queue player so back-to-back 100ms PCM
      // chunks play smoothly instead of overlapping or gapping.
      const playbackCtx = new AudioContext({ sampleRate: AUDIO_SAMPLE_RATE });
      let nextPlayTime = 0;
      call.playbackCtx = playbackCtx;
      call.playChunk = (int16) => {
        const float32 = new Float32Array(int16.length);
        for (let i = 0; i < int16.length; i++) float32[i] = int16[i] / 0x8000;
        const buffer = playbackCtx.createBuffer(1, float32.length, AUDIO_SAMPLE_RATE);
        buffer.copyToChannel(float32, 0);
        const src = playbackCtx.createBufferSource();
        src.buffer = buffer;
        src.connect(playbackCtx.destination);
        const startAt = Math.max(playbackCtx.currentTime, nextPlayTime);
        src.start(startAt);
        nextPlayTime = startAt + buffer.duration;
      };

      try {
        const micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const captureCtx = new AudioContext({ sampleRate: AUDIO_SAMPLE_RATE });
        const source = captureCtx.createMediaStreamSource(micStream);
        const processor = captureCtx.createScriptProcessor(AUDIO_BLOCK_SAMPLES, 1, 1);
        const silentGain = captureCtx.createGain();
        silentGain.gain.value = 0; // ScriptProcessorNode needs a path to destination to keep firing, but we don't want to hear ourselves
        processor.onaudioprocess = (e) => {
          if (call.stopped || call.muted) return;
          const input = e.inputBuffer.getChannelData(0);
          const pcm16 = new Int16Array(input.length);
          for (let i = 0; i < input.length; i++) {
            const s = Math.max(-1, Math.min(1, input[i]));
            pcm16[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
          }
          this.sendAudioChunk(fingerprint, new Uint8Array(pcm16.buffer)).catch((e2) => console.error("send audio failed:", e2));
        };
        source.connect(processor);
        processor.connect(silentGain);
        silentGain.connect(captureCtx.destination);
        call.micStream = micStream;
        call.captureCtx = captureCtx;
        call.processor = processor;
      } catch (e) {
        this._reportError(fingerprint, "Microphone error: " + e.message);
      }

      if (video) {
        try {
          const videoStream = await navigator.mediaDevices.getUserMedia({ video: VIDEO_SIZE });
          const videoEl = document.createElement("video");
          videoEl.srcObject = videoStream;
          videoEl.muted = true;
          videoEl.playsInline = true;
          await videoEl.play();
          const canvas = document.createElement("canvas");
          canvas.width = VIDEO_SIZE.width;
          canvas.height = VIDEO_SIZE.height;
          const ctx2d = canvas.getContext("2d");
          call.videoStream = videoStream;
          call.videoTimer = setInterval(() => {
            if (call.stopped) return;
            ctx2d.drawImage(videoEl, 0, 0, canvas.width, canvas.height);
            canvas.toBlob(
              async (blob) => {
                if (!blob || call.stopped) return;
                const jpegBytes = new Uint8Array(await blob.arrayBuffer());
                if (this.onLocalVideoFrame) this.onLocalVideoFrame(fingerprint, URL.createObjectURL(blob));
                try {
                  await this.sendVideoFrame(fingerprint, jpegBytes);
                } catch (e2) {
                  console.error("send video failed:", e2);
                }
              },
              "image/jpeg",
              VIDEO_JPEG_QUALITY
            );
          }, 1000 / VIDEO_FPS);
        } catch (e) {
          this._reportError(fingerprint, "Camera error: " + e.message);
        }
      }
    }

    _stopMedia(call) {
      call.stopped = true;
      if (call.videoTimer) clearInterval(call.videoTimer);
      if (call.micStream) call.micStream.getTracks().forEach((t) => t.stop());
      if (call.videoStream) call.videoStream.getTracks().forEach((t) => t.stop());
      if (call.processor) call.processor.disconnect();
      if (call.captureCtx) call.captureCtx.close().catch(() => {});
      if (call.playbackCtx) call.playbackCtx.close().catch(() => {});
    }

    _reportError(fingerprint, message) {
      if (this.onCallError) this.onCallError(fingerprint, message);
    }
  }

  return { CallManager };
})();
