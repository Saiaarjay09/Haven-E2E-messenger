/**
 * Group voice/video calls. Same no-WebRTC design as 1:1 calls.js — audio
 * chunks and JPEG video frames are just messages — but fanned out via
 * the group's existing sender-keys mechanism (groups.js) instead of a
 * pairwise channel, so everyone in the call sends once and every other
 * member decrypts it with that sender's already-known chain. This is
 * the same mesh-of-broadcasts model group text messages already use;
 * a group call is not fundamentally different traffic, just faster and
 * more of it (up to ~10 audio messages/sec per participant).
 *
 * "Speaking" detection is a simple RMS amplitude check on each 100ms
 * PCM chunk (own mic included) — loud enough, recently enough, counts
 * as speaking; nothing fancier (no real voice-activity-detection model)
 * since a raw energy threshold is what genuinely fits this scale.
 */

const HavenGroupCalls = (() => {
  "use strict";
  const H = Haven;

  const AUDIO_SAMPLE_RATE = 16000;
  const AUDIO_BLOCK_SAMPLES = 1600; // 100ms @ 16kHz, matches calls.js/calls.py
  const VIDEO_FPS = 7;
  const VIDEO_SIZE = { width: 320, height: 240 };
  const VIDEO_JPEG_QUALITY = 0.5;
  const SPEAKING_RMS_THRESHOLD = 600; // out of a max possible ~32767
  const SPEAKING_HOLD_MS = 500; // how long "speaking" stays true after the last loud chunk

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
  function rms(int16) {
    let sum = 0;
    for (let i = 0; i < int16.length; i++) sum += int16[i] * int16[i];
    return Math.sqrt(sum / int16.length);
  }

  class GroupCallManager {
    constructor(groupManager) {
      this.gm = groupManager;

      this.onCallState = null; // (groupId, state) state in ringing/active/ended
      this.onIncomingGroupCall = null; // (groupId, fromUsername, hasVideo) => void
      this.onParticipantsChanged = null; // (groupId) => void — join/leave/speaking/video-frame updates
      this.onCallError = null; // (groupId, message) => void
      this.onAudioChunk = null; // (groupId, senderPubHex, int16Samples) => void — raw incoming PCM, for live translation

      this.calls = new Map(); // groupId -> call state
    }

    isActive(groupId) {
      return this.calls.has(groupId);
    }

    participants(groupId) {
      const call = this.calls.get(groupId);
      return call ? call.participants : new Map();
    }

    async startOrJoin(groupId, video) {
      let call = this.calls.get(groupId);
      const isStarting = !call;
      if (!call) {
        call = { video, participants: new Map(), stopped: false };
        this.calls.set(groupId, call);
      }
      await this._broadcast(groupId, { type: "group_call_join", video });
      await this._startMedia(groupId, video);
      this._notifyState(groupId, "active");
      return isStarting;
    }

    async leave(groupId) {
      const call = this.calls.get(groupId);
      if (!call) return;
      this._stopMedia(call);
      this.calls.delete(groupId);
      await this._broadcast(groupId, { type: "group_call_leave" }).catch(() => {});
      this._notifyState(groupId, "ended");
    }

    setMuted(groupId, muted) {
      const call = this.calls.get(groupId);
      if (call) call.muted = muted;
    }

    async handleIncoming(groupId, senderPubHex, senderUsername, text) {
      let payload;
      try {
        payload = JSON.parse(text);
      } catch (e) {
        return;
      }
      try {
        if (payload.type === "group_call_join") await this._onJoin(groupId, senderPubHex, senderUsername, payload);
        else if (payload.type === "group_call_leave") this._onLeave(groupId, senderPubHex);
        else if (payload.type === "group_call_audio") this._onAudio(groupId, senderPubHex, payload);
        else if (payload.type === "group_call_video") this._onVideo(groupId, senderPubHex, payload);
      } catch (e) {
        console.error("malformed group call frame, dropped:", e);
      }
    }

    async _onJoin(groupId, senderPubHex, senderUsername, payload) {
      const call = this.calls.get(groupId);
      if (!call) {
        // Someone started a call in a group we haven't joined yet — surface
        // it as an incoming call rather than silently tracking a ghost
        // participant list for a call we're not part of.
        if (this.onIncomingGroupCall) this.onIncomingGroupCall(groupId, senderUsername, !!payload.video);
        return;
      }
      const isNewParticipant = !call.participants.has(senderPubHex);
      call.participants.set(senderPubHex, {
        username: senderUsername,
        video: !!payload.video,
        speaking: false,
        speakingUntil: 0,
        videoUrl: null,
      });
      this._notifyParticipants(groupId);
      // Call membership isn't persisted state the way group chat
      // membership is — someone joining an in-progress call only
      // learns about participants who join AFTER them unless already-
      // present members announce themselves back. `reply: true` stops
      // this from becoming an infinite announce/reply loop between the
      // two sides.
      if (isNewParticipant && !payload.reply) {
        await this._broadcast(groupId, { type: "group_call_join", video: call.video, reply: true }).catch(() => {});
      }
    }

    _onLeave(groupId, senderPubHex) {
      const call = this.calls.get(groupId);
      if (!call) return;
      const p = call.participants.get(senderPubHex);
      if (p && p.videoUrl) URL.revokeObjectURL(p.videoUrl);
      call.participants.delete(senderPubHex);
      this._notifyParticipants(groupId);
    }

    _onAudio(groupId, senderPubHex, payload) {
      const call = this.calls.get(groupId);
      if (!call) return;
      const p = call.participants.get(senderPubHex);
      if (!p) return;
      const pcmBytes = base64ToBytes(payload.pcm_b64);
      const int16 = new Int16Array(pcmBytes.buffer, pcmBytes.byteOffset, pcmBytes.length / 2);
      if (call.playChunk) call.playChunk(senderPubHex, int16);
      if (this.onAudioChunk) this.onAudioChunk(groupId, senderPubHex, int16);
      if (rms(int16) > SPEAKING_RMS_THRESHOLD) {
        p.speaking = true;
        p.speakingUntil = Date.now() + SPEAKING_HOLD_MS;
        this._notifyParticipants(groupId);
        this._scheduleSpeakingDecay(groupId, senderPubHex);
      }
    }

    _onVideo(groupId, senderPubHex, payload) {
      const call = this.calls.get(groupId);
      if (!call) return;
      const p = call.participants.get(senderPubHex);
      if (!p) return;
      const jpegBytes = base64ToBytes(payload.jpg_b64);
      if (p.videoUrl) URL.revokeObjectURL(p.videoUrl);
      p.videoUrl = URL.createObjectURL(new Blob([jpegBytes], { type: "image/jpeg" }));
      this._notifyParticipants(groupId);
    }

    _scheduleSpeakingDecay(groupId, pubHex) {
      setTimeout(() => {
        const call = this.calls.get(groupId);
        if (!call) return;
        const p = call.participants.get(pubHex);
        if (!p) return;
        if (Date.now() >= p.speakingUntil && p.speaking) {
          p.speaking = false;
          this._notifyParticipants(groupId);
        }
      }, SPEAKING_HOLD_MS + 50);
    }

    _notifyState(groupId, state) {
      if (this.onCallState) this.onCallState(groupId, state);
    }
    _notifyParticipants(groupId) {
      if (this.onParticipantsChanged) this.onParticipantsChanged(groupId);
    }

    async _broadcast(groupId, payload) {
      await this.gm.sendGroupMessage(groupId, JSON.stringify(payload), "group_call");
    }

    // -- media: getUserMedia + Web Audio, same approach as calls.js -----------

    async _startMedia(groupId, video) {
      const call = this.calls.get(groupId);
      if (!call) return;
      call.muted = false;
      call.stopped = false;

      // One shared playback context for every remote participant, each
      // with its own scheduled-queue "next play time" so simultaneous
      // speakers correctly mix instead of stepping on each other.
      const playbackCtx = new AudioContext({ sampleRate: AUDIO_SAMPLE_RATE });
      const nextPlayTimes = new Map();
      call.playbackCtx = playbackCtx;
      call.playChunk = (pubHex, int16) => {
        const float32 = new Float32Array(int16.length);
        for (let i = 0; i < int16.length; i++) float32[i] = int16[i] / 0x8000;
        const buffer = playbackCtx.createBuffer(1, float32.length, AUDIO_SAMPLE_RATE);
        buffer.copyToChannel(float32, 0);
        const src = playbackCtx.createBufferSource();
        src.buffer = buffer;
        src.connect(playbackCtx.destination);
        const startAt = Math.max(playbackCtx.currentTime, nextPlayTimes.get(pubHex) || 0);
        src.start(startAt);
        nextPlayTimes.set(pubHex, startAt + buffer.duration);
      };

      try {
        const micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const captureCtx = new AudioContext({ sampleRate: AUDIO_SAMPLE_RATE });
        const source = captureCtx.createMediaStreamSource(micStream);
        const processor = captureCtx.createScriptProcessor(AUDIO_BLOCK_SAMPLES, 1, 1);
        const silentGain = captureCtx.createGain();
        silentGain.gain.value = 0;
        processor.onaudioprocess = (e) => {
          if (call.stopped || call.muted) return;
          const input = e.inputBuffer.getChannelData(0);
          const pcm16 = new Int16Array(input.length);
          for (let i = 0; i < input.length; i++) {
            const s = Math.max(-1, Math.min(1, input[i]));
            pcm16[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
          }
          this._broadcast(groupId, { type: "group_call_audio", pcm_b64: bytesToBase64(new Uint8Array(pcm16.buffer)) }).catch(
            (e2) => console.error("broadcast audio failed:", e2)
          );
        };
        source.connect(processor);
        processor.connect(silentGain);
        silentGain.connect(captureCtx.destination);
        call.micStream = micStream;
        call.captureCtx = captureCtx;
        call.processor = processor;
      } catch (e) {
        this._reportError(groupId, "Microphone error: " + e.message);
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
                await this._broadcast(groupId, { type: "group_call_video", jpg_b64: bytesToBase64(jpegBytes) }).catch((e2) =>
                  console.error("broadcast video failed:", e2)
                );
              },
              "image/jpeg",
              VIDEO_JPEG_QUALITY
            );
          }, 1000 / VIDEO_FPS);
        } catch (e) {
          this._reportError(groupId, "Camera error: " + e.message);
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
      for (const p of call.participants.values()) {
        if (p.videoUrl) URL.revokeObjectURL(p.videoUrl);
      }
    }

    _reportError(groupId, message) {
      if (this.onCallError) this.onCallError(groupId, message);
    }
  }

  return { GroupCallManager };
})();
