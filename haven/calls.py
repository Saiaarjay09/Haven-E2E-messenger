"""Voice and video calls, layered on the exact same end-to-end encrypted
1:1 channel as text and attachments — call signaling (offer/answer/
reject/end) and every audio/video frame are just messages with
kind="call", riding whatever transport (direct LAN or relay) is already
connected to that contact. No WebRTC, no ICE/STUN/TURN, no separate
media key exchange: this reuses network.NetworkManager's existing
ratchet session, so a call is exactly as private as a text message.

The honest tradeoff for building it this way instead of real-time
SRTP-over-UDP: every audio/video chunk pays the cost of a full encrypted
message (ratchet step, JSON framing, a TCP write) rather than a
lightweight unencrypted-transport-but-content-encrypted RTP packet, and
delivery is in-order/reliable rather than "drop late packets" the way
real-time media transports prefer. For a chat app between friends over a
home relay or LAN this is perfectly usable (roughly walkie-talkie/early
Skype quality expectations), not enterprise-grade telephony — see
ROADMAP.md.

Capture/playback uses `sounddevice` (audio) and `opencv-python` (video),
both optional: a missing library or a denied OS microphone/camera
permission is reported as a call error rather than crashing the app.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time

try:
    import numpy as np
    import sounddevice as sd

    HAS_AUDIO = True
except ImportError:
    HAS_AUDIO = False

try:
    import cv2

    HAS_VIDEO = True
except ImportError:
    HAS_VIDEO = False

AUDIO_SAMPLE_RATE = 16000
AUDIO_BLOCK_SAMPLES = 1600  # 100ms per chunk @ 16kHz — see module docstring on the latency tradeoff
VIDEO_FPS = 7
VIDEO_SIZE = (320, 240)
VIDEO_JPEG_QUALITY = 50


class CallManager:
    def __init__(self, net, identity, username: str):
        self.net = net
        self.identity = identity
        self.username = username

        self.on_incoming_call = None  # callback(fingerprint, call_id, has_video)
        self.on_call_state = None  # callback(fingerprint, state) state in ringing_out/active/ended/rejected/error
        self.on_call_error = None  # callback(fingerprint, message)
        self.on_remote_video_frame = None  # callback(fingerprint, jpeg_bytes)
        self.on_local_video_frame = None  # callback(fingerprint, jpeg_bytes) — for a self-view preview
        self.on_remote_audio_chunk = None  # callback(fingerprint, pcm_bytes) — additive, e.g. live captioning

        self.calls: dict[str, dict] = {}  # fingerprint -> call state

    # -- signaling ------------------------------------------------------------

    def start_call(self, fingerprint: str, video: bool = False) -> str:
        call_id = os.urandom(8).hex()
        self.calls[fingerprint] = {"call_id": call_id, "video": video, "state": "ringing_out"}
        self.net.send_text(
            fingerprint, json.dumps({"type": "call_offer", "call_id": call_id, "video": video}), kind="call"
        )
        self._notify_state(fingerprint, "ringing_out")
        return call_id

    def accept_call(self, fingerprint: str) -> None:
        call = self.calls.get(fingerprint)
        if call is None:
            return
        self.net.send_text(
            fingerprint, json.dumps({"type": "call_answer", "call_id": call["call_id"], "accepted": True}), kind="call"
        )
        call["state"] = "active"
        self._start_media(fingerprint, call["video"])
        self._notify_state(fingerprint, "active")

    def reject_call(self, fingerprint: str) -> None:
        call = self.calls.pop(fingerprint, None)
        if call is not None:
            try:
                self.net.send_text(
                    fingerprint, json.dumps({"type": "call_reject", "call_id": call["call_id"]}), kind="call"
                )
            except ConnectionError:
                pass
        self._notify_state(fingerprint, "rejected")

    def hangup(self, fingerprint: str) -> None:
        call = self.calls.pop(fingerprint, None)
        if call is not None:
            self._stop_media(call)
            try:
                self.net.send_text(fingerprint, json.dumps({"type": "call_end", "call_id": call["call_id"]}), kind="call")
            except ConnectionError:
                pass
        self._notify_state(fingerprint, "ended")

    def set_muted(self, fingerprint: str, muted: bool) -> None:
        call = self.calls.get(fingerprint)
        if call is not None:
            call["muted"] = muted

    def handle_incoming(self, fingerprint: str, text: str) -> None:
        try:
            payload = json.loads(text)
            t = payload.get("type")
            if t == "call_offer":
                self._on_offer(fingerprint, payload)
            elif t == "call_answer":
                self._on_answer(fingerprint, payload)
            elif t == "call_reject":
                self.calls.pop(fingerprint, None)
                self._notify_state(fingerprint, "rejected")
            elif t == "call_end":
                call = self.calls.pop(fingerprint, None)
                if call is not None:
                    self._stop_media(call)
                self._notify_state(fingerprint, "ended")
            elif t == "call_audio":
                self._on_audio(fingerprint, payload)
            elif t == "call_video":
                self._on_video(fingerprint, payload)
        except (KeyError, ValueError, json.JSONDecodeError):
            pass  # malformed call-control frame — drop it rather than crash

    def _on_offer(self, fingerprint: str, payload: dict) -> None:
        call_id = payload["call_id"]
        video = payload.get("video", False)
        self.calls[fingerprint] = {"call_id": call_id, "video": video, "state": "ringing_in"}
        if self.on_incoming_call:
            self.on_incoming_call(fingerprint, call_id, video)

    def _on_answer(self, fingerprint: str, payload: dict) -> None:
        call = self.calls.get(fingerprint)
        if call is None or call["call_id"] != payload["call_id"]:
            return
        if payload.get("accepted"):
            call["state"] = "active"
            self._start_media(fingerprint, call["video"])
            self._notify_state(fingerprint, "active")
        else:
            self.calls.pop(fingerprint, None)
            self._notify_state(fingerprint, "rejected")

    def _notify_state(self, fingerprint: str, state: str) -> None:
        if self.on_call_state:
            self.on_call_state(fingerprint, state)

    # -- media: pure send/receive (hardware-independent, directly testable) ---

    def send_audio_chunk(self, fingerprint: str, pcm_bytes: bytes) -> None:
        call = self.calls.get(fingerprint)
        if call is None:
            return
        seq = call.get("audio_seq", 0)
        call["audio_seq"] = seq + 1
        payload = json.dumps(
            {
                "type": "call_audio",
                "call_id": call["call_id"],
                "seq": seq,
                "pcm_b64": base64.b64encode(pcm_bytes).decode("ascii"),
            }
        )
        self.net.send_text(fingerprint, payload, kind="call")

    def _on_audio(self, fingerprint: str, payload: dict) -> None:
        call = self.calls.get(fingerprint)
        if call is None or call["call_id"] != payload["call_id"]:
            return
        pcm = base64.b64decode(payload["pcm_b64"])
        play_queue = call.get("play_queue")
        if play_queue is not None:
            play_queue.put(pcm)
        call.setdefault("received_audio_for_test", []).append(pcm)
        if self.on_remote_audio_chunk:
            self.on_remote_audio_chunk(fingerprint, pcm)

    def send_video_frame(self, fingerprint: str, jpeg_bytes: bytes) -> None:
        call = self.calls.get(fingerprint)
        if call is None:
            return
        seq = call.get("video_seq", 0)
        call["video_seq"] = seq + 1
        payload = json.dumps(
            {
                "type": "call_video",
                "call_id": call["call_id"],
                "seq": seq,
                "jpg_b64": base64.b64encode(jpeg_bytes).decode("ascii"),
            }
        )
        self.net.send_text(fingerprint, payload, kind="call")

    def _on_video(self, fingerprint: str, payload: dict) -> None:
        call = self.calls.get(fingerprint)
        if call is None or call["call_id"] != payload["call_id"]:
            return
        jpeg_bytes = base64.b64decode(payload["jpg_b64"])
        call.setdefault("received_video_for_test", []).append(jpeg_bytes)
        if self.on_remote_video_frame:
            self.on_remote_video_frame(fingerprint, jpeg_bytes)

    # -- media: real hardware capture/playback --------------------------------

    def _start_media(self, fingerprint: str, video: bool) -> None:
        call = self.calls[fingerprint]
        call["stop_event"] = threading.Event()
        call["muted"] = False
        import queue as _queue

        call["play_queue"] = _queue.Queue()

        if not HAS_AUDIO:
            self._report_error(fingerprint, "Audio libraries not installed (pip install sounddevice numpy)")
        else:
            threading.Thread(target=self._capture_audio_loop, args=(fingerprint,), daemon=True).start()
            threading.Thread(target=self._playback_audio_loop, args=(fingerprint,), daemon=True).start()

        if video:
            if not HAS_VIDEO:
                self._report_error(fingerprint, "Video library not installed (pip install opencv-python-headless)")
            else:
                threading.Thread(target=self._capture_video_loop, args=(fingerprint,), daemon=True).start()

    def _stop_media(self, call: dict) -> None:
        stop_event = call.get("stop_event")
        if stop_event is not None:
            stop_event.set()

    def _report_error(self, fingerprint: str, message: str) -> None:
        if self.on_call_error:
            self.on_call_error(fingerprint, message)

    def _capture_audio_loop(self, fingerprint: str) -> None:
        call = self.calls.get(fingerprint)
        if call is None:
            return
        try:
            with sd.InputStream(samplerate=AUDIO_SAMPLE_RATE, channels=1, dtype="int16", blocksize=AUDIO_BLOCK_SAMPLES) as stream:
                while not call["stop_event"].is_set():
                    data, _ = stream.read(AUDIO_BLOCK_SAMPLES)
                    if call.get("muted"):
                        continue
                    try:
                        self.send_audio_chunk(fingerprint, data.tobytes())
                    except ConnectionError:
                        break
        except Exception as exc:  # sounddevice raises its own PortAudioError subclasses
            self._report_error(fingerprint, f"Microphone error: {exc}")

    def _playback_audio_loop(self, fingerprint: str) -> None:
        call = self.calls.get(fingerprint)
        if call is None:
            return
        try:
            with sd.OutputStream(samplerate=AUDIO_SAMPLE_RATE, channels=1, dtype="int16", blocksize=AUDIO_BLOCK_SAMPLES) as stream:
                while not call["stop_event"].is_set():
                    try:
                        chunk = call["play_queue"].get(timeout=0.5)
                    except Exception:
                        continue
                    arr = np.frombuffer(chunk, dtype=np.int16).reshape(-1, 1)
                    stream.write(arr)
        except Exception as exc:
            self._report_error(fingerprint, f"Speaker error: {exc}")

    def _capture_video_loop(self, fingerprint: str) -> None:
        call = self.calls.get(fingerprint)
        if call is None:
            return
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            self._report_error(fingerprint, "Could not open camera (device 0)")
            return
        try:
            interval = 1.0 / VIDEO_FPS
            while not call["stop_event"].is_set():
                ok, frame = cap.read()
                if not ok:
                    time.sleep(0.2)
                    continue
                frame = cv2.resize(frame, VIDEO_SIZE)
                ok2, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, VIDEO_JPEG_QUALITY])
                if not ok2:
                    continue
                jpeg_bytes = buf.tobytes()
                if self.on_local_video_frame:
                    self.on_local_video_frame(fingerprint, jpeg_bytes)
                try:
                    self.send_video_frame(fingerprint, jpeg_bytes)
                except ConnectionError:
                    break
                time.sleep(interval)
        except Exception as exc:
            self._report_error(fingerprint, f"Camera error: {exc}")
        finally:
            cap.release()
