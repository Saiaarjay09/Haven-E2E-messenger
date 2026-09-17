/**
 * Images, GIFs, audio clips, and video clips ride the exact same
 * end-to-end encrypted channel as text — a message's "kind" (already
 * threaded through network.js/storage.js) is "image"/"gif"/"audio"/
 * "video" instead of "text", and its content is this module's small
 * JSON envelope (filename + mime type + base64 bytes) instead of a
 * plain string. This mirrors haven/attachments.py exactly (same
 * envelope shape, same 8 MB limit) so an attachment sent from the web
 * client and one sent from the desktop app are wire-compatible.
 */

const HavenAttachments = (() => {
  "use strict";

  const MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024;

  class AttachmentTooLarge extends Error {}

  function bytesToBase64(bytes) {
    let bin = "";
    const chunkSize = 0x8000; // avoid call-stack blowups on large files
    for (let i = 0; i < bytes.length; i += chunkSize) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function guessKind(file) {
    const mime = file.type || "";
    if (mime === "image/gif") return "gif";
    if (mime.startsWith("image/")) return "image";
    if (mime.startsWith("audio/")) return "audio";
    if (mime.startsWith("video/")) return "video";
    return "file";
  }

  async function encodeAttachment(file) {
    if (file.size > MAX_ATTACHMENT_BYTES) {
      throw new AttachmentTooLarge(
        `${file.name} is ${Math.round(file.size / 1024)} KB; the limit is ${MAX_ATTACHMENT_BYTES / 1024} KB`
      );
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    return JSON.stringify({
      filename: file.name,
      mime: file.type || "application/octet-stream",
      data_b64: bytesToBase64(bytes),
    });
  }

  function decodeAttachment(text) {
    const payload = JSON.parse(text);
    return { filename: payload.filename, mime: payload.mime, data: base64ToBytes(payload.data_b64) };
  }

  function attachmentDataUrl(text) {
    const payload = JSON.parse(text);
    return `data:${payload.mime};base64,${payload.data_b64}`;
  }

  return { MAX_ATTACHMENT_BYTES, AttachmentTooLarge, guessKind, encodeAttachment, decodeAttachment, attachmentDataUrl };
})();
