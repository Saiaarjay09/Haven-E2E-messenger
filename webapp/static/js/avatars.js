/**
 * Profile pictures. Reuses the exact same channel as everything else —
 * an avatar is a small JPEG sent as a kind="avatar" message on the
 * existing 1:1 encrypted channel (see network.js/app.js), not a new
 * transport. Resized/cropped to a small square client-side before
 * sending, since an avatar only ever needs to render at ~96px and
 * there's no reason to pay for (or store) a multi-megabyte original.
 */

const HavenAvatars = (() => {
  "use strict";

  const AVATAR_SIZE = 96;

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

  // Center-cropped, resized to a fixed small square, returned as a JPEG
  // data URL (easy to store directly and drop into an <img src>).
  async function fileToAvatarDataUrl(file) {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement("canvas");
    canvas.width = AVATAR_SIZE;
    canvas.height = AVATAR_SIZE;
    const ctx = canvas.getContext("2d");
    const scale = Math.max(AVATAR_SIZE / bitmap.width, AVATAR_SIZE / bitmap.height);
    const w = bitmap.width * scale;
    const h = bitmap.height * scale;
    ctx.drawImage(bitmap, (AVATAR_SIZE - w) / 2, (AVATAR_SIZE - h) / 2, w, h);
    return canvas.toDataURL("image/jpeg", 0.7);
  }

  // Message payload helpers: {mime, data_b64} extracted from/packed into
  // a data URL, matching attachments.js's envelope shape closely enough
  // to reuse the same mental model without actually depending on it.
  function dataUrlToPayload(dataUrl) {
    const [, mime, b64] = dataUrl.match(/^data:([^;]+);base64,(.*)$/);
    return JSON.stringify({ mime, data_b64: b64 });
  }

  function payloadToDataUrl(text) {
    const { mime, data_b64 } = JSON.parse(text);
    return `data:${mime};base64,${data_b64}`;
  }

  return { AVATAR_SIZE, fileToAvatarDataUrl, dataUrlToPayload, payloadToDataUrl, bytesToBase64, base64ToBytes };
})();
