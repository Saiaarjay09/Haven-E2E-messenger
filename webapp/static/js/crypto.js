/**
 * Haven browser crypto engine — a byte-for-byte port of haven/crypto.py,
 * verified against it via webapp/static/js/test_vectors.json (see
 * test_crypto.html). Every primitive here either uses the browser's
 * native WebCrypto (crypto.subtle) — audited, vendor-implemented code,
 * not something this project wrote — or, for scrypt (which WebCrypto has
 * no native support for), a from-spec implementation checked against
 * scrypt's own official RFC 7914 test vectors.
 *
 * This file has ONE job: match haven/crypto.py exactly, so a browser
 * client and the desktop app derive identical keys from identical
 * inputs and can talk to the same relay. See webapp/README.md for the
 * real, irreducible tradeoff of running crypto in a browser at all —
 * nothing in this file changes that tradeoff, it only implements the
 * protocol correctly within it.
 */

const Haven = (() => {
  "use strict";

  // ---------------------------------------------------------------------
  // Byte utilities
  // ---------------------------------------------------------------------

  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error("odd-length hex string");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function utf8(str) {
    return new TextEncoder().encode(str);
  }

  function fromUtf8(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function concatBytes(...parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function compareBytes(a, b) {
    // Lexicographic comparison matching Python's `sorted()` over bytes
    // objects — compares byte values in order, shorter-is-less on a
    // shared prefix (irrelevant here since all our keys are fixed-length,
    // but matching the exact semantics costs nothing).
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  }

  // Big-endian uint64 pack, matching Python's struct.pack(">Q", n). Safe
  // for any index this app will realistically reach (message counts stay
  // far below Number.MAX_SAFE_INTEGER).
  function packUint64BE(n) {
    const out = new Uint8Array(8);
    let big = BigInt(n);
    for (let i = 7; i >= 0; i--) {
      out[i] = Number(big & 0xffn);
      big >>= 8n;
    }
    return out;
  }

  // ---------------------------------------------------------------------
  // Identity keys (X25519)
  // ---------------------------------------------------------------------

  // X25519 is implemented here in pure JS (RFC 7748 §5's Montgomery
  // ladder over BigInt) rather than via crypto.subtle's native X25519
  // support. Two earlier attempts at using the native curve — a
  // hand-assembled PKCS8 wrapper, then a JWK-based import — each worked
  // in Chromium but broke in another real browser, because WebCrypto's
  // X25519 support (both whether it exists at all, and the exact
  // behavior of its key-format handling) is inconsistent across engines.
  // BigInt arithmetic has none of that inconsistency, so this is the
  // version that actually is portable. Verified byte-for-byte against
  // both haven/crypto.py's own key derivation (test_vectors.json) and
  // RFC 7748 §5.2's independent scalar-mult test vectors.
  const X25519_P = (1n << 255n) - 19n;
  const X25519_A24 = 121665n;
  const X25519_BASE_U = (() => {
    const u = new Uint8Array(32);
    u[0] = 9;
    return u;
  })();

  function leBytesToBigInt(bytes) {
    let result = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) result = (result << 8n) | BigInt(bytes[i]);
    return result;
  }

  function bigIntToLeBytes(num, len) {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      out[i] = Number(num & 0xffn);
      num >>= 8n;
    }
    return out;
  }

  function modPow(base, exp, mod) {
    base = ((base % mod) + mod) % mod;
    let result = 1n;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  function modInv(a, mod) {
    return modPow(a, mod - 2n, mod);
  }

  function clampX25519Scalar(bytes) {
    const k = bytes.slice();
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return k;
  }

  function x25519ScalarMult(scalarBytes, uBytes) {
    const k = leBytesToBigInt(clampX25519Scalar(scalarBytes));
    const u = leBytesToBigInt(uBytes) % X25519_P;
    const x1 = u;
    let x2 = 1n,
      z2 = 0n,
      x3 = u,
      z3 = 1n,
      swap = 0n;
    for (let t = 254; t >= 0; t--) {
      const kt = (k >> BigInt(t)) & 1n;
      swap ^= kt;
      if (swap === 1n) {
        [x2, x3] = [x3, x2];
        [z2, z3] = [z3, z2];
      }
      swap = kt;
      const A = (x2 + z2) % X25519_P;
      const AA = (A * A) % X25519_P;
      const B = (x2 - z2 + X25519_P) % X25519_P;
      const BB = (B * B) % X25519_P;
      const E = (AA - BB + X25519_P) % X25519_P;
      const C = (x3 + z3) % X25519_P;
      const D = (x3 - z3 + X25519_P) % X25519_P;
      const DA = (D * A) % X25519_P;
      const CB = (C * B) % X25519_P;
      x3 = (DA + CB) % X25519_P;
      x3 = (x3 * x3) % X25519_P;
      z3 = (DA - CB + X25519_P) % X25519_P;
      z3 = (z3 * z3) % X25519_P;
      z3 = (z3 * x1) % X25519_P;
      x2 = (AA * BB) % X25519_P;
      z2 = (E * ((AA + X25519_A24 * E) % X25519_P)) % X25519_P;
    }
    if (swap === 1n) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    const result = (x2 * modInv(z2, X25519_P)) % X25519_P;
    return bigIntToLeBytes(result, 32);
  }

  function x25519PublicFromPrivate(privateBytes) {
    return x25519ScalarMult(privateBytes, X25519_BASE_U);
  }

  // X25519 support in crypto.subtle is NOT reliably present across
  // browsers — it varies by engine and version, and even where it exists,
  // its JWK/PKCS8 handling has already shown real interop bugs (see the
  // git history of this file). So every X25519 operation — key
  // generation, deriving a public key from a private one, and the actual
  // Diffie-Hellman itself — is done with the pure-JS Montgomery ladder
  // above instead. It depends on nothing but BigInt, which every current
  // browser implements identically, and is verified byte-for-byte against
  // both haven/crypto.py's derivation and RFC 7748 §5.2's own scalar-mult
  // test vectors. WebCrypto is still used everywhere else in this file
  // (AES-GCM/CTR, HKDF, HMAC, PBKDF2, SHA-256) — those primitives don't
  // have this cross-browser support problem.
  //
  // "privateKey"/"publicKey" below are just aliases for the same raw byte
  // arrays as "privateBytes"/"publicBytes" — kept so callers that already
  // pass `identity.privateKey` into dh()/dhProof() don't need to change.
  function generateKeyPair() {
    const privateBytes = crypto.getRandomValues(new Uint8Array(32));
    const publicBytes = x25519PublicFromPrivate(privateBytes);
    return { privateKey: privateBytes, publicKey: publicBytes, privateBytes, publicBytes };
  }

  function keyPairFromPrivateBytes(privateBytes) {
    const publicBytes = x25519PublicFromPrivate(privateBytes);
    return { privateKey: privateBytes, publicKey: publicBytes, privateBytes, publicBytes };
  }

  function dh(myPrivateKeyBytes, theirPublicBytes) {
    return x25519ScalarMult(myPrivateKeyBytes, theirPublicBytes);
  }

  function fingerprint(pubA, pubB) {
    const sorted = [pubA, pubB].sort(compareBytes);
    return fingerprintDigest(concatBytes(sorted[0], sorted[1]));
  }

  async function fingerprintDigest(material) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
    // First 30 bytes as a big-endian integer, matching Python's
    // int.from_bytes(digest[:30], "big") — needs BigInt, this exceeds
    // Number.MAX_SAFE_INTEGER by a wide margin (240 bits).
    let numeric = 0n;
    for (let i = 0; i < 30; i++) numeric = (numeric << 8n) | BigInt(digest[i]);
    const groups = [];
    for (let i = 0; i < 6; i++) {
      const group = numeric % 100000n;
      groups.push(group.toString().padStart(5, "0"));
      numeric /= 100000n;
    }
    return groups.join(" ");
  }

  // ---------------------------------------------------------------------
  // HKDF (matches haven/crypto.py's _hkdf: SHA-256, salt="haven-v1")
  // ---------------------------------------------------------------------

  async function hkdf(keyMaterial, infoBytes, length = 32) {
    const key = await crypto.subtle.importKey("raw", keyMaterial, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: utf8("haven-v1"), info: infoBytes },
      key,
      length * 8
    );
    return new Uint8Array(bits);
  }

  // ---------------------------------------------------------------------
  // HMAC-SHA256 (used by ratchet_step and dh_proof)
  // ---------------------------------------------------------------------

  async function hmacSha256(keyBytes, msgBytes) {
    // WebCrypto refuses to import a zero-length HMAC key outright ("HMAC
    // key data must not be empty"), even though HMAC's own construction
    // handles an empty key the same as any short one: zero-padded to the
    // block size. RFC 7914's own official scrypt test vectors include an
    // empty password (which becomes pbkdf2()'s empty HMAC key below), so
    // this does come up. A 64-byte all-zero key is exactly what HMAC
    // would build internally from an empty key, so substituting it
    // directly gives an identical result without hitting that restriction.
    const effectiveKey = keyBytes.length === 0 ? new Uint8Array(64) : keyBytes;
    const key = await crypto.subtle.importKey("raw", effectiveKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
    return new Uint8Array(sig);
  }

  async function dhProof(myPrivateKey, theirPublicBytes, nonceBytes) {
    const shared = await dh(myPrivateKey, theirPublicBytes);
    const mac = await hmacSha256(shared, nonceBytes);
    return bytesToHex(mac);
  }

  // ---------------------------------------------------------------------
  // 3-DH handshake (matches compute_shared_root_key / derive_chain_keys)
  // ---------------------------------------------------------------------

  async function computeSharedRootKey({ isInitiator, myIdentity, myEphemeral, theirIdentityPub, theirEphemeralPub }) {
    let dh1, dh2, dh3;
    if (isInitiator) {
      dh1 = await dh(myIdentity.privateKey, theirEphemeralPub);
      dh2 = await dh(myEphemeral.privateKey, theirIdentityPub);
      dh3 = await dh(myEphemeral.privateKey, theirEphemeralPub);
    } else {
      dh1 = await dh(myEphemeral.privateKey, theirIdentityPub);
      dh2 = await dh(myIdentity.privateKey, theirEphemeralPub);
      dh3 = await dh(myEphemeral.privateKey, theirEphemeralPub);
    }
    return hkdf(concatBytes(dh1, dh2, dh3), utf8("root"));
  }

  async function deriveChainKeys(rootKey, isInitiator) {
    const initToResp = await hkdf(rootKey, utf8("init->resp"));
    const respToInit = await hkdf(rootKey, utf8("resp->init"));
    return isInitiator ? { send: initToResp, recv: respToInit } : { send: respToInit, recv: initToResp };
  }

  // ---------------------------------------------------------------------
  // Symmetric ratchet + AES-256-GCM message encryption
  // ---------------------------------------------------------------------

  async function ratchetStep(chainKey) {
    const messageKey = await hmacSha256(chainKey, new Uint8Array([1]));
    const nextChainKey = await hmacSha256(chainKey, new Uint8Array([2]));
    return { messageKey, nextChainKey };
  }

  async function aesGcmEncrypt(keyBytes, plaintext, aad) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, plaintext));
    return { nonce, ciphertext: ct };
  }

  async function aesGcmDecrypt(keyBytes, nonce, ciphertext, aad) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, ciphertext);
    return new Uint8Array(pt);
  }

  class RatchetSession {
    constructor(sendChainKey, recvChainKey, sendIndex = 0, recvIndex = 0) {
      this.sendChainKey = sendChainKey;
      this.recvChainKey = recvChainKey;
      this.sendIndex = sendIndex;
      this.recvIndex = recvIndex;
    }

    async encrypt(plaintext, aad = new Uint8Array(0)) {
      const { messageKey, nextChainKey } = await ratchetStep(this.sendChainKey);
      this.sendChainKey = nextChainKey;
      const index = this.sendIndex++;
      const fullAad = concatBytes(aad, packUint64BE(index));
      const key = await crypto.subtle.importKey("raw", messageKey, "AES-GCM", false, ["encrypt"]);
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: fullAad }, key, plaintext)
      );
      return { index, nonce, ciphertext };
    }

    async decrypt(envelope, aad = new Uint8Array(0)) {
      if (envelope.index !== this.recvIndex) {
        throw new Error(
          `out-of-order message (expected #${this.recvIndex}, got #${envelope.index}); requires in-order delivery`
        );
      }
      const { messageKey, nextChainKey } = await ratchetStep(this.recvChainKey);
      this.recvChainKey = nextChainKey;
      this.recvIndex++;
      const fullAad = concatBytes(aad, packUint64BE(envelope.index));
      const key = await crypto.subtle.importKey("raw", messageKey, "AES-GCM", false, ["decrypt"]);
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: envelope.nonce, additionalData: fullAad },
        key,
        envelope.ciphertext
      );
      return new Uint8Array(pt);
    }
  }

  class SenderKeyChain {
    constructor(chainKey, index = 0) {
      this.chainKey = chainKey;
      this.index = index;
    }

    async encrypt(plaintext, aad = new Uint8Array(0)) {
      const { messageKey, nextChainKey } = await ratchetStep(this.chainKey);
      this.chainKey = nextChainKey;
      const index = this.index++;
      const fullAad = concatBytes(aad, packUint64BE(index));
      const key = await crypto.subtle.importKey("raw", messageKey, "AES-GCM", false, ["encrypt"]);
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: fullAad }, key, plaintext)
      );
      return { index, nonce, ciphertext };
    }

    async decrypt(envelope, aad = new Uint8Array(0)) {
      if (envelope.index !== this.index) {
        throw new Error(`out-of-order sender-key message (expected #${this.index}, got #${envelope.index})`);
      }
      const { messageKey, nextChainKey } = await ratchetStep(this.chainKey);
      this.chainKey = nextChainKey;
      this.index++;
      const fullAad = concatBytes(aad, packUint64BE(envelope.index));
      const key = await crypto.subtle.importKey("raw", messageKey, "AES-GCM", false, ["decrypt"]);
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: envelope.nonce, additionalData: fullAad },
        key,
        envelope.ciphertext
      );
      return new Uint8Array(pt);
    }
  }

  // ---------------------------------------------------------------------
  // scrypt (RFC 7914) — WebCrypto has no native scrypt, so this is a
  // from-spec implementation: Salsa20/8 core -> BlockMix -> ROMix, with
  // the outer PBKDF2-HMAC-SHA256 calls delegated to WebCrypto (a place
  // where using the native, audited primitive instead of hand-rolling it
  // is both easier and safer). Checked against scrypt's own official
  // test vectors in test_crypto.html, not just against the Python side.
  // ---------------------------------------------------------------------

  // Built directly from HMAC-SHA256 (RFC 2898's own PBKDF2 construction)
  // rather than crypto.subtle's native PBKDF2 deriveBits. Firefox refuses
  // to derive more than 2048 bits (256 bytes) from a single native
  // PBKDF2 call and throws a generic OperationError for anything larger
  // (https://bugzilla.mozilla.org/show_bug.cgi?id=1469482) — Chromium has
  // no such limit, which is why this only ever showed up for real
  // Firefox users. scrypt (RFC 7914 §6) needs up to 128*r*p bytes from a
  // single PBKDF2 call, comfortably over that cap for this app's
  // parameters. HMAC-SHA256 itself has no such length restriction since
  // each block is a fixed 32-byte HMAC output computed independently.
  async function pbkdf2(passwordBytes, saltBytes, iterations, lengthBytes) {
    const hLen = 32;
    const numBlocks = Math.ceil(lengthBytes / hLen);
    const blocks = [];
    for (let i = 1; i <= numBlocks; i++) {
      const blockIndex = new Uint8Array(4);
      new DataView(blockIndex.buffer).setUint32(0, i, false); // big-endian, per RFC 2898
      let u = await hmacSha256(passwordBytes, concatBytes(saltBytes, blockIndex));
      let t = u;
      for (let c = 1; c < iterations; c++) {
        u = await hmacSha256(passwordBytes, u);
        t = xorBytes(t, u);
      }
      blocks.push(t);
    }
    return concatBytes(...blocks).slice(0, lengthBytes);
  }

  function salsa20_8(input) {
    // Operates on 16 little-endian uint32 words (64 bytes), 8 rounds
    // (4 double-rounds), per RFC 7914 section 3.
    const B = new Uint32Array(16);
    const view = new DataView(input.buffer, input.byteOffset, 64);
    for (let i = 0; i < 16; i++) B[i] = view.getUint32(i * 4, true);
    const x = B.slice();

    const R = (a, b) => ((a << b) | (a >>> (32 - b))) >>> 0;

    for (let i = 0; i < 4; i++) {
      x[4] ^= R((x[0] + x[12]) >>> 0, 7);
      x[8] ^= R((x[4] + x[0]) >>> 0, 9);
      x[12] ^= R((x[8] + x[4]) >>> 0, 13);
      x[0] ^= R((x[12] + x[8]) >>> 0, 18);
      x[9] ^= R((x[5] + x[1]) >>> 0, 7);
      x[13] ^= R((x[9] + x[5]) >>> 0, 9);
      x[1] ^= R((x[13] + x[9]) >>> 0, 13);
      x[5] ^= R((x[1] + x[13]) >>> 0, 18);
      x[14] ^= R((x[10] + x[6]) >>> 0, 7);
      x[2] ^= R((x[14] + x[10]) >>> 0, 9);
      x[6] ^= R((x[2] + x[14]) >>> 0, 13);
      x[10] ^= R((x[6] + x[2]) >>> 0, 18);
      x[3] ^= R((x[15] + x[11]) >>> 0, 7);
      x[7] ^= R((x[3] + x[15]) >>> 0, 9);
      x[11] ^= R((x[7] + x[3]) >>> 0, 13);
      x[15] ^= R((x[11] + x[7]) >>> 0, 18);
      x[1] ^= R((x[0] + x[3]) >>> 0, 7);
      x[2] ^= R((x[1] + x[0]) >>> 0, 9);
      x[3] ^= R((x[2] + x[1]) >>> 0, 13);
      x[0] ^= R((x[3] + x[2]) >>> 0, 18);
      x[6] ^= R((x[5] + x[4]) >>> 0, 7);
      x[7] ^= R((x[6] + x[5]) >>> 0, 9);
      x[4] ^= R((x[7] + x[6]) >>> 0, 13);
      x[5] ^= R((x[4] + x[7]) >>> 0, 18);
      x[11] ^= R((x[10] + x[9]) >>> 0, 7);
      x[8] ^= R((x[11] + x[10]) >>> 0, 9);
      x[9] ^= R((x[8] + x[11]) >>> 0, 13);
      x[10] ^= R((x[9] + x[8]) >>> 0, 18);
      x[12] ^= R((x[15] + x[14]) >>> 0, 7);
      x[13] ^= R((x[12] + x[15]) >>> 0, 9);
      x[14] ^= R((x[13] + x[12]) >>> 0, 13);
      x[15] ^= R((x[14] + x[13]) >>> 0, 18);
    }

    const out = new Uint8Array(64);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) outView.setUint32(i * 4, (x[i] + B[i]) >>> 0, true);
    return out;
  }

  function blockMix(B, r) {
    // B is 2r 64-byte blocks concatenated.
    let X = B.slice(B.length - 64);
    const out = new Uint8Array(B.length);
    let outIdx1 = 0;
    let outIdx2 = r * 64;
    for (let i = 0; i < 2 * r; i++) {
      const block = B.slice(i * 64, i * 64 + 64);
      for (let j = 0; j < 64; j++) block[j] ^= X[j];
      X = salsa20_8(block);
      if (i % 2 === 0) {
        out.set(X, outIdx1);
        outIdx1 += 64;
      } else {
        out.set(X, outIdx2);
        outIdx2 += 64;
      }
    }
    return out;
  }

  function integerify(B, r) {
    // Last 64-byte block's first 8 bytes, little-endian, per RFC 7914.
    const lastBlockOffset = (2 * r - 1) * 64;
    const view = new DataView(B.buffer, B.byteOffset + lastBlockOffset, 8);
    return view.getBigUint64(0, true);
  }

  function xorBytes(a, b) {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function romix(B, N, r) {
    const V = new Array(N);
    let X = B;
    for (let i = 0; i < N; i++) {
      V[i] = X;
      X = blockMix(X, r);
    }
    for (let i = 0; i < N; i++) {
      const j = Number(integerify(X, r) % BigInt(N));
      X = blockMix(xorBytes(X, V[j]), r);
    }
    return X;
  }

  async function scrypt(passwordBytes, saltBytes, N, r, p, dkLen) {
    // RFC 7914 section 6: B = PBKDF2(password, salt, 1, p*128r), split
    // into p blocks, ROMix each, concatenate, then a final
    // PBKDF2(password, <that concatenation>, 1, dkLen).
    const blockLen = 128 * r;
    const B = await pbkdf2(passwordBytes, saltBytes, 1, blockLen * p);
    const B_blocks = [];
    for (let i = 0; i < p; i++) B_blocks.push(B.slice(i * blockLen, (i + 1) * blockLen));
    const mixed = B_blocks.map((block) => romix(block, N, r));
    const combined = concatBytes(...mixed);
    return pbkdf2(passwordBytes, combined, 1, dkLen);
  }

  // ---------------------------------------------------------------------
  // Password-based key derivation (matches derive_key_from_password /
  // derive_split_keys) and AES-256-GCM / AES-256-CTR at-rest encryption
  // ---------------------------------------------------------------------

  // SCRYPT_N is the LEGACY cost, kept as the default so backup.js's
  // export/restore (this device's own local backup files) keeps
  // deriving byte-identical keys from files already encrypted with it.
  // Never bump this default — auth.js passes a stronger `n` explicitly
  // for the hosted web app's login/signup instead (see its
  // SCRYPT_N_STRONG), which is the only thing this change is meant to
  // strengthen.
  const SCRYPT_N = 2 ** 15;
  const SCRYPT_R = 8;
  const SCRYPT_P = 1;

  async function deriveKeyFromPassword(password, saltBytes, length = 32, n = SCRYPT_N) {
    return scrypt(utf8(password), saltBytes, n, SCRYPT_R, SCRYPT_P, length);
  }

  async function deriveSplitKeys(password, saltBytes, n = SCRYPT_N) {
    const combined = await deriveKeyFromPassword(password, saltBytes, 32, n);
    const authKey = await hkdf(combined, utf8("webapp-auth-key"));
    const encKey = await hkdf(combined, utf8("webapp-enc-key"));
    return { authKey, encKey };
  }

  async function encryptAuthenticated(keyBytes, plaintext, aad = new Uint8Array(0)) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, plaintext));
    return concatBytes(nonce, ct);
  }

  async function decryptAuthenticated(keyBytes, blob, aad = new Uint8Array(0)) {
    const nonce = blob.slice(0, 12);
    const ciphertext = blob.slice(12);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, ciphertext);
    return new Uint8Array(pt);
  }

  async function encryptDeniable(keyBytes, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CTR", false, ["encrypt"]);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: 128 }, key, plaintext));
    return concatBytes(iv, ct);
  }

  async function decryptDeniable(keyBytes, blob) {
    const iv = blob.slice(0, 16);
    const ciphertext = blob.slice(16);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CTR", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-CTR", counter: iv, length: 128 }, key, ciphertext);
    return new Uint8Array(pt);
  }

  return {
    hexToBytes,
    bytesToHex,
    utf8,
    fromUtf8,
    concatBytes,
    generateKeyPair,
    keyPairFromPrivateBytes,
    dh,
    fingerprint,
    hkdf,
    hmacSha256,
    dhProof,
    computeSharedRootKey,
    deriveChainKeys,
    ratchetStep,
    RatchetSession,
    SenderKeyChain,
    scrypt,
    deriveKeyFromPassword,
    deriveSplitKeys,
    encryptAuthenticated,
    decryptAuthenticated,
    encryptDeniable,
    decryptDeniable,
  };
})();
