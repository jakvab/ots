/* ============================================================
   ots — zero-knowledge crypto (AES-256-GCM via Web Crypto)
   The key is generated in the browser and NEVER sent to the
   server. It travels only in the URL #fragment.
   ============================================================ */
window.OTS = (function () {
  "use strict";
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  // bytes -> base64 (chunked, safe for large arrays)
  function toB64(bytes) {
    var s = "";
    var CHUNK = 0x8000;
    for (var i = 0; i < bytes.length; i += CHUNK) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(s);
  }
  function fromB64(str) {
    var bin = atob(str);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toB64url(bytes) {
    return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function fromB64url(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return fromB64(str);
  }

  var PBKDF2_ITER = 210000; // browser-side work factor for the passphrase layer

  // Derive an AES-256-GCM key from a passphrase + salt (PBKDF2-SHA256).
  async function deriveKey(passphrase, salt) {
    var base = await crypto.subtle.importKey(
      "raw", enc.encode(passphrase), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  // Encrypt a UTF-8 string. Returns { ct (base64 blob for server),
  // key (base64url, goes in URL fragment), pw (bool: passphrase layer used) }.
  // Inner layer: random fragment key (always). Optional outer layer: a key
  // derived from the passphrase, so the URL alone can't decrypt.
  async function encrypt(plaintext, passphrase) {
    var key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ctBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv }, key, enc.encode(plaintext)
    );
    var ct = new Uint8Array(ctBuf);
    var raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    var inner = new Uint8Array(iv.length + ct.length);
    inner.set(iv, 0);
    inner.set(ct, iv.length);

    if (!passphrase) {
      return { ct: toB64(inner), key: toB64url(raw), pw: false };
    }

    // Wrap the inner blob under a passphrase-derived key.
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var pk = await deriveKey(passphrase, salt);
    var iv2 = crypto.getRandomValues(new Uint8Array(12));
    var wrapBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2 }, pk, inner);
    var wrap = new Uint8Array(wrapBuf);
    var blob = new Uint8Array(salt.length + iv2.length + wrap.length);
    blob.set(salt, 0);
    blob.set(iv2, salt.length);
    blob.set(wrap, salt.length + iv2.length);
    return { ct: toB64(blob), key: toB64url(raw), pw: true };
  }

  // Decrypt the server blob with the fragment key (+ passphrase if pw layer
  // was used). Throws on tamper / bad key / wrong passphrase.
  async function decrypt(ctB64, keyB64url, passphrase) {
    var blob = fromB64(ctB64);
    var inner = blob;
    if (passphrase) {
      var salt = blob.subarray(0, 16);
      var iv2 = blob.subarray(16, 28);
      var wrap = blob.subarray(28);
      var pk = await deriveKey(passphrase, salt);
      var innerBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv2 }, pk, wrap);
      inner = new Uint8Array(innerBuf);
    }
    var iv = inner.subarray(0, 12);
    var data = inner.subarray(12);
    var raw = fromB64url(keyB64url);
    var key = await crypto.subtle.importKey(
      "raw", raw, { name: "AES-GCM" }, false, ["decrypt"]
    );
    var ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, data);
    return dec.decode(ptBuf);
  }

  return { encrypt: encrypt, decrypt: decrypt };
})();
