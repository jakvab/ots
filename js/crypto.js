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

  // Encrypt a UTF-8 string. Returns { ct (base64 IV‖ciphertext for server),
  // key (base64url, goes in URL fragment) }.
  async function encrypt(plaintext) {
    var key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ctBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv }, key, enc.encode(plaintext)
    );
    var ct = new Uint8Array(ctBuf);
    var raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    var blob = new Uint8Array(iv.length + ct.length);
    blob.set(iv, 0);
    blob.set(ct, iv.length);
    return { ct: toB64(blob), key: toB64url(raw) };
  }

  // Decrypt the server blob with the fragment key. Throws on tamper/bad key.
  async function decrypt(ctB64, keyB64url) {
    var blob = fromB64(ctB64);
    var iv = blob.subarray(0, 12);
    var data = blob.subarray(12);
    var raw = fromB64url(keyB64url);
    var key = await crypto.subtle.importKey(
      "raw", raw, { name: "AES-GCM" }, false, ["decrypt"]
    );
    var ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, data);
    return dec.decode(ptBuf);
  }

  return { encrypt: encrypt, decrypt: decrypt };
})();
