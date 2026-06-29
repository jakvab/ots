/* ============================================================
   ots — app logic (create + reveal views)
   ============================================================ */
(function () {
  "use strict";
  var API = "/api"; // same-origin via CloudFront → API Gateway

  function $(id) { return document.getElementById(id); }
  function copy(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
      if (!btn) return;
      var t = btn.textContent; btn.textContent = "Kopierat ✓";
      setTimeout(function () { btn.textContent = t; }, 1500);
    });
  }

  /* ---------------- CREATE (index.html) ---------------- */
  var form = $("create-form");
  if (form) {
    var status = $("status");
    var resultBox = $("result");
    var linkOut = $("link-out");

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      var secret = $("secret").value;
      if (!secret) { status.textContent = "Skriv något att dela."; status.className = "status err"; return; }

      var token = form["cf-turnstile-response"] ? form["cf-turnstile-response"].value : "";
      if (!token) { status.textContent = "Bekräfta att du inte är en robot."; status.className = "status err"; return; }

      var btn = form.querySelector("button[type=submit]");
      btn.disabled = true;
      status.textContent = "Krypterar i webbläsaren …"; status.className = "status";

      try {
        var enc = await OTS.encrypt(secret);
        status.textContent = "Sparar krypterad blob …";
        var r = await fetch(API + "/secrets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ct: enc.ct,
            ttlSeconds: parseInt($("ttl").value, 10),
            maxViews: parseInt($("views").value, 10),
            turnstileToken: token
          })
        });
        if (!r.ok) {
          var err = await r.json().catch(function () { return {}; });
          throw new Error(err.error || ("HTTP " + r.status));
        }
        var data = await r.json();
        var link = location.origin + "/s.html?id=" + encodeURIComponent(data.id) + "#" + enc.key;
        linkOut.value = link;
        resultBox.hidden = false;
        form.hidden = true;
        status.textContent = "";
        if (window.turnstile) { try { window.turnstile.reset(); } catch (e2) {} }
      } catch (err) {
        status.textContent = "Något gick fel: " + err.message;
        status.className = "status err";
        if (window.turnstile) { try { window.turnstile.reset(); } catch (e3) {} }
      } finally {
        btn.disabled = false;
      }
    });

    var copyBtn = $("copy-link");
    if (copyBtn) copyBtn.addEventListener("click", function () { copy(linkOut.value, copyBtn); });

    var againBtn = $("again");
    if (againBtn) againBtn.addEventListener("click", function () { location.href = "/"; });
  }

  /* ---------------- REVEAL (s.html) ---------------- */
  var reveal = $("reveal");
  if (reveal) {
    var params = new URLSearchParams(location.search);
    var id = params.get("id");
    var key = location.hash ? location.hash.slice(1) : "";

    var stateEl = $("reveal-state");
    var btnWrap = $("reveal-btn-wrap");
    var revealBtn = $("reveal-btn");
    var secretWrap = $("secret-wrap");
    var secretOut = $("secret-out");
    var copySecret = $("copy-secret");

    function gone(msg) {
      btnWrap.hidden = true;
      stateEl.textContent = msg || "Den här hemligheten finns inte längre — den kan ha lästs eller gått ut.";
      stateEl.className = "status err";
    }

    if (!id || !key) {
      gone("Ogiltig länk — nyckel eller id saknas.");
    } else {
      // Probe existence WITHOUT burning.
      fetch(API + "/secrets/" + encodeURIComponent(id) + "/meta")
        .then(function (r) {
          if (!r.ok) { gone(); return null; }
          return r.json();
        })
        .then(function (meta) {
          if (!meta) return;
          stateEl.textContent = "Den här hemligheten kan bara läsas " +
            (meta.viewsLeft === 1 ? "en gång" : (meta.viewsLeft + " gånger")) +
            " och raderas sedan.";
          btnWrap.hidden = false;
        })
        .catch(function () { gone("Kunde inte nå servern."); });

      revealBtn.addEventListener("click", async function () {
        revealBtn.disabled = true;
        revealBtn.textContent = "Hämtar …";
        try {
          var r = await fetch(API + "/secrets/" + encodeURIComponent(id) + "/reveal", { method: "POST" });
          if (!r.ok) { gone(); return; }
          var data = await r.json();
          var pt = await OTS.decrypt(data.ct, key);
          secretOut.value = pt;
          secretWrap.hidden = false;
          btnWrap.hidden = true;
          stateEl.textContent = data.viewsLeft > 0
            ? ("Läst. Den kan läsas " + data.viewsLeft + " gång(er) till.")
            : "Läst och raderad. Den här länken fungerar inte längre.";
          stateEl.className = "status ok";
        } catch (err) {
          gone("Kunde inte dekryptera — fel nyckel eller skadad data.");
        }
      });

      if (copySecret) copySecret.addEventListener("click", function () { copy(secretOut.value, copySecret); });
    }
  }
})();
