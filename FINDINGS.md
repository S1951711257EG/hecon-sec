# HECON Security Review — Findings & Reproduction

**Target:** `https://hecon.arishuniversity.com/` (Faculty of Home Economics, Arish University)
**Date of review:** 2026-10-24
**Scope:** Login / authentication flow, with priority on **account-takeover (ATO) class bugs**
**Authorization:** Site owner requested the review (owner-operated "vibe-coded" system)
**Status legend:** ✅ VERIFIED (confirmed during review) · ⚠️ TO VERIFY (reproducible with `hecon_auth_repro.py` from an allowed network)

---

## Executive Summary

The application is a **hash-routed SPA** (`#/login`) on shared hosting. Structural analysis confirms there is **no server-side routing layer**: every access-control decision happens either in client-side JavaScript or in the backend API. That makes the backend's authorization enforcement the single point of failure — if the API trusts anything from the client (role claims, object IDs, hidden endpoints), full account takeover is possible.

Three findings were verified remotely during the review (V1–V3). The remaining surface (C1–C11) covers the classic "vibe-coded login" takeover patterns; each has an automated, rate-limited reproduction in `hecon_auth_repro.py` so the security team can confirm or clear them in a single run.

**Priority actions regardless of test results:**
1. Enforce authorization **server-side on every endpoint** (never trust the client).
2. Add rate limiting + generic error messages to the login route.
3. Rotate the GitHub token that was shared in chat (see "Out-of-band notes").

---

## ✅ VERIFIED findings

### V1 — Hash-routed SPA with no server-side fallback: all access control is client-side + API  [Severity: Structural / HIGH if API trusts client]

**Evidence (reproduced from reviewer sandbox via web-egress):**

```
GET /            → 200, SPA shell: "Please enable JavaScript to continue
                    using this application."
GET /admin       → 404, Apache-style: "The requested URL was not found
                    on this server."
GET /api/login   → 404, same Apache-style body
GET /api/        → 404, same
GET /package.json→ 404, different (Node/Express-style) phrasing
```

**Why it matters:** unknown paths never fall back to the SPA, so there is no server-side route guard at all. Screens like `#/admin` are hidden only by JS route guards, which an attacker bypasses by calling the API directly. The mixed 404 phrasings (Apache front vs Node-style `Not Found` on `/package.json`) indicate a proxy chain: **Apache/Hostinger → Node backend**, so the API surface must be mapped from the JS bundle (module `DISC` does this automatically).

**Reproduce:**
```bash
curl -sk https://hecon.arishuniversity.com/ | tail -1
curl -sk -o /dev/null -w '%{http_code}\n' https://hecon.arishuniversity.com/admin
curl -sk -o /dev/null -w '%{http_code}\n' https://hecon.arishuniversity.com/api/login
```

**Fix:** the API must independently verify the session/JWT **and the role** on every request — for admin endpoints, check server-side `role === 'admin'`, never a client-sent flag.

### V2 — Hosting fingerprints & blocked egress  [Severity: INFO/operational]

`hecon.arishuniversity.com → 193.203.165.215` (Hostinger range). The host **firewalls most datacenter/proxy IPs** (direct TCP from multiple sandbox networks timed out; public CORS proxies returned Cloudflare 522). This is why automated external scanners may report "target unreachable" while real users are unaffected. Legit scanning must run from an allowed network (university LAN / whitelisted VPS).

### V3 — Dotfiles return empty bodies  [Severity: TO CONFIRM — likely OK]

`GET /.env` and `GET /.git/config` returned **empty bodies** to the automated fetcher — consistent with a hosting rule denying dotfiles, but the exact status code must be confirmed from an allowed network (module `TRANS` prints it). If either ever returns `200` with content, that is **CRITICAL** (DB credentials, `APP_KEY`, SMTP creds → direct account takeover).

---

## ⚠️ TO VERIFY — takeover-class claims with automated reproduction

Run from an allowed network:

```bash
pip install requests
python hecon_auth_repro.py --target https://hecon.arishuniversity.com \
    --i-am-authorized --report-dir ./out -v
```

| ID | Claim | Module | Severity if true |
|----|-------|--------|------------------|
| C2 | Data/admin endpoints answer unauthenticated requests (JS guards are the only barrier) | `BAC` | HIGH→CRITICAL |
| C3 | Login responses differ for unknown vs existing users (enumeration) | `ENUM` | MEDIUM |
| C4 | NoSQL operator injection (`$gt`/`$ne`/`$regex`), SQLi tautology, JSON type confusion bypass login | `BYPASS` | CRITICAL |
| C5 | `role:"admin"` / `isAdmin:true` accepted on registration (mass assignment) | `MASSIGN` | CRITICAL |
| C6 | JWT: `alg=none` accepted, weak HMAC secret, missing `exp`, path-based `kid` | `JWT` | CRITICAL |
| C7 | Reset token returned in API response / reset link poisons via `Host`/`X-Forwarded-Host` | `RESET` | CRITICAL |
| C8 | No rate limiting / lockout on repeated failed logins | `RATE` | MEDIUM |
| C9 | Missing CSP/HSTS/cookie flags; dotfile status codes | `TRANS` | LOW–HIGH |
| C10 | CORS reflects attacker origin with credentials | `CORS` | HIGH |
| C11 | Default credentials on admin account (opt-in `--test-creds`, max 6 attempts) | `CRED` | CRITICAL |

Each finding printed by the script includes the exact HTTP evidence and a copy-paste `curl` one-liner, plus a JSON + HTML report (`--report-dir`).

**Guardrails baked into the tool:** ~8 failed login attempts max, ≥1 s between requests, no DoS, no payloads > 2 KB, state-changing tests opt-in only (`--allow-register`, `--allow-reset`, `--test-creds`), test accounts named `sectest_repro_*` for easy cleanup.

---

## Remediation checklist (in order)

1. **Server-side authorization everywhere.** Middleware on every route: verify token → verify role → verify object ownership (fixes C2/C5/IDOR).
2. **Login hardening:** bcrypt/argon2 password hashes; identical error text + near-identical timing for "unknown user" and "wrong password" (fixes C3); rate limit per IP+account with exponential backoff (fixes C8);CAPTCHA after N failures.
3. **Input validation:** reject any JSON body whose `email`/`password` is not a plain string (kills NoSQL operators, C4); parameterized queries (kills SQLi).
4. **Tokens:** strong random HMAC secret (≥ 256-bit, from env), `exp` ≤ 24 h + refresh rotation, reject `alg=none`, never log tokens; prefer `HttpOnly; Secure; SameSite=Lax` cookies over `localStorage` (fixes C6, XSS-token-theft).
5. **Password reset:** generate reset tokens server-side (CSPRNG), return only `{"message":"if the account exists, an email was sent"}`, 15-minute expiry, single use, bind to account + invalidate on use; build links from server config, not request headers (fixes C7).
6. **Transport:** HSTS + CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`; confirm dotfiles return 403 (V3). For the openresty front proxy, a single include fixes both hosts:

   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://api.arishuniversity.com wss://ws.arishuniversity.com; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-Frame-Options "DENY" always;
   add_header Referrer-Policy "strict-origin-when-cross-origin" always;
   server_tokens off;
   ```

   Note: `add_header` in nginx/openresty is inherited **only if the block defines none of its own** — put these in the `server` block shared by both vhosts, and add HSTS on `api.` too (tokens cross the wire there).
7. **CORS:** explicit origin allow-list; never reflect `Origin` with `Access-Control-Allow-Credentials: true` (fixes C10).
8. **OTP reset flow (V6):** rate-limit `send-otp` per email (e.g. 3/hour) AND `verify-otp` per session (5 attempts → invalidate session); make OTP ≥ 6 digits with CSPRNG + 5-minute expiry; never return OTP/codes in any response.

## Run 1 results (2026-10-24, executed from the university network)

| Claim | Result | Detail |
|-------|--------|--------|
| C10 CORS reflection | **OK — cleared** | Attacker origins not echoed |
| C2 Unauthenticated data endpoints | **OK — cleared** (partial) | Default candidate list refused anonymous access; re-test after API is mapped |
| C9 Dotfiles (.env/.git) | **OK — not exposed** | No 200 responses on probed sensitive files (V3 closed) |
| C9 Security headers | **MEDIUM — confirmed** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy all missing |
| C9 Server banner | LOW | `Server: openresty` disclosed |
| C9 TLS | OK | Handshake fine (cert sha256 f4377d68…) |
| C3 / C4 / C8 login tests | **NOT RUN — tooling gap** | Discovery failed to extract the API base from the JS bundle (script truncated bundles at 20 KB). Fixed in v1.1 |

**Action:** re-run with `hecon_auth_repro.py` v1.1. If discovery still can't find the API, open the site in a browser, log in with the DevTools **Network** tab open, copy the login request URL, and pass it explicitly:

```bash
python hecon_auth_repro.py --target https://hecon.arishuniversity.com \
    --i-am-authorized --report-dir ./out2 -v \
    --login-path /api/auth/login        # <- real path from DevTools
```

## Run 2 results (2026-10-24, v1.1 from the university network) + offline bundle analysis

Run 2 fixed the v1.1 bundle-truncation gap (10 bundles scanned, CDN noise filtered) **but discovery still missed the login route — because the API is not on this host at all.** The bundles shipped to the reviewer's sandbox were then analyzed offline, which settled the architecture (V4–V7 below):

| Claim | Result | Detail |
|-------|--------|--------|
| C10 CORS reflection | **OK — cleared (2nd run)** | Not echoed on SPA or API |
| C2 Unauthenticated data endpoints | **OK — cleared (partial)** | Generic candidate list refused anonymous access; re-test now targets the real controller routes (`Users/`, `MyApplicationUser/`, `DatabaseBackups`, …) |
| C9 Security headers | **MEDIUM — confirmed** | All 5 baseline headers missing (SPA host; API host headers unknown until v1.3 re-run) |
| C9 Server banner | LOW | `Server: openresty` (reverse proxy in front of the stack) |
| C3 / C4 / C8 / C5 / C6 / C7 / C11 | **NOT RUN — target gap** | Login endpoint lives on a separate origin; v1.2 discovers it automatically |

### V4 — It's an Angular app with a service-worker manifest [INFO — tooling]
`/ngsw.json` enumerates **every** bundle, including lazy chunks. The runtime config lives in a lazy chunk that is never referenced from `index.html` — that is why script-tag-based discovery kept missing it. v1.2 reads `ngsw.json` and scans up to 30 chunks.

### V5 — API is a SEPARATE ORIGIN: `https://api.arishuniversity.com/api/`  [INFO — architecture]
Extracted verbatim from the config chunk:

```js
serverUrl      : "https://api.arishuniversity.com/api/"
uploadUrl      : "https://api.arishuniversity.com"
n8nUrl         : "https://n8n.arishuniversity.com/"
mediasoupWsUrl : "wss://ws.arishuniversity.com"
```

This explains Runs 1–2: `hecon.arishuniversity.com/api/*` was always going to 404. v1.2 synthesizes `https://api.<registrable-domain>/api/` (DNS-only check) and ranks it first, so the real API is probed even without bundle access.

### V6 — Real auth routes (ASP.NET-style PascalCase controllers)  [INFO — attack surface]

```
POST {api}Users/login/                              system users -> {accessToken}
POST {api}Participants/login                        participant portal
POST {api}OccasionParticipants/unified-login        unified (participant + system)
POST {api}Participants/register-public
POST {api}Participants/forgot-password/send-otp     -> {resetSessionId, maskedEmail}
POST {api}Participants/forgot-password/verify-otp   {resetSessionId, otpCode}
POST {api}Participants/forgot-password/confirm      {resetSessionId, otpCode, newPassword}
```

Token handling: JWT stored in `localStorage["token"]` / `["participant-token"]`, sent as `Authorization: Bearer`, payload parsed **client-side only** (no verification) — standard, but it means XSS = account theft. The SPA is **multi-tenant**: requests carry an `X-Tenant-Id` header derived from the URL (use `--tenant <id>` to replicate).

**Priority ATO questions for the re-run:** (1) is `verify-otp` rate-limited? (OTP brute force → reset any account); (2) does `unified-login` require a tenant header, and can tenant isolation be bypassed via `X-Tenant-Id`? (3) do all three login routes share the same rate-limit bucket?

### V7 — High-value controller routes visible in the bundle  [INFO — BAC targets]
`MyApplicationUser/` (system user search by id), `DatabaseBackups` (list + create snapshot!), `RolePermissions/catalog`, `UserPermissions/`, `teachers/`, `Tenants/`. The admin UI guards these with client-side `canActivate` + permission flags — the re-run probes them unauthenticated (module `BAC`).

### SATELLITES — `n8n.arishuniversity.com` publicly referenced  [LOW — exposure]
The app's config points at a public **n8n workflow-automation** instance and a **mediasoup WebSocket** (`wss://ws.…`). n8n has shipped serious CVEs (webhook auth bypass). v1.2's `SATEL` module fingerprints it and checks anonymous access to `/rest/settings`. Recommend: VPN/IP-allowlist, latest patched version, audit workflows holding credentials.

**Run 3 command (v1.2 — no manual endpoint needed):**

```bash
python hecon_auth_repro.py --target https://hecon.arishuniversity.com \
    --i-am-authorized --report-dir ./out3 -v
# optional, if you know the tenant id from DevTools:
#   --tenant ed
# opt-ins for the flow tests:
#   --allow-reset   (OTP-flow tests; sends OTPs to the probed address)
#   --allow-register
#   --token <JWT from localStorage["token"]>   (enables C6 forgery + IDOR)
```

## Out-of-band notes

- The GitHub PAT used to create this repository was shared in chat text. **Treat it as burned: revoke/rotate it** at GitHub → Settings → Developer settings → Fine-grained tokens, then issue a new one stored only in the team's secret manager.
- The reviewer's sandbox could not reach the origin directly (V2); verification of C1–C11 therefore happens via this script from an allowed network.
