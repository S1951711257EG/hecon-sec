# hecon-sec

Security review workspace for **HECON** (`https://hecon.arishuniversity.com/`), the Faculty of Home Economics app at Arish University. Owned by the site operator; all testing is owner-authorized.

## Contents

| File | Purpose |
|------|---------|
| `FINDINGS.md` | Full findings report: verified results (V1–V3), the takeover-class test matrix (C1–C11), and a prioritized remediation checklist |
| `hecon_auth_repro.py` | Self-contained reproduction script — discovers the API from the SPA bundle, then runs rate-limited, non-destructive tests for every claim (user enumeration, NoSQL/SQLi login bypass, mass assignment, JWT forgery, reset-token leaks, CORS reflection, missing authz/IDOR, headers, default creds) |
| `mock_hecon.py` | Local mock app used to smoke-test the repro script safely before touching the real target |

## Quick start

```bash
pip install requests

# 1) (optional) prove the tool works on the local mock first
python mock_hecon.py &
python hecon_auth_repro.py --target http://127.0.0.1:8765 \
    --i-am-authorized --rate 0.3 --report-dir ./mock_out

# 2) run against the real target from an allowed network
python hecon_auth_repro.py --target https://hecon.arishuniversity.com \
    --i-am-authorized --report-dir ./out -v
```

Optional consent flags (state-changing tests stay off by default):

```bash
--allow-register   # mass-assignment test (creates sectest_repro_* account)
--allow-reset      # password-reset flow tests (may send reset emails)
--test-creds       # 6-attempt default-credential check
--token <JWT>      # low-priv token: enables IDOR + alg=none forgery tests
--probe-user a@b.c # known-real email for sharper enumeration detection
```

## Rules of engagement

- Owner-authorized testing only; max ~8 failed logins per run; ≥1 s between requests.
- No DoS, no data destruction, payloads < 2 KB; findings print exact `curl` repros.
- Delete any `sectest_repro_*` accounts after testing.
- **Rotate the GitHub token** that was used to bootstrap this repo — it was shared in chat and must be considered burned.
