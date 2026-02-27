<div align="center">

```
___       ________  _  __       ______  _ ______
      / / |     / /_  __/ | |/ /____  / / __ \(_)_  __/
 __  / /| | /| / / / /    |   // __ \/ / / / / / / /
/ /_/ / | |/ |/ / / /    /   |/ /_/ / / /_/ / / / /
\____/  |__/|__/ /_/____/_/|_/ .___/_/\____/_/ /_/
                             /_/
```

**JWT Exploitation Framework**

*28 attacks · 30 CLI flags · 97 tests · Single-file · Zero setup*

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-97%20passing-brightgreen)](#testing)
[![Attacks](https://img.shields.io/badge/attacks-28-red)](#attack-reference)

**Developed by:** [Shoaib Bin Rashid (R3D_XplOiT)](https://github.com/Shoaib-Bin-Rashid)
 · [LinkedIn](https://www.linkedin.com/in/shoaib-bin-rashid/)
 · [Twitter / X](https://x.com/ShoaibBinRashi1)
 · [shoaibbinrashid11@gmail.com](mailto:shoaibbinrashid11@gmail.com)

</div>

---

> **Legal Notice:** This tool is intended for authorised penetration testing, bug bounty research, and security education only. Never test systems without explicit written permission. The author accepts no liability for misuse.

---

## Table of Contents

1. [Overview](#overview)
2. [What Makes jwtXploit Different](#what-makes-jwtxploit-different)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Attack Reference](#attack-reference) — all 28 attacks
6. [CLI Reference](#cli-reference) — all 30 flags
7. [Modes of Operation](#modes-of-operation)
   - [Interactive Menu](#interactive-menu)
   - [Autopwn (Full Automation)](#autopwn-full-automation)
   - [Batch Mode](#batch-mode)
   - [Decode / Recon Mode](#decode--recon-mode)
   - [Intercept Proxy](#intercept-proxy)
   - [Diff Tokens](#diff-tokens)
   - [Compare Environments](#compare-environments)
8. [Delivery Matrix](#delivery-matrix)
9. [Reporting](#reporting)
10. [CI/CD Integration](#cicd-integration)
11. [CVE Reference](#cve-reference)
12. [Testing](#testing)
13. [Workflow Examples](#workflow-examples)
14. [Architecture](#architecture)
15. [Contributing](#contributing)
16. [Contact](#contact)

---

## Overview

**jwtXploit** is a single-file, zero-dependency-friction JWT exploitation framework built for professional penetration testers and bug bounty hunters. It covers the complete JWT attack surface — from trivial `alg:none` bypasses through advanced cryptographic attacks (ECDSA nonce reuse, RSA sig2n key recovery), JWE exploitation, OpenID Connect confusion, and cross-environment drift detection.

Every attack auto-verifies against a live target URL, generates PoC `curl` commands, and can export findings in JSON, HTML, SARIF, Markdown, or Nuclei YAML format.

---

## What Makes jwtXploit Different

| Capability | jwtXploit | jwt_tool | jwt-hack |
|---|---|---|---|
| Attacks | **28** | ~15 | ~8 |
| JWE Support | ✅ (3 attacks) | ❌ | ❌ |
| ECDSA k-reuse key recovery | ✅ | ❌ | ❌ |
| RSA sig2n key recovery | ✅ | ✅ | ❌ |
| OIDC provider confusion | ✅ | ❌ | ❌ |
| Nuclei template export | ✅ | ❌ | ❌ |
| SARIF output | ✅ | ❌ | ❌ |
| Passive intercept proxy | ✅ | ❌ | ❌ |
| Cross-env drift detection | ✅ | ❌ | ❌ |
| Timestamp overflow | ✅ | ❌ | ❌ |
| Header param fuzzer (30+) | ✅ | ❌ | ❌ |
| Batch mode | ✅ | ✅ | ❌ |
| CI/CD (`--quiet`, `--env`) | ✅ | ❌ | ❌ |
| Rate limiting + jitter | ✅ | ❌ | ❌ |
| Webhook notifications | ✅ | ❌ | ❌ |
| SOCKS5 proxy | ✅ | ❌ | ❌ |

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip

### Step 1 — Clone

```bash
git clone https://github.com/Shoaib-Bin-Rashid/Pentest-Automated-Tools.git
cd Pentest-Automated-Tools/Web/jwtXploit
```

### Step 2 — Install dependencies

```bash
# Recommended: use a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

**Dependencies:**

| Package | Version | Purpose |
|---------|---------|---------|
| `PyJWT` | ≥ 2.6.0 | JWT encode/decode |
| `cryptography` | ≥ 38.0.0 | RSA/EC key generation and signing |
| `requests` | ≥ 2.28.0 | HTTP verification of tokens |
| `colorama` | ≥ 0.4.6 | Cross-platform terminal colour |
| `PySocks` | ≥ 1.7.1 | SOCKS5 proxy support |

**Optional:**

| Package | Purpose |
|---------|---------|
| `jwcrypto` | JWE PBES2 brute force (attack #24) — graceful fallback if absent |
| `hashcat` | GPU-accelerated brute force via `--hashcat` flag |

### Step 3 — Verify

```bash
python3 jwtXploit.py --help
```

---

## Quick Start

```bash
# 1. Decode and analyse a token (no attacks, no network)
python3 jwtXploit.py eyJhbGci... --decode

# 2. Run ALL attacks against a live target (one command)
python3 jwtXploit.py eyJhbGci... --url https://api.target.com/profile --autopwn

# 3. Run ALL attacks, save HTML report, export Nuclei templates
python3 jwtXploit.py eyJhbGci... \
  --url https://api.target.com/profile \
  --autopwn \
  --escalate-role admin \
  -o report.html --format html \
  --nuclei-export ./nuclei-templates/

# 4. Interactive menu — explore one attack at a time
python3 jwtXploit.py eyJhbGci...
```

---

## Attack Reference

All 28 attacks are organised by category. Each attack is numbered as it appears in the interactive menu.

### Signature Bypass

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| 1 | **Null Signature** | Strip the signature component entirely — tests libraries that skip verification when sig is empty | — |
| 2 | **Unverified Signature** | Replace signature with random bytes — tests `verify=false` misconfiguration | — |
| 3 | **alg:none — 7 variants** | `none`, `None`, `NONE`, `nOnE`, URL-encoded, whitespace prefix/suffix variants | CVE-2015-9235 |
| 4 | **Weak Key Brute Force** | Multi-threaded wordlist brute force against HS256/384/512 secrets; optional GPU hashcat mode | — |

### Header Injection

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| 5 | **JWK Header Injection** | Embeds a self-signed RSA public key in the `jwk` header, signs with matching private key | CVE-2018-0114 |
| 6 | **JKU Header Injection** | Hosts a live JWKS server on a free port, injects `jku` pointing at attacker's endpoint | CVE-2018-0114 |
| 7 | **KID Path Traversal** | Injects `/dev/null`, `/proc/sys/kernel/randomize_va_space`, Windows paths into `kid` | — |
| 10 | **KID SQL Injection** | `' UNION SELECT 'secret'--`, `OR '1'='1`, and 6 other SQL injection payloads in `kid` | — |
| 11 | **KID SSRF** | Injects SSRF payloads into `kid`: AWS metadata, GCP metadata, internal IPs | — |
| 13 | **x5c Header Injection** | Self-signed certificate chain injected into `x5c` header | — |
| 15 | **typ/cty Header Mutation** | 15 variants: `jwt+api`, `application/jwt`, nested `cty:JWT`, etc. | — |
| 28 | **Header Parameter Fuzzer** | 30+ obscure params: `crit:[]`, `zip:DEF`, `b64:false`, null `alg`, SQL in `kid`, 4096-byte overflow | — |

### Algorithm Confusion

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| 8 | **Algorithm Confusion (RS256→HS256)** | Signs token with RSA public key as HMAC secret | CVE-2016-5431 |
| 9 | **ES256 Psychic Signature** | Empty/zeroed ECDSA signature bypass against Java/Go libraries | CVE-2022-21449 |
| 18 | **ES384/ES512 Psychic Signature** | Same bypass extended to ES384 and ES512 | CVE-2022-21449 |
| 19 | **PS256 PSS Blinding** | RSA-PSS signature forgery via malformed salt length | — |
| 14 | **sig2n RS256 Key Recovery** | Recover RSA modulus N from two tokens; forge RS256 tokens without the private key | — |
| 26 | **ECDSA k-Reuse Key Recovery** | If two ES256 tokens share nonce k (same r value), the EC private key is mathematically recovered | — |

### Endpoint & Key Discovery

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| 12 | **JWT Library Fingerprint** | Identifies backend library (PyJWT, JJWT, nimbus, node-jsonwebtoken, etc.) from error responses | — |
| 16 | **JWKS Endpoint Discovery** | Probes 20+ well-known JWKS paths, downloads keys, runs key-confusion on each | — |

### Claim & Payload Attacks

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| 17 | **Claim Fuzzing** | 50+ privilege escalation payloads across `role`, `scope`, `admin`, `sub`, `permissions`, `groups` | — |
| 22 | **JWE Inner JWT alg:none** | Strips signature inside a JWE-wrapped JWT | — |
| 27 | **Timestamp Integer Overflow** | Tests 8 edge cases: INT32\_MAX, INT64\_MAX, -1, 0, YEAR\_2038, MAX\_UINT32 for `nbf`/`exp`/`iat` | — |

### JWE (Encrypted JWT) Attacks

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| 22 | **JWE Inner JWT alg:none** | Unwraps JWE outer layer, modifies inner JWT with alg:none | — |
| 23 | **JWE alg:dir Confusion** | Replaces key-wrapping algorithm with `dir` (direct key) to bypass encryption validation | — |
| 24 | **JWE PBES2 Brute Force** | Brute forces PBES2-HS256+A128KW password from a wordlist | — |

### OpenID Connect & Protocol

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| 25 | **OpenID Connect Provider Confusion** | Runs live OIDC server, swaps `iss` to attacker endpoint, tests provider confusion | — |
| 20 | **Cookie Security Scanner** | Checks HttpOnly, Secure, SameSite flags; tests JWT in cookies and localStorage patterns | — |
| 21 | **Token Replay Detection** | Submits identical token N times — tests for nonce/jti replay protection | — |

### Environment & Orchestration

| # | Attack | Description | CVE |
|---|--------|-------------|-----|
| — | **Diff Tokens** | Loads N tokens, diffs claims, detects static vs dynamic claims, tests horizontal escalation | — |
| — | **Compare Environments** | Tests dev/staging tokens against production — detects cross-env secret sharing | — |

---

## CLI Reference

```
python3 jwtXploit.py [token] [options]
```

### Core

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `token` | positional | — | JWT or JWE token to test |
| `-w`, `--wordlist` | FILE | — | Wordlist for weak-key brute force |
| `--url` | URL | — | Target endpoint for live verification |
| `--decode` | flag | — | Decode + recon mode, no attacks |
| `--autopwn` | flag | — | Run all automatable attacks non-interactively |

### HTTP / Network

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--proxy` | URL | — | `http://host:port` or `socks5h://host:port` |
| `--no-ssl-verify` | flag | SSL on | Disable TLS verification |
| `--timeout` | SEC | 10 | Per-request timeout |
| `--rate-limit` | N | 0 | Max requests/sec (0 = unlimited) |
| `--jitter` | PCT | 0 | Random ±PCT% jitter on rate-limit sleep |

### Attack Modifiers

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--escalate-role` | ROLE | — | Auto-set `role`/`admin`/`sub` to ROLE in all autopwn tokens |
| `--strip-exp` | flag | — | Remove `nbf`/`iat`, push `exp` 10 years forward |
| `--hashcat` | flag | — | Use GPU hashcat instead of Python threading |
| `--sig2n` | TOKEN2 | — | Second RS256 token for sig2n key recovery (#14) |
| `--ec-key-recover` | TOKEN2 | — | Second ES256 token for ECDSA k-reuse recovery (#26) |
| `--key-bits` | N | 2048 | RSA key size hint for sig2n |

### Fast-Track Modes

Skip the interactive menu and jump directly to a single attack:

| Flag | Attack |
|------|--------|
| `--claim-fuzz` | Claim fuzzing (#17) |
| `--replay` | Token replay (#21) |
| `--openid-fuzz` | OIDC provider confusion (#25) |
| `--fuzz-header` | Header parameter fuzzer (#28) |
| `--ts-overflow` | Timestamp overflow (#27) |
| `--discover-jwks` | JWKS discovery (#16) |

### Advanced Modes

| Flag | Description |
|------|-------------|
| `--batch FILE` | One `token` or `token::https://url` per line — autopwn each |
| `--diff-tokens FILE` | Load N tokens, diff claims, test horizontal escalation |
| `--intercept PORT` | Start passive JWT capture proxy; autopwn every captured token |
| `--compare-envs FILE [FILE ...]` | Test dev/staging token files against production `--url` |
| `--replay-count N` | Number of replay attempts (default: 5) |

### CI/CD & Reporting

| Flag | Description |
|------|-------------|
| `--quiet` | Machine-readable output, no colour, no banner; `exit 1` on confirmed finding |
| `--env` | Read token from `$JWTX_TOKEN`, URL from `$JWTX_URL` |
| `--webhook URL` | POST confirmed findings JSON to Slack/Discord/custom URL |
| `-o FILE` | Save report to file |
| `--format FMT` | `json` (default) · `txt` · `md` · `sarif` · `html` |
| `--nuclei-export DIR` | Export one Nuclei YAML template per confirmed finding |

---

## Modes of Operation

### Interactive Menu

Run the tool with just a token to enter the interactive menu. You will be shown attack recommendations based on the token's `alg` and claims, then presented with numbered attack options.

```bash
python3 jwtXploit.py eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIG
```

```
[*] Recommended attacks for alg=RS256:
  → Algorithm Confusion (RS256 → HS256)
  → JWK Header Injection
  → sig2n RS256 Key Recovery
  → JWKS Discovery

[1]  Null Signature
[2]  Unverified Signature
...
[28] Header Parameter Fuzzer
[0]  Exit
```

### Autopwn (Full Automation)

Runs all 28 automatable attacks in sequence, verifies each against `--url`, prints PoC `curl` commands for every hit, and saves a report. One command replaces hours of manual testing.

```bash
python3 jwtXploit.py eyJhbGci... \
  --url https://api.target.com/v1/user \
  --autopwn \
  --escalate-role admin \
  --strip-exp \
  --rate-limit 5 \
  --jitter 20 \
  -o report.json
```

JWE tokens are automatically detected — JWE-specific attacks (#22–24) are prepended to the autopwn queue.

### Batch Mode

Process a large list of tokens from a bug bounty scope or a crawl. Useful when you have intercepted dozens of JWTs across multiple endpoints.

```bash
# tokens.txt format:
# eyJhbGci...                          (token only)
# eyJhbGci...::https://api.target.com  (token with specific URL)

python3 jwtXploit.py --batch tokens.txt \
  --url https://api.target.com/profile \
  --escalate-role admin \
  -o batch_results.html --format html
```

### Decode / Recon Mode

Full static analysis of a token with zero network traffic. Outputs: algorithm, all header/payload claims, embedded secret detection, library fingerprint hints, and recommended attack list.

```bash
python3 jwtXploit.py eyJhbGci... --decode
```

JWE tokens are automatically detected and their encrypted header is decoded for recon.

### Intercept Proxy

Start a transparent HTTP proxy that sniffs every JWT from passing traffic and immediately runs autopwn on each unique token.

```bash
# Terminal 1: start proxy
python3 jwtXploit.py --intercept 8080 \
  --url https://api.target.com/profile \
  --webhook https://hooks.slack.com/your/webhook

# Terminal 2: browse (or run curl through proxy)
curl -x http://127.0.0.1:8080 https://api.target.com/profile \
  -H "Authorization: Bearer eyJhbGci..."
```

Every unique JWT is SHA-256 deduplicated — each token is only tested once.

### Diff Tokens

Load multiple tokens (e.g. from different user accounts or sessions), automatically diff their claims, classify each claim as static or dynamic, and test cross-user token swaps for horizontal privilege escalation.

```bash
# tokens_file.txt: one token per line
python3 jwtXploit.py --diff-tokens tokens_file.txt \
  --url https://api.target.com/account
```

Output shows a side-by-side claim table, marks which claims differ between users, and tests swapping each user's token against other accounts' endpoints.

### Compare Environments

Detects cross-environment JWT acceptance — the critical misconfiguration where dev or staging tokens work on production because the signing secret is shared.

```bash
# One file per environment
python3 jwtXploit.py \
  --compare-envs dev_tokens.txt staging_tokens.txt \
  --url https://api.production.com/profile
```

Outputs a table: `[env] sub=X HTTP 200 ✅ ACCEPTED` — any acceptance is a critical finding.

---

## Delivery Matrix

jwtXploit tests every attack across **13 delivery methods** automatically:

| Method | Header / Location |
|--------|-------------------|
| Bearer token | `Authorization: Bearer <token>` |
| Lowercase bearer | `authorization: bearer <token>` |
| Raw Authorization | `Authorization: <token>` |
| X-Auth-Token | `X-Auth-Token: <token>` |
| X-Access-Token | `X-Access-Token: <token>` |
| X-JWT-Token | `X-JWT-Token: <token>` |
| X-Api-Key | `X-Api-Key: <token>` |
| Cookie (generic) | `Cookie: token=<token>` |
| Cookie (jwt) | `Cookie: jwt=<token>` |
| Cookie (session) | `Cookie: session=<token>` |
| Cookie (access_token) | `Cookie: access_token=<token>` |
| JSON body | `{"token": "<token>"}` |
| GraphQL | `{"query": "{ me { id } }", "variables": {"token": "<token>"}}` |

---

## Reporting

### Formats

| Format | Flag | Best For |
|--------|------|---------|
| JSON | `--format json` | Automation, ingestion into SIEM/ticketing |
| Markdown | `--format md` | Bug bounty reports, documentation |
| HTML | `--format html` | Stakeholder reports (dark-mode, request/response diff) |
| SARIF 2.1.0 | `--format sarif` | GitHub Advanced Security, VS Code, CI/CD pipelines |
| Plain text | `--format txt` | Quick review, terminal archiving |

### Nuclei Template Export

Every confirmed finding can be auto-exported as a ready-to-run [Nuclei](https://github.com/projectdiscovery/nuclei) template:

```bash
python3 jwtXploit.py eyJhbGci... \
  --url https://api.target.com/profile \
  --autopwn \
  --nuclei-export ./nuclei-templates/

# Then run the templates against the full scope
nuclei -t ./nuclei-templates/ -l scope.txt
```

Each template includes: `id`, `info.severity`, `info.tags: [jwt]`, request headers with the forged token, and response matchers.

### Webhook Notifications

Get real-time Slack/Discord pings on confirmed findings during long scans:

```bash
# Slack
python3 jwtXploit.py ... --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

# Discord
python3 jwtXploit.py ... --webhook https://discord.com/api/webhooks/XXX/YYY

# Custom
python3 jwtXploit.py ... --webhook https://your.server.com/jwt-findings
```

Payload: `{"attack": "...", "token": "...", "verify_reason": "...", "poc_curl": "..."}`

---

## CI/CD Integration

### GitHub Actions

```yaml
name: JWT Security Scan

on: [push, pull_request]

jobs:
  jwt-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install jwtXploit
        run: pip install -r requirements.txt

      - name: Run JWT scan
        env:
          JWTX_TOKEN: ${{ secrets.TEST_JWT_TOKEN }}
          JWTX_URL:   ${{ secrets.TEST_JWT_URL }}
        run: |
          python3 jwtXploit.py \
            --env \
            --autopwn \
            --quiet \
            --strip-exp \
            --escalate-role admin \
            -o results.sarif --format sarif
        # exit 1 if any confirmed finding — fails the pipeline

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
jwt-security-scan:
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - python3 jwtXploit.py --env --autopwn --quiet -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  variables:
    JWTX_TOKEN: $TEST_JWT_TOKEN
    JWTX_URL:   $TEST_JWT_URL
```

### Jenkins

```groovy
stage('JWT Security Scan') {
    environment {
        JWTX_TOKEN = credentials('jwt-test-token')
        JWTX_URL   = 'https://staging-api.internal/profile'
    }
    steps {
        sh 'pip install -r requirements.txt'
        sh 'python3 jwtXploit.py --env --autopwn --quiet -o report.sarif --format sarif'
    }
}
```

---

## CVE Reference

| CVE | Score | Attack | Description |
|-----|-------|--------|-------------|
| CVE-2015-9235 | 9.8 | alg:none | JWT `alg:none` bypass in `node-jsonwebtoken` |
| CVE-2016-5431 | 8.1 | Algorithm Confusion | RS256 public key used as HS256 HMAC secret |
| CVE-2018-0114 | 9.8 | JWK/JKU Injection | Cisco node-jose attacker-controlled JWK |
| CVE-2019-20933 | 9.8 | Unverified Signature | InfluxDB JWT verification bypass |
| CVE-2020-28042 | 5.3 | Null Signature | python-jwt null signature acceptance |
| CVE-2022-21449 | 7.5 | ES256 Psychic Sig | Java ECDSA `verifySignature` returns true for empty sig |
| CVE-2022-29217 | 7.5 | Algorithm Confusion | PyJWT algorithm confusion |
| CVE-2023-37947 | 8.2 | KID SSRF | Jenkins JWT plugin SSRF via `kid` |

---

## Testing

The test suite uses `unittest` / `pytest` with 97 tests across 23 test classes.

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run a specific class
python3 -m pytest tests/ -k TestEcdsaKReuse -v

# With coverage
pip install pytest-cov
python3 -m pytest tests/ --cov=jwtXploit --cov-report=html
```

**Test classes:**

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestDecodeToken` | Token parsing, JWE detection | `decode_token`, `get_header`, `_is_jwe` |
| `TestApplyExpStrip` | exp/nbf manipulation | `apply_exp_strip` |
| `TestManualNoneToken` | alg:none variants | `manual_none_token` |
| `TestScanTokenSecrets` | Embedded secret detection | `scan_token_secrets` |
| `TestRecommendAttacks` | Attack recommendation engine | `recommend_attacks` |
| `TestCveLookup` | CVE map lookups | `_cve_for_attack`, `CVE_MAP` |
| `TestSaveReport` | All 5 report formats | `save_report` |
| `TestParseBatchLine` | Batch file parsing | `_parse_batch_line` |
| `TestFingerprintHeaderMatching` | Library fingerprint | `fingerprint_jwt_library` |
| `TestClaimFuzzMatrix` | 50+ claim fuzz entries | `_CLAIM_FUZZ_MATRIX` |
| `TestSarifReport` | SARIF 2.1.0 schema | `save_report` (sarif) |
| `TestHtmlReport` | HTML report structure | `save_report` (html) |
| `TestGraphqlDetection` | GraphQL URL detection | `_is_graphql_url` |
| `TestReplayDetect` | Replay attack output | `attack_replay_detect` |
| `TestJweDetection` | JWE detection + decode | `_is_jwe`, `_decode_jwe_header` |
| `TestDiffTokens` | Static/dynamic claim diff | `diff_tokens_mode` |
| `TestInterceptExtraction` | JWT regex extraction | `_InterceptHandler` |
| `TestOpenIdFuzzCveMap` | OIDC + Phase 10 CVE coverage | `CVE_MAP` |
| `TestNucleiExport` | Nuclei YAML generation | `_nuclei_template`, `export_nuclei_templates` |
| `TestEcdsaKReuse` | ECDSA k-reuse math | `_ecdsa_recover_private_key`, `_modinv` |
| `TestTimestampOverflow` | Timestamp edge cases | `_TS_EDGE_CASES` |
| `TestFuzzHeaderParams` | Header fuzz matrix | `_HEADER_FUZZ_PARAMS` |
| `TestCompareEnvs` | Cross-env detection | `compare_envs_mode` |

---

## Workflow Examples

### Bug Bounty — Full Scope Scan

```bash
# 1. Intercept a session JWT from BurpSuite, save to token.txt
# 2. Recon
python3 jwtXploit.py $(cat token.txt) --decode

# 3. Full autopwn with admin escalation
python3 jwtXploit.py $(cat token.txt) \
  --url https://api.target.com/v2/account \
  --autopwn \
  --escalate-role admin \
  --strip-exp \
  --rate-limit 3 --jitter 30 \
  --webhook $SLACK_WEBHOOK \
  --nuclei-export ./templates/ \
  -o report.html --format html

# 4. Check account takeover (horizontal escalation)
python3 jwtXploit.py \
  --diff-tokens intercepted_tokens.txt \
  --url https://api.target.com/v2/account

# 5. Check if dev credentials work on prod
python3 jwtXploit.py \
  --compare-envs dev_tokens.txt staging_tokens.txt \
  --url https://api.target.com/v2/account
```

### Penetration Test — Internal API

```bash
# Through Burp/SOCKS5 proxy
python3 jwtXploit.py eyJhbGci... \
  --url https://internal-api.corp.local/admin \
  --proxy socks5h://127.0.0.1:1080 \
  --no-ssl-verify \
  --autopwn \
  --escalate-role superadmin \
  -o pentest_report.sarif --format sarif

# Extract RS256 private key via sig2n (needs 2 RS256 tokens)
python3 jwtXploit.py token1.jwt \
  --sig2n token2.jwt \
  --url https://internal-api.corp.local/admin
```

### ECDSA Nonce Reuse — Key Recovery

```bash
# If you have two ES256 tokens from the same server
python3 jwtXploit.py eyJhbGciOiJFUzI1NiJ9.PAYLOAD1.SIG1 \
  --ec-key-recover eyJhbGciOiJFUzI1NiJ9.PAYLOAD2.SIG2 \
  --url https://api.target.com/admin \
  --escalate-role admin
```

If both tokens share the same ECDSA nonce (r₁ = r₂), jwtXploit recovers the private key mathematically and forges arbitrary tokens.

### Passive JWT Sniffing

```bash
# Configure your browser/tool to proxy through 127.0.0.1:8080
python3 jwtXploit.py \
  --intercept 8080 \
  --url https://api.target.com/profile \
  --autopwn \
  --escalate-role admin \
  -o intercepted_findings.html --format html
```

---

## Architecture

```
jwtXploit.py                    (single file, ~4,260 lines)
│
├── CONFIG {}                   Global state dict — populated from argparse
│
├── Core Utilities
│   ├── decode_token()          JWT + JWE decode
│   ├── get_header()            Header extraction (JWE-aware)
│   ├── check_url()             13-method delivery tester
│   ├── print_result()          Unified finding printer + PoC curl
│   └── _rate_sleep()           Rate limiting with jitter
│
├── Intelligence
│   ├── recommend_attacks()     Algorithm-based attack recommender
│   ├── fingerprint_jwt_library() Backend library identification
│   ├── _cve_for_attack()       CVE/CVSS lookup
│   └── scan_token_secrets()    Embedded secret detector
│
├── Attacks #1–28               attack_*() functions
│
├── Orchestration
│   ├── run_autopwn()           Runs all attacks in sequence
│   ├── run_batch()             Batch file processor
│   ├── diff_tokens_mode()      Multi-token claim diff + horizontal escalation
│   ├── compare_envs_mode()     Cross-environment drift detection
│   └── run_intercept()         Passive JWT capture proxy
│
├── Reporting
│   ├── save_report()           JSON / TXT / MD / SARIF / HTML
│   └── export_nuclei_templates() Nuclei YAML export
│
└── main()                      argparse — 30 flags
```

**Design principles:**
- **Single file** — no modules, no complex installation, drop anywhere
- **Zero side effects** — all state in `CONFIG{}`, functions are independently testable
- **Fail-safe** — every attack wrapped in try/except; one failure never stops autopwn
- **CI-friendly** — `--quiet` produces machine-readable output, `exit 1` on findings
- **No mandatory external services** — JWKS server, OIDC server, intercept proxy are all stdlib-based

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-attack`
3. Write your attack function following the `attack_*(token, url=None)` pattern
4. Add it to `run_autopwn()` and the interactive menu in `main()`
5. Write tests in `tests/test_jwtxploit.py`
6. Run `python3 -m pytest tests/ -v` — all tests must pass
7. Open a Pull Request

### Attack Function Template

```python
def attack_my_new_attack(token, url=None):
    """
    One-line title.
    Detailed description of what this attack tests and why it works.
    """
    header  = get_header(token)
    payload = decode_token(token)

    # Build forged token
    forged = jwt.encode(payload, "", algorithm="none", headers={...})

    # Record and verify
    print_result("My New Attack — description", forged, payload, header)
    check_url(forged, url)
```

---

## Contact

**Shoaib Bin Rashid (R3D_XplOiT)**

- 🔗 **LinkedIn:** [Shoaib Bin Rashid](https://www.linkedin.com/in/shoaib-bin-rashid/)
- 📧 **Email:** [shoaibbinrashid11@gmail.com](mailto:shoaibbinrashid11@gmail.com)
- 🐙 **GitHub:** [Shoaib-Bin-Rashid](https://github.com/Shoaib-Bin-Rashid)
- 🐦 **Twitter / X:** [@ShoaibBinRashi1](https://x.com/ShoaibBinRashi1)

---

<div align="center">

**jwtXploit** — built by security professionals, for security professionals.

Developed by **Shoaib Bin Rashid (R3D_XplOiT)**

*If this tool helped you find a vulnerability, consider responsible disclosure.*

</div>
