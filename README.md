# jwtXploit

**jwtXploit** is a comprehensive JWT exploitation framework designed for penetration testing, CTFs, and bug bounty hunting. It enables security researchers to test for common vulnerabilities in JSON Web Tokens (JWT).

## Features

- **Unverified Signature Bypass:** Modify tokens and strip the signature check.
- **None Algorithm:** Exploits `alg: none` vulnerability.
- **Weak Key Brute Force:** Brute force HS256 secrets using a wordlist.
- **Header Injection:**
    - JWK (JSON Web Key) Header Injection.
    - JKU (JSON Web Key Set URL) Header Injection.
    - KID (Key ID) Path Traversal.
- **Algorithm Confusion:** Native implementation to test Public Key as HMAC secret (CVE-2016-5431).
- **ES256 Psychic Signature:** Exploits ECDSA signature validation bypass (CVE-2022-21449).
- **Null Signature:** Tests stripping the signature entirely.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 jwtXploit.py <token> [options]
```

Example:
```bash
python3 jwtXploit.py eyJhbGci... -w /path/to/wordlist.txt
```
