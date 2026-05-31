# ANANSI CLI

**Attack Surface Intelligence Engine — Terminal Edition**

Built by [HSOCIETY OFFSEC](https://hsociety.io) — an offensive security company operating out of Accra, Ghana.

```
anansi target.com
anansi target.com --deep
anansi target.com --out json > results.json
anansi target.com --modules discovery,tls,takeover
```

---

## What it does

ANANSI runs a full recon pipeline against a target domain and prints real technical output — not scores, not grades, not a report card. Raw intelligence. The kind of output you can act on immediately.

Six modules, run in sequence:

| Phase | Module | What it finds |
|-------|--------|---------------|
| 01 | **DISCOVERY** | Subdomains via crt.sh CT logs + DNS brute-force |
| 02 | **PROBE** | Live HTTP/HTTPS surface — status codes, servers, titles |
| 03 | **TLS** | Certificate expiry, SANs, protocol version, cipher, self-signed |
| 04 | **HEADERS** | Missing security headers, CORS misconfigurations |
| 05 | **PATHS** | Exposed files — `.env`, `.git`, configs, admin panels, backups |
| 06 | **TAKEOVER** | Dangling CNAMEs pointing to unclaimed cloud services |

---

## Install

**Download the binary (recommended):**
```bash
# Linux x86_64
curl -L https://github.com/hsociety/anansi-cli/releases/latest/download/anansi-linux-amd64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/
```

**Build from source:**
```bash
git clone https://github.com/hsociety/anansi-cli
cd anansi-cli
go build -o anansi .
sudo mv anansi /usr/local/bin/
```

**Requirements:** Go 1.22+ (build only). The binary has zero runtime dependencies.

---

## Usage

```bash
# Standard scan — all six modules
anansi target.com

# Deep scan — larger wordlist, more path rules
anansi target.com --deep

# Run specific modules only
anansi target.com --modules discovery,probe,takeover

# JSON output — pipe to jq or save for further processing
anansi target.com --out json | jq '.Findings[] | select(.Severity == "CRITICAL")'

# Adjust per-request timeout (default: 5s)
anansi target.com --timeout 10
```

---

## Output

No bar charts. No letter grades. Terminal output built for operators:

```
  ══ PHASE 01 ── DISCOVERY // subdomain enumeration + DNS resolution
  ──────────────────────────────────────────────────────────────────
  sources: crt.sh=12  wordlist=3  san=2

  api.target.com                               104.21.44.12      crt.sh    LIVE
  dev.target.com                               104.21.44.13      crt.sh    LIVE
  old.target.com                               —                 wordlist  DEAD
                                               CNAME → target.herokuapp.com

  ══ PHASE 06 ── TAKEOVER // dangling CNAME detection
  ──────────────────────────────────────────────────────────────────

  [CRITICAL ] Subdomain Takeover — Heroku
  ASSET:     old.target.com
  DESC:      CNAME points to unclaimed Heroku app. Takeover viable.
  EVIDENCE:  CNAME: target.herokuapp.com | Body match: "No such app"
  FIX:       Remove the dangling CNAME or claim the Heroku resource.
```

---

## Why

The bug bounty and pentesting community runs on Linux terminals. Tools should be single binaries that do one thing well and get out of the way. ANANSI CLI is the local companion to [ANANSI](https://hsociety.io/anansi) — the API-powered attack surface intelligence service. Same detection logic. Same output philosophy. One is for your laptop, one is for your pipeline.

---

## Legal

Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions. HSOCIETY OFFSEC takes no responsibility for misuse.

---

## License

MIT — fork it, extend it, integrate it.

---

*HSOCIETY OFFSEC // Accra, Ghana // Cybersecurity in Africa is booming. We are building the people behind it.*
