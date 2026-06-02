# ANANSI CLI

**Attack Surface Intelligence Engine — Terminal Edition**

Built by [HSOCIETY OFFSEC](https://hsociety.io) — an offensive security company operating out of Accra, Ghana.

```
anansi target.com
anansi target.com --deep
anansi target.com --out json > results.json
anansi target.com --modules discovery,tls,takeover
```

> Only scan targets you own or have explicit written permission to test.

---

## What it does

ANANSI CLI is a terminal-first attack surface recon tool for pentesters and bug bounty hunters. Give it a domain — it runs a full six-phase intelligence pipeline and prints raw technical output you can act on immediately. No scores. No dashboards. No noise.

| Phase | Module | What it finds |
|-------|--------|---------------|
| 01 | **DISCOVERY** | Subdomains via crt.sh CT logs + DNS brute-force wordlist |
| 02 | **PROBE** | Live HTTP/HTTPS hosts — status codes, servers, redirect chains, titles |
| 03 | **TLS** | Certificate expiry, SANs, protocol version, cipher, self-signed detection |
| 04 | **HEADERS** | Missing security headers, CORS misconfigurations |
| 05 | **PATHS** | Exposed files — `.env`, `.git`, configs, admin panels, backups, API docs |
| 06 | **TAKEOVER** | Dangling CNAMEs pointing to unclaimed cloud services |

---

## Install

### Option 1 — Download binary (no Go required)

```bash
# Linux x86_64
curl -L https://github.com/wsuits6/hsociety-anansi-cli/releases/latest/download/anansi-linux-amd64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# Linux arm64 (Raspberry Pi, etc.)
curl -L https://github.com/wsuits6/hsociety-anansi-cli/releases/latest/download/anansi-linux-arm64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/wsuits6/hsociety-anansi-cli/releases/latest/download/anansi-macos-arm64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/wsuits6/hsociety-anansi-cli/releases/latest/download/anansi-macos-amd64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/
```

### Option 2 — Build from source

**Requirements:** Go 1.22+
```bash
git clone https://github.com/wsuits6/hsociety-anansi-cli
cd hsociety-anansi-cli
go mod tidy
go build -o anansi .
sudo mv anansi /usr/local/bin/
```

Verify the build:
```bash
anansi --help
```

The binary has **zero runtime dependencies** — copy it anywhere and run it.

---

## Usage

```bash
# Full scan — all six modules
anansi target.com

# Deep scan — larger wordlist, extended path rules
anansi target.com --deep

# Run specific modules only
anansi target.com --modules discovery,probe,takeover

# Increase per-request timeout (default: 5s)
anansi target.com --timeout 10

# JSON output — pipe to jq or save for downstream tools
anansi target.com --out json > results.json
anansi target.com --out json | jq '.Findings[] | select(.Severity == "CRITICAL")'

# Markdown output — drop straight into a report
anansi target.com --out markdown > recon.md
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--deep` | false | Larger subdomain wordlist + more path probing rules |
| `--out` | terminal | Output format: `terminal` \| `json` \| `markdown` |
| `--timeout` | 5 | Per-request timeout in seconds |
| `--modules` | all | Comma-separated list of modules to run |

### Module names for `--modules`

`discovery` `probe` `tls` `headers` `paths` `takeover`

---

## Output

Terminal output built for operators. No bar charts, no letter grades:

```
  ┌─────────────────────────────────────────────────────────┐
  │  ANANSI  Attack Surface Intelligence Engine             │
  │  TARGET  target.com                                     │
  │  TIME    2025-06-01 14:22:01 UTC                        │
  │  BY      HSOCIETY OFFSEC // github.com/wsuits6/hsociety-anansi-cli  │
  └─────────────────────────────────────────────────────────┘

  ══ PHASE 01 ── DISCOVERY // subdomain enumeration + DNS resolution
  ────────────────────────────────────────────────────────────────
  sources: crt.sh=12  wordlist=3  san=2

  api.target.com              104.21.44.12    crt.sh    LIVE
  dev.target.com              104.21.44.13    crt.sh    LIVE
  old.target.com              —               wordlist  DEAD
                              CNAME → target.herokuapp.com

  ══ PHASE 05 ── PATHS // exposed endpoint + file detection
  ────────────────────────────────────────────────────────────────

  [CRITICAL ] Exposed .env File
  ASSET:     https://api.target.com/.env
  DESC:      /.env returned HTTP 200
  EVIDENCE:  HTTP 200 at https://api.target.com/.env
             APP_KEY=base64:abc123... DB_PASSWORD=prod_pass_here...
  FIX:       Restrict or remove /.env from public access.

  ══ PHASE 06 ── TAKEOVER // dangling CNAME detection
  ────────────────────────────────────────────────────────────────

  [CRITICAL ] Subdomain Takeover — Heroku
  ASSET:     old.target.com
  DESC:      CNAME points to unclaimed Heroku app. Takeover viable.
  EVIDENCE:  CNAME: target.herokuapp.com | Body match: "No such app"
  FIX:       Remove the dangling CNAME or claim the Heroku resource.

  ══ SUMMARY ──────────────────────────────────────────────────────
  target      target.com
  duration    1m43s
  subdomains  17 discovered, 11 live
  risk score  74/100

  findings    CRIT:3  HIGH:7  MED:4  LOW:6  INFO:2
```

---

## Project structure

```
anansi-cli/
├── main.go                      # Entry point
├── go.mod                       # Go module + dependencies
├── cmd/
│   └── root.go                  # CLI command, flags, phase orchestration
└── internal/
    ├── output/
    │   ├── types.go             # Shared data structures (Report, Finding, etc.)
    │   └── terminal.go          # Terminal/JSON renderer
    ├── discovery/
    │   ├── discovery.go         # crt.sh + DNS brute-force enumeration
    │   └── wordlist.go          # Default and deep subdomain wordlists
    ├── probe/
    │   └── probe.go             # HTTP/HTTPS surface probing
    ├── tls/
    │   └── tls.go               # TLS certificate analysis + SAN discovery
    ├── headers/
    │   └── headers.go           # Security header audit + CORS check
    ├── paths/
    │   └── paths.go             # Exposed path + file detection
    └── takeover/
        └── takeover.go          # Subdomain takeover detection
```

---

## Why

The pentesting and bug bounty community runs on Linux terminals. Tools should be single binaries that do one thing well and get out of the way. No web UI, no cloud account, no API key required.

ANANSI CLI is the portable companion to [ANANSI](https://hsociety.io/anansi) — the API-powered attack surface intelligence service built into the HSOCIETY OFFSEC platform. Same detection logic. Same output philosophy. CLI is for your laptop. The API is for your pipeline.

---

## Legal

Only scan targets you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions. HSOCIETY OFFSEC accepts no responsibility for misuse of this tool.

---

## License

MIT — fork it, extend it, integrate it. Attribution appreciated.

---

## Contributing

PRs welcome. Open an issue first for major changes. If you add a new path rule, takeover fingerprint, or detection module — open a PR. The goal is to keep the binary small and the signal high.

---

*HSOCIETY OFFSEC // Accra, Ghana*
*Cybersecurity in Africa is booming. We are building the people behind it.*