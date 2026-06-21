# ANANSI CLI

**Attack Surface Intelligence Engine — Terminal Edition**

Built by [QYVORA OffSec](https://qyvora.netlify.app) — an offensive security company operating out of Tamale, Ghana.

```
anansi target.com
anansi target.com --verbose
anansi target.com --deep
anansi target.com --out json > results.json
anansi target.com --modules discovery,tls,takeover
```

> Only scan targets you own or have explicit written permission to test.

---

## What it does

ANANSI CLI is a terminal-first attack surface recon tool for pentesters and bug bounty hunters. Give it a domain — it runs a full six-phase intelligence pipeline and prints raw technical output you can act on immediately.

By default, ANANSI filters out the noise and only displays **found** assets (e.g., live subdomains, active HTTP/HTTPS hosts, successful TLS certificates, missing security headers on live URLs, exposed paths, and confirmed takeovers). This keeps your terminal clean. If you want to see all attempted checks, including dead subdomains, failed connections, and unchecked endpoints, simply enable the **verbose** flag (`-v`/`--verbose`).

| Phase | Module | What it finds |
|-------|--------|---------------|
| 01 | **DISCOVERY** | Subdomains via crt.sh CT logs + DNS brute-force wordlist (only shows live/dead-CNAME subdomains by default) |
| 02 | **PROBE** | Live HTTP/HTTPS hosts — status codes, servers, redirect chains, titles (only shows live hosts by default) |
| 03 | **TLS** | Certificate expiry, SANs, protocol version, cipher, self-signed detection (only shows successful TLS connections by default) |
| 04 | **HEADERS** | Missing security headers, CORS misconfigurations (only shows audited live endpoints by default) |
| 05 | **PATHS** | Exposed files — `.env`, `.git`, configs, admin panels, backups, API docs (only shows exposed paths by default) |
| 06 | **TAKEOVER** | Dangling CNAMEs pointing to unclaimed cloud services (only shows vulnerable assets by default) |

---

## Performance & Architecture Improvements

We have significantly optimized ANANSI for speed, efficiency, and cleanliness:
* **Native Go DNS Resolver**: Bypasses slow `cgo`-blocked system lookups to query DNS concurrently using pure Go goroutines.
* **Concurrent Probing**: HTTP Probes, TLS analyses, and Security Header checks are fully parallelized based on your thread configuration.
* **Smart Takeover Filtering**: Instead of executing slow DNS lookups for thousands of failed subdomain candidates, ANANSI target-scans only subdomains with verified dead CNAME records or TLS SAN origins.
* **Parallel Exposed Path Probing**: Target hosts have their custom 404 baselines fetched concurrently, and paths are scanned concurrently, avoiding slow sequential lookups.

---

## Install

### Option 1 — Download binary (no Go required)

```bash
# Linux x86_64
curl -L https://github.com/wsuits6/qyvora-anansi-cli/releases/latest/download/anansi-linux-amd64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# Linux arm64 (Raspberry Pi, etc.)
curl -L https://github.com/wsuits6/qyvora-anansi-cli/releases/latest/download/anansi-linux-arm64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/wsuits6/qyvora-anansi-cli/releases/latest/download/anansi-macos-arm64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/wsuits6/qyvora-anansi-cli/releases/latest/download/anansi-macos-amd64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/
```

### Option 2 — Build from source (automated)

**Requirements:** Go 1.22+ and active internet connection.
```bash
git clone https://github.com/wsuits6/qyvora-anansi-cli
cd qyvora-anansi-cli
./install.sh
```

The installer verifies your dependencies, downloads packages, builds the stripped binary, and configures it in your environment path automatically.

The binary has **zero runtime dependencies** — copy it anywhere and run it.

---

## Usage

```bash
# Clean scan — only show found assets (default)
anansi target.com

# Recursive scan — perform recursive subdomain brute-forcing on resolved subdomains
anansi target.com -r
# or:
anansi target.com --recursive

# Verbose scan — show all found and not found/failed outputs
anansi target.com -v
# or:
anansi target.com --verbose

# Subdomain mutation scan — brute-force permutations based on resolved subdomain prefixes
anansi target.com -m
# or:
anansi target.com --mutate

# Scan alternative ports (default: 80,443)
anansi target.com -p 80,443,8080,8443
# or:
anansi target.com --ports 80,443,8080,8443

# Rate limit requests with a delay in milliseconds
anansi target.com --delay 100

# Deep scan — larger wordlist, extended path rules
anansi target.com --deep

# Run specific modules only
anansi target.com --modules discovery,probe,takeover

# Increase per-request timeout (default: 5s)
anansi target.com --timeout 10

# Configure concurrent thread pool (default: 50)
anansi target.com --threads 100

# JSON output — pipe to jq or save for downstream tools
anansi target.com --out json > results.json
anansi target.com --out json | jq '.Findings[] | select(.Severity == "CRITICAL")'

# Markdown output — drop straight into a report
anansi target.com --out markdown > recon.md

# HTML output — generate a premium, high-fidelity dark mode report
anansi target.com --out html > report.html
```

### Flags

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--recursive` | `-r` | false | Enable recursive subdomain brute-forcing on resolved subdomains |
| `--verbose` | `-v` | false | Enable verbose output (shows all found and not found/failed assets) |
| `--mutate` | `-m` | false | Enable subdomain mutation brute-forcing based on resolved prefixes |
| `--ports` | `-p` | 80,443 | Alternative ports to probe (comma-separated list) |
| `--delay` | | 0 | Delay between requests in milliseconds for rate limiting |
| `--deep` | | false | Larger subdomain wordlist + more path probing rules |
| `--out` | | terminal | Output format: `terminal` \| `json` \| `markdown` \| `html` |
| `--timeout` | | 5 | Per-request timeout in seconds |
| `--threads` | `-t` | 50 | Number of concurrent threads to use for scanning |
| `--stealth` | | false | Enable stealth mode: random User-Agent, jitter, skip crt.sh, reduce noise |
| `--modules` | | all | Comma-separated list of modules to run |

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
  │  BY      QYVORA OffSec // qyvora.netlify.app                    │
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

ANANSI CLI is the portable companion to the full ANANSI platform — the API-powered attack surface intelligence service built into the QYVORA OffSec ecosystem. Same detection logic. Same output philosophy. CLI is for your laptop. The API is for your pipeline.

---

## Legal

Only scan targets you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions. QYVORA OffSec accepts no responsibility for misuse of this tool.

---

## License

MIT — fork it, extend it, integrate it. Attribution appreciated.

---

## Contributing

PRs welcome. Open an issue first for major changes. If you add a new path rule, takeover fingerprint, or detection module — open a PR. The goal is to keep the binary small and the signal high.

---

*QYVORA // Tamale, Ghana*
*Cybersecurity in Africa is booming. We are building the people behind it.*