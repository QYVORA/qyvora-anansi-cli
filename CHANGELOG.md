# Changelog

## [Unreleased]

### Added
- LICENSE file (MIT)
- SECURITY.md with vulnerability disclosure policy
- Dependabot config for Go deps and GitHub Actions
- golangci-lint configuration
- Makefile with build/test/lint/clean targets
- CONTRIBUTING.md with coding standards
- goreleaser configuration for automated releases
- CI workflow running tests and lint on every push/PR
- SIGINT/SIGTERM handling for clean partial-result abort

### Changed
- Pinned Go version to 1.22.0 in go.mod
- Replaced init() with sync.Once lazy loading in probe, headers, takeover
- Replaced raw int completed counter with atomic.Int64 in discovery, probe, takeover
- Removed unused stealth parameter from tls.probeHost
- Fixed shadowed delay variable in probe.probeHost
- DNS-label validation on target input (rejects IPs, empty labels, >253 chars)
- WHOIS privacy warning about unencrypted TCP transport

### Fixed
- Race condition in concurrent progress counters
