# Contributing to ANANSI CLI

## PR Process

1. Open an issue first for major changes.
2. Fork the repo, create a feature branch.
3. Run `go test ./...` and `go vet ./...` before committing.
4. Keep PRs focused on a single concern.

## Code Style

- Follow standard Go conventions (`gofmt`, `govet`).
- Use `sync.Once` for package-level initialisation, not `init()`.
- Avoid unused params; use `_` only where the signature must match an interface.
- Use `atomic.Int64` for counters accessed across goroutines.
- Wire `context.Context` through blocking calls where possible.
- No external dependencies beyond what `go.mod` already pins.

## Testing

- Add `_test.go` files alongside the package under test.
- Use table-driven tests for functions with multiple input/output cases.
- Mock network calls where possible; avoid testing against live targets.

## Commit Messages

Use conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.
