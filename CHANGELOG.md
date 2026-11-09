# Changelog

## [1.0.0] - 2026-10-30
### Added
- `scan`: threaded header grading (A+ to F) with CSP, HSTS, cookie, CORS and version-leak checks
- `raw`: grade headers pasted from `curl -I` or DevTools
- `fix`: config snippets for nginx, Apache, Caddy and Express
- `--baseline` / `--save-baseline` regression detection, `--min-grade` for CI, `--json`
- Shield banner, unit tests with local HTTP/HTTPS servers
