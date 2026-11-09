# ChronoHeaders

> Grade a website's HTTP security headers, then get the config to fix them.
> Part of the **CHRONO SUITE**. Dev: **Chrono**.

Single Python file, standard library plus `rich`. Built for Termux (no root), works anywhere with Python 3.8+.

## Commands

| Command | What it does |
|---|---|
| `scan` | Fetch and grade one or many sites (A+ to F, score out of 100) |
| `raw` | Grade headers pasted from `curl -I` or browser DevTools, no network needed |
| `fix` | Print ready-to-paste config (nginx, Apache, Caddy, Express) for missing or weak headers |

`chronoheaders example.com` is shorthand for `chronoheaders scan example.com`.

## Setup (Termux)

~~~bash
pkg update -y && pkg install -y python git
pip install rich
git clone https://github.com/chrono200/chronoheaders.git
cd chronoheaders
python chronoheaders.py
~~~

## Usage

~~~bash
python chronoheaders.py example.com
python chronoheaders.py github.com google.com -d      # full report for each
python chronoheaders.py example.com --cors --check-http
python chronoheaders.py fix example.com --for apache
curl -sI https://example.com | python chronoheaders.py raw -
python chronoheaders.py -f sites.txt --min-grade B    # CI: exit 1 below B
~~~

### scan options

| Option | Description |
|---|---|
| `-f FILE` | One URL per line, `#` for comments |
| `-t`, `-k` | Timeout (10s); skip TLS verification |
| `--no-follow`, `--max-redirects N` | Redirect handling (default: follow up to 5) |
| `-H 'Name: value'` | Extra request header, repeatable (e.g. a cookie for a logged-in page) |
| `--cors` | Also test CORS with a foreign `Origin` |
| `--check-http` | Also check that `http://` redirects to HTTPS |
| `-d` | Full report for every site (single sites always get one) |
| `--min-grade G` | Exit 1 if any site grades below `G` |
| `--baseline FILE` / `--save-baseline FILE` | Detect regressions between runs |
| `--json` | JSON output |

## What is graded

| Check | Points |
|---|---|
| Content-Security-Policy (`unsafe-inline`, `unsafe-eval`, wildcards, `base-uri`, `object-src`) | 25 |
| Strict-Transport-Security (max-age, `includeSubDomains`, `preload`) | 20 |
| Clickjacking: X-Frame-Options or CSP `frame-ancestors` | 10 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 10 |
| Set-Cookie flags: Secure, HttpOnly, SameSite (only if cookies are set) | 10 |
| Permissions-Policy | 5 |
| Version disclosure (`Server`, `X-Powered-By`, ...) | 5 |
| Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy | 4 + 4 |
| HTTP to HTTPS redirect (with `--check-http` or an `http://` URL) | 5 |
| CORS with a foreign origin (`--cors`) | 5 |

`X-XSS-Protection` and `Cross-Origin-Embedder-Policy` are shown for information and are not scored.

**Grade:** A+ 97 or more with no warnings, A 90+, B 80+, C 65+, D 50+, F below. Only checks that apply are counted, so the score is always out of 100. Plain-HTTP pages cannot pass the HSTS check.

## Regression detection

~~~bash
python chronoheaders.py -f sites.txt --save-baseline base.json
python chronoheaders.py -f sites.txt --baseline base.json
~~~

A removed header or a lower grade is a **regression** and exits with code 1. Changed or added headers are reported but don't fail the run.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | A site could not be scanned, a regression was found, or a grade is below `--min-grade` |
| 2 | Usage error |
| 130 | Interrupted |

## Tests

~~~bash
python -m unittest discover -s tests -v
~~~

Tests use local HTTP and HTTPS servers, so they never touch the internet. The HTTPS test needs `pkg install openssl-tool`.

## Skills demonstrated

HTTP internals (`http.client`, redirects, duplicate headers), security header and CSP analysis, cookie and CORS testing, scoring design, config generation, regression detection, `argparse` subcommands, terminal UI with `rich`, unit testing with local servers.

## Disclaimer

For legal, defensive and educational use on sites you own or are authorized to test. `--cors` sends one extra request with a foreign `Origin` header.

## License

MIT. Copyright (c) 2026 Chrono.
