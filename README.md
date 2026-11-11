# Valider

Valider is a Python command-line tool for **authorized technical URL diagnostics**.
It reports HTTP status, redirects, DNS answers, basic TLS certificate details,
and neutral HTML title and description metadata.

Valider does **not** discover or classify people, search for profiles, or infer
whether an account exists. Account/profile existence is always **INCONCLUSIVE**.
It does not bypass authentication, CAPTCHAs, or other protections.

## Safety and authorization

- An explicit `--allow-domain` entry is required for every run. Each entry
  authorizes that exact domain and its subdomains; use only domains you control
  or have explicit permission to test.
- Only HTTP and HTTPS on their default ports are accepted.
- DNS is resolved before every request, including every redirect. All resolved
  addresses must be globally routable, and connections are pinned to a validated
  address. Loopback, private, link-local, and other non-global destinations are
  blocked.
- Redirect targets must also be on the allowlist. No request is made to an
  unauthorized host.
- Requests are separated by at least one second. Timeouts are limited to
  1–30 seconds, redirect chains to at most 10 hops, and each run to 1,000 URLs.

## Installation on Kali Linux

Use a virtual environment so installation does not modify Kali's externally
managed system Python:

```bash
sudo apt update
sudo apt install -y build-essential cargo rustc python3-dev python3 python3-venv git
git clone <REPOSITORY_URL>
cd Valider
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install .
```

## Usage

### Check one authorized URL

The domain goes after `--allow-domain`; the URL is a separate positional
argument:

```bash
valider --allow-domain championat.com https://www.championat.com/user/pdr
```

`--allow-domain` accepts a **domain name only**, not a URL. To check several
domains, repeat the option. URLs must still be passed separately:

```bash
valider \
  --allow-domain example.com \
  --allow-domain example.net \
  https://www.example.com/status https://example.net/health
```

### Check URLs from a file

`--input` takes a **local text-file path**, not a URL. Put one URL per line;
blank lines and lines beginning with `#` are ignored:

```text
# links.txt
https://example.com/status
https://www.example.com/health
```

```bash
valider --allow-domain example.com --input links.txt
```

Input URLs are subject to the same allowlist and network checks as positional
URLs. Files may contain up to 1,000 URLs per run.

### Tune limits and export results

```bash
valider --allow-domain example.com \
  --timeout 8 --max-redirects 3 https://example.com/status

valider --allow-domain example.com --input links.txt \
  --format json --output results.json
valider --allow-domain example.com --input links.txt \
  --format csv --output results.csv
valider --allow-domain example.com https://example.com/ \
  --format txt --output results.txt
```

Supported output formats are `json`, `txt`, and `csv`. `--format` and
`--output` must be supplied together. Without them, Valider displays a Rich
terminal table. A nonzero exit status indicates that at least one URL could not
be checked successfully.

### Common command-line errors

- `--allow-domain` needs a domain value **and** at least one URL (or `--input
  FILE`); it does not take the URL as its value.
- Use `--allow-domain`, not the misspelled `--allow-dommain`.
- `--input links.txt` reads a file. To check a URL directly, put it after the
  options as a positional argument.
- URLs outside the allowlist, malformed URLs, and URLs resolving to non-global
  addresses are rejected before connecting.

## Project files

| File | Purpose |
| --- | --- |
| `README.md` | Project overview, safety model, installation, and usage guide. |
| `LICENSE` | States the project's current licensing status and where to ask about reuse. |
| `.gitignore` | Excludes local environments, caches, and generated build artifacts. |
| `CONTRIBUTING.md` | Contribution workflow, coding expectations, and test instructions. |
| `CHANGELOG.md` | Human-readable history of released changes. |
| `SECURITY.md` | Security boundaries and instructions for reporting vulnerabilities. |
| `CODE_OF_CONDUCT.md` | Standards for respectful and constructive participation. |
| `AUTHORS.md` | Records verified authorship and contributor acknowledgements. |
| `setup.py` | Builds the C++17 policy extension as part of Python package installation. |
| `valider/_native.cpp` | Implements typed domain authorization and redirect-chain state. |
| `rust/src/lib.rs` | Classifies HTTP status categories and reports common retryable codes. |

## Development and tests

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Building the package requires C++17, Rust, and Python development toolchains.
The C++ policy component enforces canonical domain matching and redirect-chain
limits. Rust classifies HTTP status codes and adds a retryability hint for
common transient responses. Numeric `Retry-After` values are reported as
technical hints; Valider does not wait or retry automatically. DNS,
global-address checks, and pinned HTTP/TLS connections remain in Python.

Tests use injected DNS/HTTP functions and do not send requests to external
hosts. Contributions must keep that property.
