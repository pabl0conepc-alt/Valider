# Changelog

Notable project changes are recorded here.

## Unreleased

- Added a C++17 policy core with typed allowlist and redirect-chain state,
  integrated with the Python URL validator; allowlist membership uses a
  hash-indexed domain set.
- Added Rust-based HTTP status-class reporting and a non-operative retryability
  hint for common transient statuses, including numeric `Retry-After` values.

## 1.0.0

- Added the Valider CLI for technical HTTP, DNS, TLS, redirect, and neutral HTML
  metadata diagnostics on explicitly authorized domains.
- Added batch input and JSON, TXT, and CSV export.
- Added network safety checks and focused unit tests.
