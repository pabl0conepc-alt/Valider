# Contributing to Valider

Contributions that improve authorized technical URL diagnostics are welcome.
Keep changes focused and preserve the project's authorization and network
safety boundaries.

## Before opening a change

- Use only domains you control or have explicit permission to test.
- Do not add account/profile discovery, identity classification, or logic that
  infers whether a profile exists.
- Do not bypass authentication, CAPTCHAs, or other protections.
- Do not add tests that send network requests to external hosts. Inject or mock
  DNS and HTTP behavior, as the existing tests do.
- Avoid adding dependencies unless they are needed for the change.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Keep CLI help and documentation aligned with the actual argument syntax. Add
focused tests for new behavior and safety boundaries. Describe user-visible
changes in `CHANGELOG.md`.

## Pull requests

Explain the problem and behavior change, list tests run, and call out any
security or compatibility considerations. Do not include real user data,
credentials, or unredacted sensitive URLs in examples or test fixtures.
