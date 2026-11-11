# Security policy

Valider is intended only for technical checks on domains the operator controls
or has explicit authorization to test. Its allowlist and public-address checks
are safety controls, not a substitute for authorization.

## Reporting a vulnerability

Please do not publish exploit details in a public issue. Use the repository's
private vulnerability reporting feature if it is enabled. Otherwise, contact
the repository maintainers through a private channel listed on the repository
profile. Include the affected version, impact, and a minimal safe reproduction.
Do not include credentials, real personal data, or unauthorized target details.

There is no published response-time guarantee.

## Scope

Reports are most useful when they concern bypasses of domain authorization,
unsafe DNS or redirect handling, unbounded resource use, or exposure of local
data. Valider does not provide account discovery or profile-existence checks.
