# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest 0.2.x beta | Yes |
| 0.1.x beta | Critical fixes only |
| Older pre-release snapshots | No |

## Report a vulnerability privately

Do not open a public issue. Use GitHub's **Report a vulnerability** button under
the repository's Security tab, or create a private report at:

<https://github.com/ajayasai/OpenConstraint/security/advisories/new>

Include the affected version, impact, minimal reproducer, and any suggested
mitigation. Remove proprietary design data and credentials. If a reproducer
cannot be safely shared, describe the conditions without attaching it.

The maintainers make a best-effort attempt to acknowledge reports within seven
calendar days. Validation, remediation, release, and coordinated disclosure are
handled through a private GitHub security advisory. Credit is offered unless
the reporter prefers anonymity. The project may request a CVE for a published
advisory when appropriate.

## Security boundary

SDC is based on Tcl and can contain arbitrary computation in a full Tcl
interpreter. By default, OpenConstraint's static backend **does not execute Tcl,
command substitutions, environment lookups, sourced files, or shell commands**.
It tokenizes a deliberately supported subset and reports dynamic or unsupported
constructs rather than evaluating them.

The explicit `--opensta` option is different: it executes trusted SDC in a
separately installed OpenSTA process with the caller's permissions. Never enable
it on an untrusted pull request or input. See
[docs/security-model.md](docs/security-model.md) for threats, assumptions, and
safe integration guidance.

This policy covers vulnerabilities in OpenConstraint itself. OpenSTA and other
separately installed tools follow their own security policies.
