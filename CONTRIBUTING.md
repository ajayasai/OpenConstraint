# Contributing to OpenConstraint

Thank you for helping make timing constraints easier to inspect. Contributions
of code, rules, fixtures, documentation, issue triage, and design feedback are
welcome.

## Before you start

- Search existing issues and pull requests.
- Use an issue labelled `rfc` before a breaking schema change, a new coverage
  component, or a rule whose semantics may be contentious.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
- Never post proprietary netlists, Liberty data, SDC files, PDK data, or vendor
  logs. Reduce the problem to a synthetic reproducer.

## Development setup

OpenConstraint requires Python 3.11 or newer.

```console
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pip install pre-commit
pre-commit install
```

Run the same core checks used in CI:

```console
ruff check .
ruff format --check .
mypy src/openconstraint
pytest --cov=openconstraint --cov-branch
python -m build
python -m twine check dist/*
```

Parser changes must also preserve the property and seed-corpus suites:

```console
pytest tests/test_parser_properties.py tests/test_fuzz_seed_corpus.py
```

Run the Atheris targets from Linux according to [fuzz/README.md](fuzz/README.md).
Never add proprietary design data to a corpus or crash reproducer.

Changes to parsing, elaboration, coverage, or diagnostics should reproduce the
public OpenROAD semantic baseline before merge. Follow
[benchmarks/README.md](benchmarks/README.md); review baseline updates rather
than regenerating them blindly.

## Adding or changing a diagnostic

Each diagnostic is a user-facing compatibility surface. A contribution must:

1. Use a stable `OC####` identifier and avoid repurposing an existing ID.
2. Explain the structural evidence, risk, and practical remediation.
3. Add a minimal failing fixture, a nearby passing fixture, and edge cases.
4. Assert deterministic text and machine-readable output where relevant.
5. Add or update the rule reference under `docs/rules/`.
6. State known false-positive and false-negative boundaries.
7. Update the coverage methodology if the rule changes any numerator,
   denominator, exclusion, or weight.

Rules should be deterministic and explainable. A new dependency needs a clear
maintenance, security, and license justification.

## Pull requests

Keep pull requests focused. Describe the user-visible effect, tests performed,
compatibility impact, and security impact. Update `CHANGELOG.md` for a notable
change. Resolve review conversations and keep generated files out of commits
unless they are intentionally versioned golden results.

### Developer Certificate of Origin

All commits must be signed off to certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```console
git commit --signoff -m "Describe the change"
```

The sign-off states that you have the right to submit the contribution under
the project's license. It is not a copyright assignment.

## Review expectations

Maintainers review for correctness, determinism, security, compatibility,
documentation, and test quality. CI must pass before merge. A review may ask
for a smaller synthetic fixture or additional evidence when a rule makes a
broad claim.

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
