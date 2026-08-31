# Repository launch settings

These settings cannot be enforced by files alone. A repository administrator
should verify them before announcing a release.

## Identity and features

- Visibility: public.
- Default branch: `main`.
- Description: `Auditable, deterministic SDC constraint-quality checks and structural coverage for CI.`
- Topics: `eda`, `sdc`, `static-timing-analysis`, `opensta`, `verilog`, `sarif`, `lint`, `ci`.
- Enable Issues, Discussions, Releases, and the Security tab.
- Add a social preview and documentation URL after Pages is deployed.
- Prefer versioned documentation in the repository over an unmaintained wiki.

## Branch and tag rules

- Protect `main`: require a pull request, required CI/security checks, resolved
  conversations, and linear history; block force-push and deletion.
- Require the repository's `DCO sign-off` check on pull requests.
- Require one approving review once a second active maintainer exists. Do not
  misrepresent single-person self-review as independent review.
- Apply rules to administrators except for a documented emergency path.
- Protect release tags matching `v*` from update or deletion.
- Enable squash merge, automatic branch deletion, and auto-merge after checks.

## Actions

- Default workflow permissions: read repository contents.
- Do not allow Actions to create or approve pull requests by default.
- Allow only required Actions and require full-length commit-SHA pinning.
- Keep fork pull-request workflows read-only and never expose release secrets.

## Security

- Require two-factor authentication for maintainers.
- Enable dependency graph, Dependabot alerts and updates, CodeQL/code scanning,
  secret scanning, push protection, and private vulnerability reporting.
- Subscribe maintainers to security-alert notifications.
- Review OpenSSF Scorecard results; display a badge only after results publish.

## PyPI trusted publishing

- Create a protected GitHub environment named `pypi`.
- Configure PyPI Trusted Publishing for `.github/workflows/release.yml` and that
  environment; do not store an API token.
- Optionally require a maintainer approval in the environment.
- Set repository variable `PYPI_PUBLISH` to `true` only after the package name
  and trusted publisher are configured. Without that variable, tag releases are
  created on GitHub but PyPI publishing is intentionally skipped.
