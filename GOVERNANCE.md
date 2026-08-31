# Governance

## Current model

OpenConstraint's 0.x beta series is maintainer-led. The maintainers listed in
[MAINTAINERS.md](MAINTAINERS.md) are responsible for releases, security
decisions, repository administration, and the final resolution of technical
disagreements. This document describes the project as it exists today; it does
not imply a foundation, standards-body, or vendor affiliation.

## How decisions are made

Routine changes are decided through pull-request review. Material changes—new
diagnostic semantics, coverage weighting, output-schema changes, removal of
supported syntax, or governance changes—start with a public issue labelled
`rfc`. The proposal should state the problem, alternatives, compatibility
impact, security impact, and migration plan.

The maintainer seeks rough consensus and normally leaves an RFC open for at
least seven days. The maintainer records the decision and rationale in the
issue. Security fixes and release-blocking corrections may use an expedited
private process, with a public explanation after disclosure when safe.

## Compatibility promises

Before 1.0, interfaces may change, but releases must document changes in
[CHANGELOG.md](CHANGELOG.md). Stable diagnostic IDs are not silently reused for
a different meaning. Machine-readable output carries a schema version. A score
or clean run is evidence about the implemented static checks, not proof of
timing correctness or sign-off readiness.

## Contributions and copyright

Contributors retain copyright in their contributions and license them to the
project under Apache-2.0. The project uses Developer Certificate of Origin
sign-off rather than a contributor license agreement. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Conflicts of interest

Maintainers and reviewers disclose employment, financial, or technical
interests that could reasonably affect a decision and recuse themselves where
appropriate. If every maintainer is conflicted, the decision remains open until
an independent reviewer can be found.

## Conduct and appeals

The [Code of Conduct](CODE_OF_CONDUCT.md) applies in project spaces. A person
affected by a governance decision may request reconsideration with new evidence
in the original issue. Conduct appeals are handled privately by a maintainer not
involved in the original report when one is available.
