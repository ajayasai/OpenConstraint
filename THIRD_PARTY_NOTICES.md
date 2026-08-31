# Third-party notices

OpenConstraint's own source code is licensed under Apache-2.0. Runtime and
development dependencies retain their respective licenses. Release provenance
attestations bind published artifacts to their source and build workflow; they
are not a software bill of materials or a transitive dependency/license
inventory. The build backend and direct distribution tools are exactly
versioned in `pyproject.toml`; other development tooling is constrained by
compatible ranges rather than represented as a full transitive lock.

## OpenSTA

[OpenSTA](https://github.com/The-OpenROAD-Project/OpenSTA) is an optional,
separately installed timing engine licensed under GPL-3.0-or-later and offered
under separate commercial terms by its copyright holder. OpenConstraint
v0.3.0-beta does not copy, vendor, link against, or redistribute OpenSTA source
or binaries. When a user explicitly supplies `--opensta`, it can invoke a
separately installed `sta`/`opensta` executable as an isolated child process.
Any future distribution that bundles OpenSTA must be reviewed for and comply
with OpenSTA's applicable license terms.

OpenConstraint's default static audit backend does not require or execute
OpenSTA. References to OpenSTA describe interoperability and do not imply
affiliation or endorsement.

## Public benchmark inputs

The benchmark manifest references gate-level AES, Ibex, and JPEG test designs
and a SKY130HD Liberty model from the OpenROAD 26Q3 repository at immutable
commit `a9147cf3aebe65e058bb3fa89c1f9e524488dbb8`. OpenConstraint does not vendor
those bytes: `benchmark fetch` downloads each upstream file into a
content-addressed cache only after its exact size and SHA-256 are verified.

The manifest preserves file-level license links and notices. OpenROAD is
BSD-3-Clause; Ibex and the SKY130HD standard-cell library are Apache-2.0; the
AES/JPEG design sources use the permissive ASICs World terms recorded in the
manifest. Those upstream terms continue to govern the downloaded inputs.
OpenConstraint's small static-coverage overlays are original Apache-2.0 project
files. They exercise the non-executing coverage model and are not represented
as collection-equivalent OpenROAD helper expansions or sign-off SDC.

The Nangate45 corpus was deliberately excluded because the available Liberty
file carries a legacy restriction header that conflicts with broader platform
licensing. A benchmark manifest is provenance metadata, not legal advice or an
endorsement by any upstream project.

## Reporting an omission

If an attribution or license notice is missing, open a documentation issue. For
a potentially sensitive license or security concern, use the repository's
private vulnerability-reporting channel described in [SECURITY.md](SECURITY.md).
