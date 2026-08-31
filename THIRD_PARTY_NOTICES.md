# Third-party notices

OpenConstraint's own source code is licensed under Apache-2.0. Runtime and
development dependencies retain their respective licenses; the installed
package metadata and dependency lock files are the authoritative inventory for
a particular release.

## OpenSTA

[OpenSTA](https://github.com/The-OpenROAD-Project/OpenSTA) is an optional,
separately installed timing engine licensed under GPL-3.0-or-later and offered
under separate commercial terms by its copyright holder. OpenConstraint
v0.1.0-beta does not copy, vendor, link against, or redistribute OpenSTA source
or binaries. When a user explicitly supplies `--opensta`, it can invoke a
separately installed `sta`/`opensta` executable as an isolated child process.
Any future distribution that bundles OpenSTA must be reviewed for and comply
with OpenSTA's applicable license terms.

OpenConstraint's default static audit backend does not require or execute
OpenSTA. References to OpenSTA describe interoperability and do not imply
affiliation or endorsement.

## Reporting an omission

If an attribution or license notice is missing, open a documentation issue. For
a potentially sensitive license or security concern, use the repository's
private vulnerability-reporting channel described in [SECURITY.md](SECURITY.md).
