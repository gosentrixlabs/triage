# Security policy

## Reporting a vulnerability

Please report security issues privately. Don't open a public issue or pull
request.

Use GitHub's private vulnerability reporting: go to the
[Security tab](https://github.com/gosentrixlabs/triage/security) of this
repository and choose **Report a vulnerability**.

Include what you found, how to reproduce it, and the version (`triage version`)
you tested. We'll acknowledge the report, keep you updated while we work on a
fix, and credit you in the release notes unless you'd rather not be named.

## Supported versions

Security fixes are made on the latest release.

## Scope

`triage` reads input files and workspace state that may come from other tools
or from other people, for example a `.triage/state.json` shared through a
repository. We treat these as untrusted. Issues we especially want to hear
about include:

- input or workspace content that can control or corrupt terminal output
- crashes, hangs or excessive memory use caused by an input file
- workspace or export files written with broader permissions than documented
- any way `triage` could be made to read, write or send data beyond what a
  command documents

`triage` makes no network calls. If you find a code path that does, please
report it.
