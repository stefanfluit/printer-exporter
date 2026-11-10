# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/stefanfluit/printer-exporter/security/advisories/new).
Do not open a public issue for a security problem.

Include the version (or image digest), what you observed, and how to
reproduce it. Only the latest release receives fixes.

## Scope

In scope: anything that lets a network peer crash or hang the exporter, make
it send SNMP other than GET/GETNEXT, or inject content into the metrics
output; and anything that weakens the container image (running as root,
extra files, writable paths).

Out of scope: the absence of authentication and TLS on `/metrics`, and the
clear-text community string of SNMP v2c. Both are inherent to the protocols
involved; the README describes how to deploy around them.
