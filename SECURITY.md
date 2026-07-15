# Security policy

Report vulnerabilities privately to the Last State maintainers. Do not open a public issue before a fix is available.

## Security defaults

- Admin and metrics listeners bind to loopback by default.
- Remote Trace destinations must use HTTPS.
- Admin and ingest bearer tokens are independent.
- Authorization uses constant-time comparison.
- Redirects are rejected so credentials are never forwarded to a different host.
- Event and artifact objects use restrictive permissions and content hashes.
- HTTP body size, header size, timeouts, connection count, and concurrent ingest are bounded.
- Unknown YAML fields are rejected.
- Raw event payloads and secrets are never included in normal logs.

## Threat model

Relay treats devices, imported files, remote destinations, artifacts, and network clients as untrusted. Operators must protect the data directory, use TLS outside loopback, rotate tokens, and apply privacy policies before forwarding memory dumps to third parties.
