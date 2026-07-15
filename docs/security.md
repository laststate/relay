# Deployment security

- Keep admin and metrics on loopback or a private management network.
- Use separate secrets for each HTTP source and the admin API.
- Prefer `env:` or `file:` references over literal production tokens.
- Use HTTPS/mTLS for non-loopback TCP and HTTP sources.
- Leave `insecure_skip_verify` off outside a lab.
- Protect the data directory: raw events can hold logs, memory dumps, and IDs.
