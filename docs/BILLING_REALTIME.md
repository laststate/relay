# Relay ↔ billing-service realtime

Relay stays offline-first, but it knows its tier live and reports what it forwards.

## Live link (env only — `relay.yaml` schema is unchanged)

```bash
BILLING_URL=http://billing:8080
BILLING_API_KEY=<bearer for billing-service /v1>
BILLING_ORG_ID=<org-uuid>
```

- `internal/billing.Cache.Get(ctx)` — cached `GET /v1/entitlements/{org}`
  (5 min TTL, fail-open: a billing outage keeps the last known tier and never
  blocks ingest).
- `Config.ReportUsage(ctx, events, key)` — `POST /v1/usage` every 60s from the
  forwarder with `Idempotency-Key: org:events:YYYYMMDDHHMM` so replays dedupe.
- SSE tail (`GET billing-service /v1/billing/events/stream`) is available for
  operators; relay itself polls the cached tier because gateways must survive
  disconnects.

## `relay.yaml.example` note

Billing is intentionally env-only so a typo can never silently disable safety
options (the config loader rejects unknown YAML fields). The example file
carries the block below as comments:

```yaml
# Billing realtime (env, not YAML):
#   BILLING_URL=http://billing:8080
#   BILLING_API_KEY=...
#   BILLING_ORG_ID=<org-uuid>
```
