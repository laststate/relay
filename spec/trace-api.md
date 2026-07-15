# Trace ingestion contract used by Relay

## Capabilities

`GET /v1/relay/capabilities`

A `404` or `405` means legacy single-event ingestion. A successful response can advertise API version, LEP versions, event-size limits, batch support, compression, and artifact support.

## Single event

`POST /v1/ingest`

Headers:

```text
Content-Type: application/octet-stream
Idempotency-Key: evt_<stable-id>
X-Last-State-Event-ID: evt_<stable-id>
Authorization: Bearer <token>   # when configured
```

`2xx` and `409` are idempotent success. `408`, `425`, `429`, and `5xx` are retryable. `401`, `403`, `413`, and `422` require operator or payload action.


## Batch ingestion

`POST /v1/events:batch` accepts JSON matching `internal/traceapi.BatchRequest`.
Binary event payloads are base64-encoded by standard JSON encoding. The response
contains independent `accepted`, `duplicates`, and `rejected` arrays. A rejected
item includes `retryable`, allowing Relay to retry only temporary failures.

Servers advertise batch support and limits through `GET /v1/relay/capabilities`.
Relay falls back to `POST /v1/ingest` when the endpoint is absent or disabled.
