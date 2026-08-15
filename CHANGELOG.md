# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Observability improvements and dependency updates
- Enhanced worker tests with LEP frame utilities and retry logic
- Hardened security with OpenTelemetry instrumentation
- Vendored protocol golden vectors for CI

## [0.3.0] - 2025-07-29

- Durable spool with content-addressed objects and SQLite WAL
- Startup reconcile and stale delivery-lease recovery
- Sources: serial, TCP/TLS, HTTP/TLS, UDP, directory, MQTT, subprocess adapter
- Latch stream and COBS framing with resync
- Delivery: mirror / priority / route / local-only, batch (JSON + binary), zstd, retries, Retry-After, circuit breaker
- Admin vs ingest API split, bearer auth, health, readiness, metrics
- ELF catalog, build-id match, DWARF symbolication, multi-arch basics
- LEP encode + HMAC / AEAD crypto draft, key IDs, replay window
- Signed `.lsbundle` export/import
- CLI/TUI, Docker, systemd, Windows service scripts, launchd, Homebrew, deb/rpm templates, udev, Grafana dashboard, backup/restore
