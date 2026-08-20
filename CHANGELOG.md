# Changelog

All notable changes to the LastState Relay gateway.

## [0.4.0] — 2026-08-15

### Added
- **Binary batch delivery** — zstd-compressed JSON/binary batches to Trace
- **LEP crypto wire layout** — draft spec for envelope encryption
- **Attachment chunk TLVs** — large memory dump support
- **Build/project/release identity TLVs** — enhanced device identity
- **Signed `.lsbundle`** — export/import with signature verification
- **Windows service** — native Windows service support
- **Homebrew formula** — `brew install laststate/relay/laststate-relay`
- **Grafana dashboard** — relay metrics dashboard template
- **Relay capabilities API** — `GET /v1/relay/capabilities`
- **Batch ingest API** — `POST /v1/events:batch`

### Changed
- CLI: added `bundle`, `doctor`, `config` subcommands
- Delivery: priority routing with per-destination batching

## [0.3.0] — 2026-08-14

### Added
- Serial, TCP/TLS, UDP, HTTP/TLS, directory, MQTT sources
- Latch stream and COBS framing with resync
- Mirror / priority / route / local-only delivery modes
- Admin vs ingest API split with bearer auth
- ELF catalog with build-id match and DWARF symbolication
- Multi-architecture basics (Cortex-M, RISC-V)
- Backup/restore
- Docker, systemd, deb/rpm templates

## [0.2.0] — 2026-08-10

### Added
- Durable spool (content-addressed objects + SQLite WAL)
- Startup reconcile and stale delivery-lease recovery
- LEP v1 validation and encoding
- Basic HTTP and serial sources
- Admin API (status, events, destinations)

## [0.1.0] — 2026-07-29

### Added
- Initial project setup
- LEP v1 codec implementation
- Basic spool storage
