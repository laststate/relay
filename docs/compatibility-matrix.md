# Compatibility matrix

What this repo implements today, and what still depends on a frozen shared
protocol or real hardware CI.

## Protocol

| Component | Version | Where |
|-----------|---------|--------|
| LEP | v1 | `internal/lep`, golden vector in tests |
| LEP CRC | CRC-32/IEEE | poly `0x04C11DB7` |
| LSAK ACK | v1 | `internal/latchstream` |
| Latch stream | v1 | [latch-integration.md](latch-integration.md) |
| COBS | — | `internal/framing` |
| LEP crypto | draft | [lep-crypto.md](../spec/lep-crypto.md) |
| Binary batch | draft | [binary-batch.md](../spec/binary-batch.md) |
| Attachments | draft | [attachments.md](../spec/attachments.md) |
| Architecture codes | draft | [architecture-codes.md](../spec/architecture-codes.md) |
| TLV registry | draft | [lep-tlv-registry.md](../spec/lep-tlv-registry.md) |
| Bundle | v1 + optional Ed25519 | [bundle-format.md](../spec/bundle-format.md) |

Draft specs are good enough for Relay ↔ Trace experiments. They will track the
upstream protocol repo when that freezes.

## Sources

| Type | Status |
|------|--------|
| serial | ready |
| tcp / tls | ready |
| udp | ready |
| http / tls | ready |
| directory | ready |
| mqtt | ready (QoS 0–2, TLS) |
| adapter (subprocess) | ready |

## Analysis

| Feature | Status |
|---------|--------|
| Cortex-M CFSR/HFSR | ready |
| RISC-V mcause/mepc | basic |
| ARM-A / Xtensa / AVR | short layouts |
| FreeRTOS / Zephyr task TLVs | basic |
| DWARF symbolicate | ready |
| Build-id auto-match | ready |
| External symbolizer | ready (sandboxed) |
| Full CFI / EHABI unwind | not yet |

## Before calling it 1.0

- Latch + Trace end-to-end CI and at least one supported MCU
- Hardware-in-the-loop matrix
- External security review
- Protocol freeze that supersedes the draft specs
- Power-loss soak on production filesystems
