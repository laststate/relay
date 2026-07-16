# Compatibility matrix

Aligned with **LEP protocol v1.0** (device path = Latch).

## Protocol

| Component | Version | Where |
|-----------|---------|--------|
| LEP | v1.0 | `internal/lep` |
| LEP CRC | CRC-32/IEEE | poly `0x04C11DB7` |
| Flags | bit3 TRUNCATED, bit4 COMPRESSED | `lep.go` |
| LEP crypto | v1.0 device path | `lep-crypto.md`, XChaCha+HKDF+HMAC |
| LSAK ACK | v1 | `internal/latchstream` |
| Latch stream | v1 | [latch-integration.md](latch-integration.md) |
| COBS | — | `internal/framing` |
| Architecture codes | v1.0 Latch table | `architecture-codes.md` |
| TLV registry | v1.0 core 1–15 | `lep-tlv-registry.md` |
| Binary batch | v1 | `binary-batch.md` |
| Attachments | v1 | `attachments.md` |
| Bundle | v1 + optional Ed25519 | `bundle-format.md` |

## Sources

| Type | Status |
|------|--------|
| serial | ready |
| tcp / tls | ready |
| udp | ready |
| http / tls | ready |
| directory | ready |
| mqtt | ready |
| adapter (subprocess) | ready |
| native CAN / BLE / LoRa | not yet (adapter) |

## Analysis

| Feature | Status |
|---------|--------|
| Cortex-M / Latch multi-arch CPU TLV | ready |
| RISC-V / Xtensa / Linux codes | aligned v1.0 |
| DWARF symbolicate | ready |
| Full CFI / EHABI unwind | not yet |

## Product v1.0.0 still needs

- Latch + Trace end-to-end CI on real MCU  
- Hardware-in-the-loop matrix  
- External security review  
- Power-loss soak on production filesystems  
